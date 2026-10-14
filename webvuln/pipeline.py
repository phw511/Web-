"""四段闭环编排：检测 → 决策 → 授权 → 攻击 → 复核（状态机见计划书 5.3）。

- 低危函数：Agent 自动放行执行（证据链记录 system(auto) 审批）；
- 中高危函数：产出审批单，人工在界面批准后由 execute_approved 续跑；
- 每步证据留痕：scan_start / decision / approval / attack_* / state_change / sign。
"""
from __future__ import annotations

import json

from webvuln.contracts.agent import DecisionAgent
from webvuln.contracts.attack import AttackRegistry
from webvuln.contracts.authz import AuthorizationError, Authorizer
from webvuln.contracts.evidence import EvidenceStore
from webvuln.db.database import Database
from webvuln.detector.engine import DetectorEngine
from webvuln.attacker.executor import AttackExecutor
from webvuln.models.schemas import (
    AttackDecision, CandidateState, Conclusion, EvidenceLevel, FindingCandidate,
    HttpSpec, RiskLevel, TargetRegistration, now_iso, uid,
)


class Pipeline:
    def __init__(
        self, db: Database, authorizer: Authorizer, engine: DetectorEngine,
        agent: DecisionAgent, executor: AttackExecutor, evidence: EvidenceStore,
        registry: AttackRegistry,
    ):
        self.db = db
        self.authorizer = authorizer
        self.engine = engine
        self.agent = agent
        self.executor = executor
        self.evidence = evidence
        self.registry = registry

    # ---- 扫描主流程 ----
    def run_scan(self, target_id: str, username: str) -> dict:
        target = self.authorizer.get_target(target_id)
        if target is None or target.status.value != "approved":
            raise AuthorizationError("目标不存在或未获批")
        scan_id = uid("scan")
        self.db.execute(
            "INSERT INTO scans(id,target_id,status,started_by,started_at)"
            " VALUES(?,?,?,?,?)",
            (scan_id, target_id, "running", username, now_iso()),
        )
        self.evidence.append(scan_id, "scan_start", {
            "target_id": target_id, "url": target.url, "by": username,
        })
        candidates = self.engine.run(target, scan_id)
        executed, pending = 0, 0
        for cand in candidates:
            self._save_candidate(cand)
            decision = self.agent.decide(cand, self.registry)
            self._save_decision(decision)
            self.evidence.append(scan_id, "decision", decision.model_dump())
            meta = self.registry.get(decision.function_name).meta
            if meta.risk_level == RiskLevel.LOW:
                self.evidence.append(scan_id, "approval", {
                    "decision_id": decision.id, "action": "approve",
                    "actor": "system(auto)",
                    "reason": "低危函数按可逆性分级自动放行（计划书 4.1）",
                })
                self._execute_and_conclude(scan_id, target, cand, decision)
                executed += 1
            else:
                self.evidence.append(scan_id, "pending_approval", {
                    "decision_id": decision.id,
                    "risk_level": meta.risk_level.value,
                })
                pending += 1
        self.db.execute(
            "UPDATE scans SET status=?, finished_at=? WHERE id=?",
            ("finished", now_iso(), scan_id),
        )
        return {"scan_id": scan_id, "candidates": len(candidates),
                "auto_executed": executed, "pending_approval": pending}

    # ---- 人工审批后续跑（中高危） ----
    def execute_approved(self, actor: str, decision_id: str, action: str,
                         reason: str) -> Conclusion:
        decision = self._get_decision(decision_id)
        cand = self._candidate_row(decision["candidate_id"])
        scan = self.db.one("SELECT * FROM scans WHERE id=?", (cand["scan_id"],))
        target = self.authorizer.get_target(scan["target_id"])
        approval = self.authorizer.record_attack_approval(actor, decision_id, action, reason)
        self.evidence.append(cand["scan_id"], "approval", approval.model_dump())
        if action == "reject":
            return self._conclude(cand, CandidateState.INCONCLUSIVE,
                                  EvidenceLevel.CLAIM,
                                  decided_by=f"human-reject:{actor}",
                                  note="人工否决攻击验证，结论如实标注证据不足")
        return self._execute_and_conclude(cand["scan_id"], target, cand,
                                          AttackDecision(**{
                                              k: decision[k] for k in
                                              ("id", "candidate_id", "function_name",
                                               "reason", "expected_result", "decision_source")
                                          }))

    # ---- 签署 ----
    def sign_conclusion(self, actor: str, conclusion_id: str, note: str) -> None:
        row = self.db.one("SELECT * FROM conclusions WHERE id=?", (conclusion_id,))
        if row is None:
            raise ValueError("结论不存在")
        if row["state"] not in (CandidateState.CONFIRMED.value, CandidateState.REJECTED.value):
            raise AuthorizationError("仅 CONFIRMED/REJECTED 结论可签署（INCONCLUSIVE 不签署，计划书 5.3）")
        self.db.execute(
            "UPDATE conclusions SET signed_by=?, signed_at=?, signature_note=? WHERE id=?",
            (actor, now_iso(), note, conclusion_id),
        )
        self.evidence.append(row["scan_id"] if "scan_id" in row else self._scan_of(row["candidate_id"]),
                             "sign", {
                                 "conclusion_id": conclusion_id, "signer": actor,
                                 "note": note,
                             })

    # ---- 证据回放（可复现口径：证据快照重放一致，计划书 2.3） ----
    def replay(self, scan_id: str) -> dict:
        records = self.evidence.for_scan(scan_id)
        return {
            "scan_id": scan_id,
            "verified": self.evidence.verify_scan(scan_id),
            "record_count": len(records),
            "timeline": [
                {"kind": r.kind, "id": r.id, "hash": r.hash,
                 "created_at": r.created_at} for r in records
            ],
        }

    # ---- 内部 ----
    def _scan_of(self, candidate_id: str) -> str:
        return self.db.one("SELECT scan_id FROM candidates WHERE id=?",
                           (candidate_id,))["scan_id"]

    def _get_decision(self, decision_id: str) -> dict:
        row = self.db.one("SELECT * FROM decisions WHERE id=?", (decision_id,))
        if row is None:
            raise ValueError(f"决策不存在: {decision_id}")
        if self.db.one("SELECT 1 FROM attack_runs WHERE decision_id=?", (decision_id,)):
            raise AuthorizationError("该决策已执行，不可重复审批执行")
        return row

    def _candidate_row(self, candidate_id: str) -> dict:
        return self.db.one("SELECT * FROM candidates WHERE id=?", (candidate_id,))

    def _save_candidate(self, cand: FindingCandidate) -> None:
        self.db.execute(
            "INSERT INTO candidates(id,scan_id,target_id,vuln_type,endpoint,parameter,"
            "claim,detector,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (cand.id, cand.scan_id, cand.target_id, cand.vuln_type.value,
             cand.endpoint, cand.parameter, cand.claim, cand.detector, cand.created_at),
        )

    def _save_decision(self, dec: AttackDecision) -> None:
        meta = self.registry.get(dec.function_name).meta
        self.db.execute(
            "INSERT INTO decisions(id,candidate_id,function_name,reason,expected_result,"
            "decision_source,risk_level,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (dec.id, dec.candidate_id, dec.function_name, dec.reason,
             dec.expected_result, dec.decision_source, meta.risk_level.value, now_iso()),
        )

    def _execute_and_conclude(self, scan_id: str, target: TargetRegistration,
                              cand: FindingCandidate,
                              decision: AttackDecision) -> Conclusion:
        base = HttpSpec(url=target.url, params=dict(target.base_params))
        result = self.executor.execute(decision, cand, base, scan_id)
        self.db.execute(
            "INSERT INTO attack_runs(id,decision_id,matched,result_json,executed_at)"
            " VALUES(?,?,?,?,?)",
            (uid("run"), decision.id, int(result.matched),
             json.dumps(result.model_dump(), ensure_ascii=False), result.executed_at),
        )
        state = (CandidateState.CONFIRMED if result.matched
                 else CandidateState.REJECTED)
        level = (EvidenceLevel.REPRODUCED if result.matched
                 else EvidenceLevel.OBSERVED)
        return self._conclude(cand, state, level,
                              decided_by="agent:" + decision.decision_source)

    def _conclude(self, cand_row_or_obj, state: CandidateState,
                  level: EvidenceLevel, decided_by: str,
                  note: str = "") -> Conclusion:
        candidate_id = (cand_row_or_obj.id if isinstance(cand_row_or_obj, FindingCandidate)
                        else cand_row_or_obj["id"])
        scan_id = (cand_row_or_obj.scan_id if isinstance(cand_row_or_obj, FindingCandidate)
                   else cand_row_or_obj["scan_id"])
        existing = self.db.one("SELECT id FROM conclusions WHERE candidate_id=?",
                               (candidate_id,))
        if existing:
            raise AuthorizationError("该候选已有结论")
        con = Conclusion(
            id=uid("con"), candidate_id=candidate_id, state=state,
            evidence_level=level, decided_by=decided_by, signature_note=note,
            created_at=now_iso(),
        )
        self.db.execute(
            "INSERT INTO conclusions(id,candidate_id,state,evidence_level,decided_by,"
            "signature_note,created_at) VALUES(?,?,?,?,?,?,?)",
            (con.id, con.candidate_id, con.state.value, con.evidence_level.value,
             con.decided_by, note, con.created_at),
        )
        self.evidence.append(scan_id, "state_change", {
            "candidate_id": candidate_id, "state": state.value,
            "evidence_level": level.value, "decided_by": decided_by,
        })
        return con
