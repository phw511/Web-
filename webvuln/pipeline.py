"""四段闭环编排：检测 → 决策 → 授权 → 攻击 → 复核（状态机见计划书 5.3）。

- 低危函数：Agent 自动放行执行（证据链记录 system(auto) 审批）；
- 中高危函数：产出审批单，人工在界面批准后由 execute_approved 续跑；
- 每步证据留痕：scan_start / decision / approval / attack_* / state_change / sign。

v0.2.0（计划书 2.3 预算约束 + 9 章四项上限）：
- 时长与决策轮次在本层强制：超限即停，扫描状态 `stopped_budget` 并写
  `budget_exceeded` 证据；攻击请求数与并发由出口/执行器各自强制（见 egress、executor），
  本层只负责把"攻击请求超限"这类异常如实上抛给调用方（不能吞，否则"超限即停"变静默）；
- Agent 找不到匹配白名单函数（AgentDecisionError）时，候选挂起并留痕，
  不再让整次扫描崩掉——这正是"新增检测器但尚未新增攻击函数"的正常过渡态；
- 任何未预期异常都把扫描标记 `failed` 并留痕，避免"永远 running"的僵尸扫描；
- 人工审批的角色判定下沉到授权层（authorizer.assert_approval_allowed），本层只透传角色。
"""
from __future__ import annotations

import json
from typing import Optional

from webvuln.contracts.agent import AgentDecisionError, DecisionAgent
from webvuln.contracts.attack import AttackRegistry
from webvuln.contracts.authz import AuthorizationError, Authorizer
from webvuln.contracts.budget import (
    KIND_ROUNDS, KIND_TIME, BudgetExceeded, BudgetGuardContract,
)
from webvuln.contracts.evidence import EvidenceStore
from webvuln.db.database import Database
from webvuln.detector.engine import DetectorEngine
from webvuln.attacker.executor import AttackExecutor
from webvuln.models.schemas import (
    AttackDecision, CandidateState, Conclusion, EvidenceLevel, FindingCandidate,
    HttpSpec, RiskLevel, TargetRegistration, now_iso, uid,
)

STATUS_RUNNING = "running"
STATUS_FINISHED = "finished"
STATUS_STOPPED_BUDGET = "stopped_budget"
STATUS_FAILED = "failed"


class Pipeline:
    def __init__(
        self, db: Database, authorizer: Authorizer, engine: DetectorEngine,
        agent: DecisionAgent, executor: AttackExecutor, evidence: EvidenceStore,
        registry: AttackRegistry, budget: Optional[BudgetGuardContract] = None,
    ):
        self.db = db
        self.authorizer = authorizer
        self.engine = engine
        self.agent = agent
        self.executor = executor
        self.evidence = evidence
        self.registry = registry
        self.budget = budget

    # ---- 扫描主流程 ----
    def run_scan(self, target_id: str, username: str) -> dict:
        target = self.authorizer.get_target(target_id)
        if target is None or target.status.value != "approved":
            raise AuthorizationError("目标不存在或未获批")

        scan_id = uid("scan")
        if self.budget is not None:
            self.budget.start_scan(scan_id, target.url)
        self.db.execute(
            "INSERT INTO scans(id,target_id,status,started_by,started_at)"
            " VALUES(?,?,?,?,?)",
            (scan_id, target_id, STATUS_RUNNING, username, now_iso()),
        )
        self.evidence.append(scan_id, "scan_start", {
            "target_id": target_id, "url": target.url, "by": username,
        })

        candidates_count = 0
        executed = pending = suspended = 0
        try:
            self._check_time("检测启动")
            candidates = self.engine.run(target, scan_id)
            candidates_count = len(candidates)

            for cand in candidates:
                self._check_time("逐个候选决策前")
                self._check_round()          # 轮次上限：超限即停，已处理部分保留
                self._save_candidate(cand)
                try:
                    decision = self.agent.decide(cand, self.registry)
                except AgentDecisionError as e:
                    suspended += 1
                    self.evidence.append(scan_id, "candidate_suspended", {
                        "candidate_id": cand.id, "vuln_type": cand.vuln_type.value,
                        "reason": str(e),
                    })
                    continue

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

        except BudgetExceeded as e:
            if e.kind in (KIND_TIME, KIND_ROUNDS):
                # 编排层可控的两项：停止扫描，如实留痕，不抛给调用方
                self._set_status(scan_id, STATUS_STOPPED_BUDGET)
                self.evidence.append(scan_id, "budget_exceeded", {
                    "kind": e.kind, "limit": e.limit, "reason": str(e),
                    "budget": self.budget.snapshot() if self.budget else {},
                })
                return self._result(scan_id, candidates_count, executed, pending,
                                    suspended, str(e), STATUS_STOPPED_BUDGET)
            # 请求数/并发：属于"某条攻击被出口/执行器拦下"，必须上抛，不能静默
            self._set_status(scan_id, STATUS_FAILED)
            self.evidence.append(scan_id, "budget_exceeded", {
                "kind": e.kind, "limit": e.limit, "reason": str(e),
                "budget": self.budget.snapshot() if self.budget else {},
            })
            raise
        except Exception as e:
            self._set_status(scan_id, STATUS_FAILED)
            self.evidence.append(scan_id, "scan_failed", {
                "error": f"{type(e).__name__}: {e}",
            })
            raise

        self._set_status(scan_id, STATUS_FINISHED)
        return self._result(scan_id, candidates_count, executed, pending,
                            suspended, "", STATUS_FINISHED)

    # ---- 人工审批后续跑（中高危） ----
    def execute_approved(self, actor: str, decision_id: str, action: str,
                         reason: str, actor_role: Optional[str] = None) -> Conclusion:
        decision = self._get_decision(decision_id)
        cand = self._candidate_row(decision["candidate_id"])
        scan = self.db.one("SELECT * FROM scans WHERE id=?", (cand["scan_id"],))
        target = self.authorizer.get_target(scan["target_id"])
        # 分级放行的判定只在授权层一份；此处只透传角色（不传则视为内部调用，不做角色约束）
        if actor_role is not None:
            self.authorizer.assert_approval_allowed(actor_role, decision["risk_level"])
        approval = self.authorizer.record_attack_approval(actor, decision_id, action, reason)
        self.evidence.append(cand["scan_id"], "approval", approval.model_dump())
        if action == "reject":
            return self._conclude(cand, CandidateState.INCONCLUSIVE,
                                  EvidenceLevel.OBSERVED,
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
        self.evidence.append(self._scan_of(row["candidate_id"]),
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
                 "created_at": r.created_at, "app_version": r.app_version}
                for r in records
            ],
        }

    # ---- 内部：预算与状态 ----
    def _check_time(self, phase: str) -> None:
        if self.budget is not None:
            self.budget.check_time(phase)

    def _check_round(self) -> None:
        if self.budget is not None:
            self.budget.check_round()

    def _set_status(self, scan_id: str, status: str) -> None:
        self.db.execute(
            "UPDATE scans SET status=?, finished_at=? WHERE id=?",
            (status, now_iso(), scan_id),
        )

    @staticmethod
    def _result(scan_id: str, candidates: int, executed: int, pending: int,
                suspended: int, stopped: str, status: str) -> dict:
        return {
            "scan_id": scan_id,
            "candidates": candidates,
            "auto_executed": executed,
            "pending_approval": pending,
            "suspended": suspended,
            "budget_stopped": stopped,      # 未触发时为空串，调用方无需做 key 判断
            "status": status,
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
