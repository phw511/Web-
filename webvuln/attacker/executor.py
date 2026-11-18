"""攻击执行器：经授权层放行后调度白名单攻击函数，采集响应证据。

执行前后均向证据层留痕（decision → attack_request → attack_response），
构成"检测---决策---攻击"链路的完整证据。

v0.2.0：并发上限（计划书第 9 章"全局攻击函数调用并发 ≤2"）在此强制。
放在执行器而不是出口，是因为"并发"约束的对象是攻击函数调用本身（含其内部
多次请求的整体），出口只认识单条请求，无法表达"一次调用"的边界。
"""
from __future__ import annotations

from webvuln.contracts.attack import AttackRegistry
from webvuln.contracts.budget import BudgetGuardContract
from webvuln.contracts.evidence import EvidenceStore
from webvuln.authz.egress import EgressGateway
from webvuln.models.schemas import (
    AttackDecision, AttackResult, FindingCandidate, HttpSpec,
)


class AttackExecutor:
    def __init__(self, registry: AttackRegistry, gateway: EgressGateway,
                 evidence: EvidenceStore, budget: BudgetGuardContract | None = None):
        self.registry = registry
        self.gateway = gateway
        self.evidence = evidence
        self.budget = budget

    def execute(
        self, decision: AttackDecision, candidate: FindingCandidate,
        base: HttpSpec, scan_id: str,
    ) -> AttackResult:
        fn = self.registry.get(decision.function_name)
        if fn is None:
            raise ValueError(f"未注册攻击函数: {decision.function_name}")
        self.evidence.append(scan_id, "attack_request", {
            "decision_id": decision.id, "function": decision.function_name,
            "risk_level": fn.meta.risk_level.value,
            "side_effects": fn.meta.side_effects,
        })
        if self.budget is not None:
            self.budget.acquire_slot()
        try:
            # 攻击函数内部统一走 gateway.send_attack()：打 context=attack 标记并在出口记账
            result = fn.execute(self.gateway, candidate, base, decision.id)
        finally:
            if self.budget is not None:
                self.budget.release_slot()
        self.evidence.append(scan_id, "attack_response", result.model_dump())
        return result
