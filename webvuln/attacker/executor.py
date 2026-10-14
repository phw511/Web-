"""攻击执行器：经授权层放行后调度白名单攻击函数，采集响应证据。

执行前后均向证据层留痕（decision → attack_request → attack_response），
构成"检测---决策---攻击"链路的完整证据。
"""
from __future__ import annotations

from webvuln.contracts.attack import AttackRegistry
from webvuln.contracts.evidence import EvidenceStore
from webvuln.authz.egress import EgressGateway
from webvuln.models.schemas import (
    AttackDecision, AttackResult, FindingCandidate, HttpSpec,
)


class AttackExecutor:
    def __init__(self, registry: AttackRegistry, gateway: EgressGateway,
                 evidence: EvidenceStore):
        self.registry = registry
        self.gateway = gateway
        self.evidence = evidence

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
        result = fn.execute(self.gateway, candidate, base, decision.id)
        self.evidence.append(scan_id, "attack_response", result.model_dump())
        return result
