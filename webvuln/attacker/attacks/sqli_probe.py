"""sqli_boolean_probe：SQL 注入布尔验证型攻击函数（低危，Agent 可自动放行）。

验证逻辑：对候选参数分别附加恒真/恒假条件各发一次只读请求，
响应体长度差显著即判定命中（与检测器信号口径一致，可机器断言）。
"""
from __future__ import annotations

from webvuln.contracts.attack import AttackFunction, register_attack
from webvuln.models.schemas import (
    AttackFunctionMeta, AttackResult, FindingCandidate, HttpSpec, RiskLevel,
    VulnType, now_iso,
)

DIFF_THRESHOLD = 0.2


@register_attack
class SQLiBooleanProbe(AttackFunction):
    meta = AttackFunctionMeta(
        name="sqli_boolean_probe",
        vuln_type=VulnType.SQLI,
        risk_level=RiskLevel.LOW,
        reversible=True,
        side_effects="仅 2 次只读 GET 请求，无写操作",
        expected_signal="恒真/恒假条件响应体长度差 > 20%（可复现）",
    )

    TRUE_COND = "' AND '1'='1"
    FALSE_COND = "' AND '1'='2"

    def execute(self, gateway, candidate: FindingCandidate, base: HttpSpec,
                decision_id: str) -> AttackResult:
        spec_true = base.model_copy(update={
            "params": {**base.params, candidate.parameter: base.params.get(candidate.parameter, "") + self.TRUE_COND}
        })
        spec_false = base.model_copy(update={
            "params": {**base.params, candidate.parameter: base.params.get(candidate.parameter, "") + self.FALSE_COND}
        })
        resp_true = gateway.send(spec_true)
        resp_false = gateway.send(spec_false)
        bigger = max(len(resp_true.body), len(resp_false.body), 1)
        matched = abs(len(resp_true.body) - len(resp_false.body)) / bigger > DIFF_THRESHOLD
        return AttackResult(
            decision_id=decision_id,
            request=spec_false,
            response_status=resp_false.status_code,
            response_excerpt=resp_false.body[:400],
            matched=matched,
            executed_at=now_iso(),
        )
