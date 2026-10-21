"""xss_reflected_probe：反射型 XSS 验证型攻击函数（低危，Agent 可自动放行）。

验证逻辑：对候选参数注入非执行型金丝雀（不含事件处理器/脚本），
金丝雀字符串原样（尖括号未转义）出现在响应体即判定命中。
全程只读 GET、不加载任何外部脚本，副作用可控、可机器断言。
"""
from __future__ import annotations

from webvuln.contracts.attack import AttackFunction, register_attack
from webvuln.models.schemas import (
    AttackFunctionMeta, AttackResult, FindingCandidate, HttpSpec, RiskLevel,
    VulnType, now_iso,
)

REFLECT_PROBE = "wvxss7k<svg>"


@register_attack
class XSSReflectedProbe(AttackFunction):
    meta = AttackFunctionMeta(
        name="xss_reflected_probe",
        vuln_type=VulnType.XSS,
        risk_level=RiskLevel.LOW,
        reversible=True,
        side_effects="仅 1 次只读 GET 请求，无脚本加载、无写操作",
        expected_signal="金丝雀字符串（含未转义尖括号 <svg>）原样出现在响应体中",
    )

    def execute(self, gateway, candidate: FindingCandidate, base: HttpSpec,
                decision_id: str) -> AttackResult:
        spec = base.model_copy(update={
            "params": {**base.params,
                       candidate.parameter: base.params.get(candidate.parameter, "") + REFLECT_PROBE}
        })
        resp = gateway.send(spec)
        idx = resp.body.find(REFLECT_PROBE)
        matched = idx >= 0
        if matched:
            excerpt = resp.body[max(0, idx - 40): idx + len(REFLECT_PROBE) + 40]
        else:
            excerpt = resp.body[:400]
        return AttackResult(
            decision_id=decision_id,
            request=spec,
            response_status=resp.status_code,
            response_excerpt=excerpt[:400],
            matched=matched,
            executed_at=now_iso(),
        )
