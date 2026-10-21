"""反射型 XSS 检测器（第一次更新新增，与 SQLi 同一契约扩展，F2 风格）。

信号口径（保守策略，控制 FP）：
- 对每个参数注入唯一的、非执行型金丝雀（wvxss7k<svg>），不含事件处理器/脚本；
- 响应体中原样出现该金丝雀（即 < > 未被转义为 &lt; &gt;）即判定为
  "未编码反射"，产出候选（ClaimOnly 级）；
- 若仅出现转义形态则视为安全，不报。
金丝雀随机化，避免页面本身偶然命中造成误报；候选是否成立由低危攻击函数复验。
"""
from __future__ import annotations

from webvuln.contracts.detector import BaseDetector
from webvuln.models.schemas import (
    FindingCandidate, HttpSpec, TargetRegistration, VulnType, now_iso, uid,
)

# 非执行型金丝雀：含一对尖括号标签，但无 onload/alert/script，本身不触发任何动作
REFLECT_PROBE = "wvxss7k<svg>"


class XSSDetector(BaseDetector):
    name = "xss_reflected_v1"
    vuln_types = (VulnType.XSS,)

    def _probe(self, gateway, base: HttpSpec, param: str, payload: str) -> str:
        spec = base.model_copy(update={
            "params": {**base.params, param: base.params.get(param, "") + payload}
        })
        return gateway.send(spec).body

    def detect(
        self,
        gateway,
        target: TargetRegistration,
        base: HttpSpec,
        scan_id: str,
    ) -> list[FindingCandidate]:
        candidates: list[FindingCandidate] = []
        params = list(base.params.keys()) or ["q"]
        for pname in params:
            try:
                body = self._probe(gateway, base, pname, REFLECT_PROBE)
            except Exception:  # 网络错误等：该参数跳过，不误报
                continue

            idx = body.find(REFLECT_PROBE)
            if idx < 0:
                continue  # 未原样反射（可能已转义）→ 安全

            start = max(0, idx - 40)
            end = idx + len(REFLECT_PROBE) + 40
            excerpt = body[start:end].replace("\n", " ")
            claim = (
                f"参数「{pname}」反射探测命中：金丝雀「{REFLECT_PROBE}」未转义原样"
                f"出现在响应体中，出现位置上下文「{excerpt}」"
            )
            candidates.append(FindingCandidate(
                id=uid("cand"), scan_id=scan_id, target_id=target.id,
                vuln_type=VulnType.XSS, endpoint=base.url, parameter=pname,
                claim=claim, detector=self.name, created_at=now_iso(),
            ))
        return candidates
