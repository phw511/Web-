"""本地文件包含（LFI）检测器：路径穿越读取服务器文件系统。

信号口径（保守）：向参数注入 ../../etc/passwd 穿越载荷，响应体出现
类 Unix 口令文件特征行（root:x:0:0）即判定候选，claim 记录原始摘录。
主动读取服务器文件，影响面大于布尔/反射探测，归中危。
"""
from __future__ import annotations

from webvuln.contracts.detector import BaseDetector
from webvuln.models.schemas import (
    FindingCandidate, HttpSpec, TargetRegistration, VulnType, now_iso, uid,
)

TRAVERSAL_PAYLOAD = "../../../../etc/passwd"
OS_INDICATORS = ("root:x:0:0:", "[extensions]", "boot loader")


class LFIDetector(BaseDetector):
    name = "lfi_traversal_v1"
    vuln_types = (VulnType.LFI,)

    def detect(
        self,
        gateway,
        target: TargetRegistration,
        base: HttpSpec,
        scan_id: str,
    ) -> list[FindingCandidate]:
        candidates: list[FindingCandidate] = []
        params = list(base.params.keys()) or ["page"]
        for pname in params:
            spec = base.model_copy(update={
                "params": {**base.params, pname: TRAVERSAL_PAYLOAD}
            })
            try:
                body = gateway.send(spec).body
            except Exception:  # 网络错误等：该参数跳过，不误报
                continue
            hit = next((k for k in OS_INDICATORS if k in body), None)
            if not hit:
                continue
            excerpt = body[:200].replace("\n", " ")
            candidates.append(FindingCandidate(
                id=uid("cand"), scan_id=scan_id, target_id=target.id,
                vuln_type=VulnType.LFI, endpoint=base.url, parameter=pname,
                claim=f"参数「{pname}」路径穿越探测命中：注入「{TRAVERSAL_PAYLOAD}」后"
                      f"响应出现系统文件特征「{hit}」，摘录「{excerpt}」",
                detector=self.name, created_at=now_iso(),
            ))
        return candidates
