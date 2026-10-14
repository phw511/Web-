"""SQL 注入检测器（初版唯一检测器，F2 后续按同一契约扩展）。

信号口径（保守策略，控制 FP）：
- 错误型：响应体出现数据库错误关键字；
- 布尔型：恒真/恒假条件对的响应体长度差显著（>20%）。
满足其一即产出候选，claim 中记录原始证据摘录（ClaimOnly 级）。
"""
from __future__ import annotations

from webvuln.contracts.detector import BaseDetector
from webvuln.models.schemas import (
    FindingCandidate, HttpSpec, TargetRegistration, VulnType, now_iso, uid,
)

ERROR_KEYWORDS = (
    "sql syntax", "mysql", "sqlite", "postgresql", "ora-", "odbc",
    "syntax error", "unterminated", "quoted string not properly",
)

DIFF_THRESHOLD = 0.2


class SQLiDetector(BaseDetector):
    name = "sqli_error_boolean_v1"
    vuln_types = (VulnType.SQLI,)

    def _probe(self, gateway, base: HttpSpec, param: str, suffix: str) -> str:
        spec = base.model_copy(update={
            "params": {**base.params, param: base.params.get(param, "") + suffix}
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
            baseline = gateway.send(base).body
            try:
                error_body = self._probe(gateway, base, pname, "'")
                true_body = self._probe(gateway, base, pname, "' AND '1'='1")
                false_body = self._probe(gateway, base, pname, "' AND '1'='2")
            except Exception as e:  # 网络错误等：该参数跳过，不误报
                continue

            error_hit = any(k in error_body.lower() for k in ERROR_KEYWORDS)
            bigger = max(len(true_body), len(false_body), 1)
            bool_hit = abs(len(true_body) - len(false_body)) / bigger > DIFF_THRESHOLD

            if not (error_hit or bool_hit):
                continue

            signals = []
            if error_hit:
                excerpt = error_body[:200].replace("\n", " ")
                signals.append(f"错误型信号：响应包含数据库错误特征，摘录「{excerpt}」")
            if bool_hit:
                signals.append(
                    f"布尔型信号：恒真/恒假条件响应长度 {len(true_body)}/{len(false_body)} 字节，"
                    f"基线 {len(baseline)} 字节，差异率超阈值 {DIFF_THRESHOLD:.0%}"
                )
            claim = f"参数「{pname}」注入探测异常：" + "；".join(signals)
            candidates.append(FindingCandidate(
                id=uid("cand"), scan_id=scan_id, target_id=target.id,
                vuln_type=VulnType.SQLI, endpoint=base.url, parameter=pname,
                claim=claim, detector=self.name, created_at=now_iso(),
            ))
        return candidates
