"""报告层实现：仅读 DB 汇总数据，输出 JSON / Markdown / HTML。

指标口径：TP=CONFIRMED 数，FP=REJECTED 数，INCONCLUSIVE 单列，
FN 需靶场真值集（M2 部署 DVWA 后统计），本版在报告中如实标注口径。
"""
from __future__ import annotations

import html
import json

from webvuln.contracts.report import Reporter
from webvuln.db.database import Database

NL = chr(10)  # 避免转义歧义


class ReporterService(Reporter):
    def __init__(self, db: Database):
        self.db = db

    def summary(self, scan_id: str) -> dict:
        scan = self.db.one("SELECT * FROM scans WHERE id=?", (scan_id,))
        if scan is None:
            raise ValueError(f"扫描不存在: {scan_id}")
        target = self.db.one("SELECT * FROM targets WHERE id=?", (scan["target_id"],))
        rows = self.db.query(
            "SELECT c.*, d.function_name, d.decision_source, d.risk_level,"
            "       con.state, con.evidence_level, con.signed_by, con.signed_at"
            " FROM candidates c"
            " LEFT JOIN decisions d ON d.candidate_id=c.id"
            " LEFT JOIN conclusions con ON con.candidate_id=c.id"
            " WHERE c.scan_id=? ORDER BY c.created_at", (scan_id,),
        )
        state_counts: dict[str, int] = {}
        for r in rows:
            key = r["state"] or "PENDING"
            state_counts[key] = state_counts.get(key, 0) + 1
        return {
            "scan": scan,
            "target": {"id": target["id"], "url": target["url"]} if target else None,
            "findings": rows,
            "metrics": {
                "TP": state_counts.get("CONFIRMED", 0),
                "FP": state_counts.get("REJECTED", 0),
                "INCONCLUSIVE": state_counts.get("INCONCLUSIVE", 0),
                "PENDING": state_counts.get("PENDING", 0),
                "FN": None,  # 需靶场真值集，如实标注（计划书 5.1）
            },
        }

    def render(self, scan_id: str, fmt: str) -> str:
        data = self.summary(scan_id)
        if fmt == "json":
            return json.dumps(data, ensure_ascii=False, indent=2)
        if fmt == "md":
            return self._to_md(data)
        if fmt == "html":
            return self._to_html(data)
        raise ValueError(f"不支持格式: {fmt}")

    @staticmethod
    def _to_md(data: dict) -> str:
        m = data["metrics"]
        lines = [
            f"# 扫描报告 {data['scan']['id']}",
            f"- 目标: {data['target']['url'] if data['target'] else '?'}",
            f"- 开始: {data['scan']['started_at']} 状态: {data['scan']['status']}",
            f"- 指标: TP={m['TP']} FP={m['FP']} "
            f"INCONCLUSIVE={m['INCONCLUSIVE']}（FN 需靶场真值集后统计）",
            "",
            "| 候选 | 类型 | 参数 | 结论 | 证据等级 | 签署 |",
            "|---|---|---|---|---|---|",
        ]
        for r in data["findings"]:
            lines.append(
                f"| {r['id']} | {r['vuln_type']} | {r['parameter']} | "
                f"{r['state'] or 'PENDING'} | {r['evidence_level'] or '-'} | "
                f"{r['signed_by'] or '-'} |"
            )
        return NL.join(lines)

    @staticmethod
    def _to_html(data: dict) -> str:
        m = data["metrics"]
        rows = "".join(
            "<tr><td>{id}</td><td>{vt}</td><td>{p}</td><td>{s}</td><td>{e}</td><td>{sg}</td></tr>".format(
                id=html.escape(r["id"]), vt=r["vuln_type"],
                p=html.escape(r["parameter"]), s=r["state"] or "PENDING",
                e=r["evidence_level"] or "-",
                sg=html.escape(r["signed_by"] or "-"),
            )
            for r in data["findings"]
        )
        return (
            '<!doctype html><html lang="zh"><meta charset="utf-8">'
            f"<title>扫描报告 {data['scan']['id']}</title>"
            f"<body><h1>扫描报告 {data['scan']['id']}</h1>"
            f"<p>目标: {html.escape(data['target']['url'] if data['target'] else '?')}</p>"
            f"<p>指标: TP={m['TP']} FP={m['FP']} "
            f"INCONCLUSIVE={m['INCONCLUSIVE']}（FN 需靶场真值集后统计）</p>"
            '<table border="1" cellspacing="0" cellpadding="4">'
            "<tr><th>候选</th><th>类型</th><th>参数</th><th>结论</th>"
            "<th>证据等级</th><th>签署</th></tr>"
            f"{rows}</table></body></html>"
        )
