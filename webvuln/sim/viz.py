"""结果可视化与导出（离线、自包含、无外部依赖）。

- 可视化：生成单文件 HTML（内联 SVG 图表：按漏洞类型分布条形图 + 结论状态
  环形图 + 整齐明细表），不引用 CDN/JS，离线即可打开；
- 文本导出：同一份数据同时产出 Markdown 与纯文本（.txt / .md）。
指标口径沿用报告层：TP=CONFIRMED、FP=REJECTED、INCONCLUSIVE 单列。
"""
from __future__ import annotations

import html

NL = chr(10)

# 统一配色（结论状态）
STATE_COLORS = {
    "CONFIRMED": "#16a34a",
    "REJECTED": "#dc2626",
    "INCONCLUSIVE": "#d97706",
    "PENDING": "#64748b",
}
TYPE_COLORS = {
    "sqli": "#6366f1",
    "xss": "#0ea5e9",
    "lfi": "#f59e0b",
    "idor": "#ec4899",
    "config": "#10b981",
}


# ---------- SVG 图表（纯 Python 内联，无 JS/CDN） ----------

def _bar_svg(data: dict, width: int = 520, height: int = 220) -> str:
    """按漏洞类型计数的横向条形图。data: {type_label: count}"""
    items = sorted(data.items(), key=lambda kv: kv[1], reverse=True)
    if not items:
        return "<p>（无数据）</p>"
    pad_l, pad_r, top, bottom = 70, 20, 30, 30
    plot_h = height - top - bottom
    row_h = plot_h / max(len(items), 1)
    maxv = max(v for _, v in items) or 1
    w = width - pad_l - pad_r
    parts = [
        f'<svg width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg" '
        'font-family="Segoe UI, Microsoft YaHei, sans-serif" font-size="12">',
        f'<text x="{pad_l//2}" y="18" text-anchor="middle" font-size="13" '
        'font-weight="bold">按漏洞类型分布</text>',
    ]
    for i, (label, v) in enumerate(items):
        y = top + i * row_h + (row_h - 14) / 2
        bar_w = max(2, w * v / maxv)
        color = TYPE_COLORS.get(label, "#64748b")
        parts.append(f'<text x="{pad_l-8}" y="{y+10}" text-anchor="end">{html.escape(str(label))}</text>')
        parts.append(
            f'<rect x="{pad_l}" y="{y}" width="{bar_w:.1f}" height="14" '
            f'fill="{color}" rx="2"/>'
        )
        parts.append(
            f'<text x="{pad_l+bar_w+6}" y="{y+11}">{v}</text>'
        )
    parts.append("</svg>")
    return NL.join(parts)


def _donut_svg(data: dict, width: int = 240, height: int = 240) -> str:
    """结论状态环形图（donut）。data: {state_label: count}"""
    items = [(k, v) for k, v in data.items() if v > 0]
    total = sum(v for _, v in items)
    if total <= 0:
        return "<p>（无数据）</p>"
    cx, cy, r = 100, 100, 70
    inner_r = 46
    parts = [
        f'<svg width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg" '
        'font-family="Segoe UI, Microsoft YaHei, sans-serif" font-size="11">',
    ]
    # 从顶部顺时针画扇区
    angle = -90.0
    for label, v in items:
        color = STATE_COLORS.get(label, "#64748b")
        sweep = 360.0 * v / total
        # 扇区外弧
        a0, a1 = angle, angle + sweep
        x0, y0 = cx + r * _cos(a0), cy + r * _sin(a0)
        x1, y1 = cx + r * _cos(a1), cy + r * _sin(a1)
        # 内弧（反向）
        ix0, iy0 = cx + inner_r * _cos(a1), cy + inner_r * _sin(a1)
        ix1, iy1 = cx + inner_r * _cos(a0), cy + inner_r * _sin(a0)
        large = 1 if sweep > 180 else 0
        parts.append(
            f'<path d="M{x0:.1f},{y0:.1f} A{r},{r} 0 {large} 1 {x1:.1f},{y1:.1f} '
            f'L{ix0:.1f},{iy0:.1f} A{inner_r},{inner_r} 0 {large} 0 {ix1:.1f},{iy1:.1f} Z" '
            f'fill="{color}"/>'
        )
        angle = a1
    # 中心合计
    parts.append(
        f'<text x="{cx}" y="{cy-2}" text-anchor="middle" font-size="20" '
        'font-weight="bold">{total}</text>'
    )
    parts.append(
        f'<text x="{cx}" y="{cy+14}" text-anchor="middle" fill="#64748b">结论</text>'
    )
    parts.append("</svg>")
    # 图例
    legend = "<ul style='list-style:none;padding:0;font-size:12px'>"
    for label, v in items:
        color = STATE_COLORS.get(label, "#64748b")
        legend += (
            f"<li style='display:flex;align-items:center;gap:6px;margin:2px 0'>"
            f"<span style='width:10px;height:10px;background:{color};display:inline-block;"
            f"border-radius:2px'></span>{label}: {v}</li>"
        )
    legend += "</ul>"
    return f"<div style='display:flex;align-items:center;gap:16px'>{NL.join(parts)}{legend}</div>"


def _cos(d: float) -> float:
    import math
    return math.cos(math.radians(d))


def _sin(d: float) -> float:
    import math
    return math.sin(math.radians(d))


# ---------- 组装 ----------

def render_html(data: dict) -> str:
    """由 summary(data) 生成整齐的单文件可视化 HTML。"""
    m = data["metrics"]
    scan = data["scan"]
    target = data["target"]
    by_type: dict[str, int] = {}
    by_state: dict[str, int] = {}
    for r in data["findings"]:
        by_type[r["vuln_type"]] = by_type.get(r["vuln_type"], 0) + 1
        state = r["state"] or "PENDING"
        by_state[state] = by_state.get(state, 0) + 1

    rows = []
    for r in data["findings"]:
        state = r["state"] or "PENDING"
        color = STATE_COLORS.get(state, "#64748b")
        rows.append(
            "<tr>"
            f"<td>{html.escape(r['id'])}</td>"
            f"<td>{html.escape(r['vuln_type'])}</td>"
            f"<td>{html.escape(r['parameter'])}</td>"
            f"<td>{html.escape(r['detector'])}</td>"
            f"<td><span style='color:{color};font-weight:600'>{state}</span></td>"
            f"<td>{html.escape(r['evidence_level'] or '-')}</td>"
            f"<td>{html.escape(r['signed_by'] or '-')}</td>"
            "</tr>"
        )
    rows_html = NL.join(rows) if rows else (
        "<tr><td colspan='7' style='color:#94a3b8'>（本次扫描未产生候选）</td></tr>"
    )

    metric_cards = ""
    for label, val, color in (
        ("TP（确认）", m["TP"], "#16a34a"),
        ("FP（误报）", m["FP"], "#dc2626"),
        ("INCONCLUSIVE", m["INCONCLUSIVE"], "#d97706"),
        ("PENDING", m["PENDING"], "#64748b"),
    ):
        metric_cards += (
            f"<div style='flex:1;min-width:120px;background:#f8fafc;border:1px solid #e2e8f0;"
            f"border-radius:8px;padding:12px 16px;text-align:center'>"
            f"<div style='font-size:26px;font-weight:700;color:{color}'>{val}</div>"
            f"<div style='font-size:12px;color:#64748b'>{label}</div></div>"
        )

    turl = html.escape(target["url"]) if target else "?"
    return f"""<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>模拟扫描可视化报告 · {html.escape(scan['id'])}</title>
<style>
  body {{ font-family: "Segoe UI", "Microsoft YaHei", sans-serif; margin: 0;
         background: #f1f5f9; color: #0f172a; }}
  .wrap {{ max-width: 920px; margin: 0 auto; padding: 24px 20px 48px; }}
  .card {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 12px;
           padding: 20px 24px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(15,23,42,.06); }}
  h1 {{ font-size: 20px; margin: 0 0 4px; }}
  h2 {{ font-size: 15px; margin: 0 0 12px; color: #334155;
        border-left: 4px solid #6366f1; padding-left: 8px; }}
  .meta {{ color: #64748b; font-size: 13px; margin-bottom: 8px; }}
  .metrics {{ display: flex; gap: 12px; flex-wrap: wrap; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 13px; }}
  th, td {{ border-bottom: 1px solid #e2e8f0; padding: 8px 10px; text-align: left; }}
  th {{ background: #f8fafc; color: #475569; font-weight: 600; }}
  tr:hover td {{ background: #f8fafc; }}
  .footer {{ color: #94a3b8; font-size: 12px; text-align: center; margin-top: 8px; }}
  svg {{ max-width: 100%; }}
</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <h1>模拟扫描可视化报告</h1>
    <div class="meta">
      扫描ID {html.escape(scan['id'])} · 目标 {turl} · 状态 {html.escape(scan['status'])}<br>
      开始 {html.escape(scan['started_at'])} · 说明：离线模拟（非真实接入）
    </div>
  </div>

  <div class="card">
    <h2>指标总览</h2>
    <div class="metrics">{metric_cards}</div>
    <div class="meta" style="margin-top:8px">FN 需靶场真值集后统计（本版如实标注）</div>
  </div>

  <div class="card">
    <h2>漏洞类型分布</h2>
    {_bar_svg(by_type)}
  </div>

  <div class="card">
    <h2>结论状态分布</h2>
    {_donut_svg(by_state)}
  </div>

  <div class="card">
    <h2>明细</h2>
    <table>
      <tr><th>候选</th><th>类型</th><th>参数</th><th>检测器</th>
          <th>结论</th><th>证据等级</th><th>签署</th></tr>
      {rows_html}
    </table>
  </div>

  <div class="footer">由 Web漏洞检测工具 · 模拟模式生成 · 可导出为 .txt / .md</div>
</div>
</body>
</html>
"""


def render_text(data: dict) -> str:
    """整齐的纯文本导出。"""
    scan = data["scan"]
    target = data["target"]
    m = data["metrics"]
    turl = target["url"] if target else "?"
    lines = [
        "=" * 60,
        "模拟扫描结果（纯文本导出）",
        "=" * 60,
        f"扫描ID   : {scan['id']}",
        f"目标     : {turl}",
        f"状态     : {scan['status']}",
        f"开始时间 : {scan['started_at']}",
        f"TP(确认) : {m['TP']}",
        f"FP(误报) : {m['FP']}",
        f"INCONCLUSIVE: {m['INCONCLUSIVE']}",
        f"PENDING  : {m['PENDING']}",
        f"说明     : 离线模拟（非真实接入）；FN 需靶场真值集后统计",
        "-" * 60,
        "明细",
        "-" * 60,
    ]
    for r in data["findings"]:
        lines.append(
            f"  [{r['vuln_type']}] 参数={r['parameter']} 结论={r['state'] or 'PENDING'} "
            f"证据={r['evidence_level'] or '-'} 检测器={r['detector']}"
        )
        lines.append(f"      claim: {r['claim']}")
    if not data["findings"]:
        lines.append("  （本次扫描未产生候选）")
    lines.append("=" * 60)
    return NL.join(lines)


def render_md(data: dict) -> str:
    """Markdown 导出。"""
    scan = data["scan"]
    target = data["target"]
    m = data["metrics"]
    turl = target["url"] if target else "?"
    lines = [
        f"# 模拟扫描报告 {scan['id']}",
        "",
        f"- 目标: {turl}",
        f"- 状态: {scan['status']} 开始: {scan['started_at']}",
        f"- 指标: TP={m['TP']} FP={m['FP']} INCONCLUSIVE={m['INCONCLUSIVE']} "
        "(FN 需靶场真值集后统计)",
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
