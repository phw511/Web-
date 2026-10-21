"""离线模拟演示：注册模拟靶标 → 跑通真实"检测→决策→授权→攻击→结论→证据"
闭环 → 生成可视化 HTML + 文本导出。全程不触网（Transport 替换为 MockTransport）。

与真实扫描的唯一差异在底层 Transport：其余检测器、RuleAgent、Pipeline、
授权、证据、报告逻辑全部复用真实实现，保证"模拟结果口径 = 真实口径"。
"""
from __future__ import annotations

import os

from webvuln.agent.rule_agent import RuleAgent
from webvuln.attacker.attacks import *  # noqa: F401,F403  注册白名单攻击函数
from webvuln.attacker.executor import AttackExecutor
from webvuln.authz.egress import EgressGateway
from webvuln.authz.service import AuthorizerService
from webvuln.contracts.attack import default_registry
from webvuln.db.database import Database
from webvuln.detector.engine import DetectorEngine
from webvuln.detector.sqli import SQLiDetector
from webvuln.detector.xss import XSSDetector
from webvuln.evidence.store import FileEvidenceStore
from webvuln.pipeline import Pipeline
from webvuln.report.reporter import ReporterService
from webvuln.sim import viz
from webvuln.sim.mock_transport import MockTransport

# 模拟靶标（离线，不解析、不触网；EgressGateway 校验仍走 loopback + allow_private）
SIM_URL = "http://127.0.0.1:8080"
SIM_BASE_PARAMS = {"q": "hello"}
SIM_USER_SUBMIT = "sim-submitter"
SIM_USER_APPROVE = "sim-approver"   # 双人审批：提交人与审批人分离


def build_pipeline(db_path: str, evidence_dir: str) -> tuple[Pipeline, Database]:
    """以 MockTransport 组装一条与真实一致的流水线。"""
    db = Database(db_path)
    evidence = FileEvidenceStore(evidence_dir, db)
    transport = MockTransport()
    gateway = EgressGateway(db, transport)
    authorizer = AuthorizerService(db)
    registry = default_registry()
    engine = DetectorEngine(gateway, [SQLiDetector(), XSSDetector()])
    agent = RuleAgent()
    executor = AttackExecutor(registry, gateway, evidence)
    reporter = ReporterService(db)
    pipeline = Pipeline(db, authorizer, engine, agent, executor, evidence, registry)
    return pipeline, db


def run_simulation(out_dir: str, db_path: str | None = None) -> dict:
    """注册模拟靶标并跑完整闭环，输出 html/txt/md/json 到 out_dir。

    返回 {"scan_id", "target_id", "metrics", "outputs"}。
    """
    db_path = db_path or os.path.join(out_dir, "sim.db")
    evidence_dir = os.path.join(out_dir, "evidence")
    os.makedirs(out_dir, exist_ok=True)

    pipeline, db = build_pipeline(db_path, evidence_dir)
    authorizer = pipeline.authorizer

    # 双人审批注册目标（allow_private 放行 loopback，模拟靶场）
    reg = authorizer.submit_target(
        SIM_USER_SUBMIT, SIM_URL, ["/"], dict(SIM_BASE_PARAMS),
        "离线模拟靶标：演示 SQLi 与反射型 XSS", allow_private=True,
    )
    authorizer.approve_target(SIM_USER_APPROVE, reg.id, "模拟演示放行", allow_private=True)

    # 跑真实扫描闭环
    result = pipeline.run_scan(reg.id, SIM_USER_SUBMIT)
    scan_id = result["scan_id"]

    # 报告：可视化 + 文本导出（同一份 summary 数据）
    reporter = ReporterService(db)
    data = reporter.summary(scan_id)

    outputs = {}
    html_out = os.path.join(out_dir, "report.html")
    txt_out = os.path.join(out_dir, "report.txt")
    md_out = os.path.join(out_dir, "report.md")
    json_out = os.path.join(out_dir, "report.json")

    with open(html_out, "w", encoding="utf-8") as f:
        f.write(viz.render_html(data))
    with open(txt_out, "w", encoding="utf-8") as f:
        f.write(viz.render_text(data))
    with open(md_out, "w", encoding="utf-8") as f:
        f.write(viz.render_md(data))
    with open(json_out, "w", encoding="utf-8") as f:
        import json
        json.dump(data, f, ensure_ascii=False, indent=2)

    outputs = {"html": html_out, "txt": txt_out, "md": md_out, "json": json_out}
    return {
        "scan_id": scan_id, "target_id": reg.id,
        "metrics": result, "outputs": outputs,
    }
