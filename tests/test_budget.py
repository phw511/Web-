"""预算四项上限的强制执行测试（计划书第 9 章数值化口径）。

章节03口径：验收项必须有"执行与判定办法 + 真实结果"，只在 config
声明数值而不设强制点，属于"检查办法存在但从未执行 = 未运行"。
"""
import pytest

from webvuln.budget import BudgetExceeded
from webvuln.config import Settings
from webvuln.container import Container
from webvuln.models.schemas import ResponseSnapshot, Role


class ComboTransport:
    """同时带 SQLi 布尔差异与 XSS 未转义反射的构造靶场（教学用）。"""

    def __init__(self):
        self.requests = []

    def send(self, spec) -> ResponseSnapshot:
        self.requests.append(spec)
        q = spec.params.get("q", "")
        if "'1'='2" in q:
            return ResponseSnapshot(status_code=200, body="Empty.")
        if "wvxss7k<svg>" in q:
            return ResponseSnapshot(status_code=200, body=f"Echo: {q} rendered.")
        return ResponseSnapshot(status_code=200,
                                body="Welcome. Items: book, pen, cup, desk.")


def _make_container(tmp_path, **over):
    settings = Settings(db_path=str(tmp_path / "app.db"),
                        evidence_dir=str(tmp_path / "evidence"),
                        jwt_secret="t", **over)
    c = Container(settings)
    c.transport = ComboTransport()
    c.gateway.transport = c.transport
    for u, p, r in [("admin", "a1", Role.ADMIN), ("sub1", "s1", Role.SUBMITTER),
                    ("app1", "p1", Role.APPROVER), ("sig1", "g1", Role.SIGNER)]:
        c.users.create(u, p, r)
    reg = c.authorizer.submit_target(
        "sub1", "http://vuln.example.com", ["/"], {"q": "book"}, "构造靶场")
    c.authorizer.approve_target("app1", reg.id, "ok")
    return c, c.authorizer.get_target(reg.id)


def test_scan_time_budget_stops_scan(tmp_path):
    c, target = _make_container(tmp_path, scan_timeout_seconds=0)
    result = c.pipeline.run_scan(target.id, "sub1")
    assert "预算" in result["budget_stopped"] and "时长" in result["budget_stopped"]
    assert c.db.one("SELECT status FROM scans WHERE id=?", (result["scan_id"],))["status"]         == "stopped_budget"
    kinds = [r.kind for r in c.evidence.for_scan(result["scan_id"])]
    assert "budget_exceeded" in kinds          # 超限已写入证据层
    assert c.evidence.verify_scan(result["scan_id"]) is True


def test_decision_round_budget_stops_partial(tmp_path):
    # 2 个候选（SQLi+XSS），轮次上限 1：第一个放行，第二个触发超限即停
    c, target = _make_container(tmp_path, llm_rounds_per_target=1)
    result = c.pipeline.run_scan(target.id, "sub1")
    assert result["candidates"] == 2
    assert result["auto_executed"] == 1        # 已处理部分保留，如实标注
    assert "轮次" in result["budget_stopped"]
    assert c.db.one("SELECT status FROM scans WHERE id=?", (result["scan_id"],))["status"]         == "stopped_budget"


def test_attack_request_cap_blocks_at_gateway(tmp_path):
    # 攻击请求上限 1：SQLi 验证需 2 次只读请求，第 2 次在唯一出口被拦
    c, target = _make_container(tmp_path, max_attack_requests_per_target=1)
    with pytest.raises(BudgetExceeded):
        c.pipeline.run_scan(target.id, "sub1")
    # 出站计数含全部探测，但攻击流量只有 1 条真正发出（第 2 条被拦在出口）
    attack_reqs = [r for r in c.transport.requests if r.context == "attack"]
    assert len(attack_reqs) == 1
    assert c.evidence.verify() is True


def test_concurrency_guard(tmp_path):
    c, _ = _make_container(tmp_path)   # 默认上限 2
    c.budget.acquire_slot()
    c.budget.acquire_slot()
    with pytest.raises(BudgetExceeded):
        c.budget.acquire_slot()
    c.budget.release_slot()
    c.budget.acquire_slot()            # 释放后可再获取
