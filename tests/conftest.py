"""测试设施：临时目录容器 + 模拟易受攻击端点的 FakeTransport。"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from webvuln.config import Settings
from webvuln.container import Container
from webvuln.contracts.transport import Transport
from webvuln.models.schemas import ResponseSnapshot, Role


class FakeVulnTransport(Transport):
    """模拟带 SQLi 布尔差异的易受攻击端点。

    - 恒假条件 → 短响应；恒真 → 长响应；裸引号 → 数据库报错
    - 记录所有请求以便断言"未授权零发包"
    """

    def __init__(self, vulnerable: bool = True):
        self.vulnerable = vulnerable
        self.requests = []

    def send(self, spec) -> ResponseSnapshot:
        self.requests.append(spec)
        q = spec.params.get("q", "")
        if self.vulnerable:
            if "'1'='2" in q:
                return ResponseSnapshot(status_code=200, body="Empty.")
            if q.endswith("'"):
                return ResponseSnapshot(
                    status_code=500,
                    body="You have an error in your SQL syntax; check the manual")
            return ResponseSnapshot(status_code=200,
                                    body="Welcome. Items: book, pen, cup, desk.")
        return ResponseSnapshot(status_code=200,
                                body="Welcome. Items: book, pen, cup, desk.")


@pytest.fixture()
def container(tmp_path):
    settings = Settings(
        db_path=str(tmp_path / "app.db"),
        evidence_dir=str(tmp_path / "evidence"),
        jwt_secret="test-secret",
    )
    c = Container(settings)
    c.transport = FakeVulnTransport(vulnerable=True)
    c.gateway.transport = c.transport
    c.users.create("admin", "admin123", Role.ADMIN)
    c.users.create("sub1", "subpass1", Role.SUBMITTER)
    c.users.create("app1", "apppass1", Role.APPROVER)
    c.users.create("sig1", "sigpass1", Role.SIGNER)
    return c


@pytest.fixture()
def approved_target(container):
    reg = container.authorizer.submit_target(
        "sub1", "http://vuln.example.com", ["/"], {"q": "book"},
        "课程授权靶场", allow_private=False,
    )
    container.authorizer.approve_target("app1", reg.id, "授权材料齐全")
    return container.authorizer.get_target(reg.id)


def auth_headers(container, username, password):
    user = container.users.verify(username, password)
    token = container.tokens.issue(user["username"], user["role"])
    return {"Authorization": f"Bearer {token}"}
