import pytest

from webvuln.contracts.authz import EgressDenied
from webvuln.models.schemas import HttpSpec


def test_unregistered_target_zero_packets(container):
    spec = HttpSpec(url="http://evil.example.com/x")
    with pytest.raises(EgressDenied):
        container.gateway.send(spec)
    assert container.transport.requests == []  # 未发包即拦截


def test_out_of_scope_path_blocked(container):
    # 根 scope "/" 在本设计中表示整站放行（扫描依赖它），
    # 故用窄 scope 演示"越范围路径拦截"：只授权 /search，请求 /admin 应被拦。
    reg = container.authorizer.submit_target(
        "sub1", "http://vuln.example.com", ["/search"], {"q": "1"}, "窄范围靶场")
    container.authorizer.approve_target("app1", reg.id, "仅授权 /search")
    spec = HttpSpec(url=reg.url + "/admin", params={"q": "1"})
    with pytest.raises(EgressDenied):
        container.gateway.send(spec)


def test_private_ip_blocked_unless_flagged(container, monkeypatch):
    from webvuln.authz import egress as egress_mod
    monkeypatch.setattr(egress_mod, "_resolve_ip", lambda host: "127.0.0.1")
    reg = container.authorizer.submit_target(
        "sub1", "http://127.0.0.1:8081", ["/"], {"q": "1"}, "本地 DVWA 靶场",
        allow_private=True)
    with pytest.raises(EgressDenied):
        container.gateway.send(HttpSpec(url=reg.url, params={"q": "1"}))
    container.authorizer.approve_target("app1", reg.id, "本地靶场", allow_private=True)
    resp = container.gateway.send(HttpSpec(url=reg.url, params={"q": "1"}))
    assert resp.status_code == 200


def test_same_person_cannot_approve(container):
    from webvuln.contracts.authz import AuthorizationError
    reg = container.authorizer.submit_target(
        "sub1", "http://t2.example.com", ["/"], {}, "自审测试")
    with pytest.raises(AuthorizationError):
        container.authorizer.approve_target("sub1", reg.id, "自己批自己")
