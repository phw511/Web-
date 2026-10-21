from fastapi.testclient import TestClient

from webvuln.web.app import create_app
from tests.conftest import auth_headers


def _client(container):
    return TestClient(create_app(container.settings, container=container))


def test_login_and_dual_approval(container):
    client = _client(container)
    bad = client.post("/api/auth/login", json={"username": "sub1", "password": "wrong"})
    assert bad.status_code == 401
    ok = client.post("/api/auth/login", json={"username": "sub1", "password": "subpass1"})
    assert ok.status_code == 200 and ok.json()["role"] == "submitter"

    sub = auth_headers(container, "sub1", "subpass1")
    reg = client.post("/api/targets", json={
        "url": "http://t1.example.com", "justification": "测试"}, headers=sub)
    assert reg.status_code == 201

    # submitter 无审批角色 → 403
    r = client.post(f"/api/targets/{reg.json()['id']}/approve",
                    json={"reason": "x"}, headers=sub)
    assert r.status_code == 403
    # approver 审批（非提交人）→ 200
    appr = auth_headers(container, "app1", "apppass1")
    r2 = client.post(f"/api/targets/{reg.json()['id']}/approve",
                     json={"reason": "材料齐全"}, headers=appr)
    assert r2.status_code == 200


def test_scan_report_sign_flow(container, approved_target):
    client = _client(container)
    sub = auth_headers(container, "sub1", "subpass1")
    scan = client.post("/api/scans", json={"target_id": approved_target.id}, headers=sub)
    assert scan.status_code == 201
    scan_id = scan.json()["scan_id"]

    detail = client.get(f"/api/scans/{scan_id}", headers=sub)
    assert detail.json()["evidence"]["verified"] is True

    cons = client.get("/api/conclusions", params={"scan_id": scan_id}, headers=sub)
    con_id = cons.json()[0]["id"]

    sig = auth_headers(container, "sig1", "sigpass1")
    s = client.post(f"/api/conclusions/{con_id}/sign", json={"note": "签署"}, headers=sig)
    assert s.status_code == 200

    md = client.get(f"/api/reports/{scan_id}?format=md", headers=sub)
    assert "TP=1" in md.text

    stats = client.get("/api/stats", headers=sub).json()
    assert stats["TP"] == 1 and stats["FN"] is None
