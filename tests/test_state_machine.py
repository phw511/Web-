import pytest

from webvuln.models.schemas import CandidateState, ResponseSnapshot


def test_full_pipeline_low_risk(container, approved_target):
    result = container.pipeline.run_scan(approved_target.id, "sub1")
    assert result["candidates"] == 1
    assert result["auto_executed"] == 1
    con = container.db.one("SELECT * FROM conclusions")
    assert con["state"] == CandidateState.CONFIRMED.value
    assert con["evidence_level"] == "Reproduced"
    replay = container.pipeline.replay(result["scan_id"])
    assert replay["verified"] is True
    kinds = [t["kind"] for t in replay["timeline"]]
    assert kinds == ["scan_start", "decision", "approval",
                     "attack_request", "attack_response", "state_change"]


def test_negative_target_rejected(container):
    from tests.conftest import FakeVulnTransport
    container.gateway.transport = FakeVulnTransport(vulnerable=False)
    reg = container.authorizer.submit_target(
        "sub1", "http://safe.example.com", ["/"], {"q": "1"}, "对照站点")
    container.authorizer.approve_target("app1", reg.id, "ok")
    result = container.pipeline.run_scan(reg.id, "sub1")
    assert result["candidates"] == 0


def test_sign_confirmed_conclusion(container, approved_target):
    container.pipeline.run_scan(approved_target.id, "sub1")
    con = container.db.one("SELECT * FROM conclusions")
    container.pipeline.sign_conclusion("sig1", con["id"], "证据链完整，签署")
    signed = container.db.one("SELECT * FROM conclusions WHERE id=?", (con["id"],))
    assert signed["signed_by"] == "sig1"


def test_sign_inconclusive_forbidden(container):
    # 用一个只暴露 LFI（中危）、不触发 SQLi/XSS 的传输层：
    # run_scan 产出 1 个中危候选，按分级策略不自动执行、转人工审批。
    class LfiOnlyTransport:
        def send(self, spec):
            q = spec.params.get("q", "")
            if "../../../../etc/passwd" in q:
                return ResponseSnapshot(
                    status_code=200,
                    body="root:x:0:0:root:/root:/bin/bash\n"
                         "www-data:x:33:33::/var/www:/usr/sbin/nologin",
                )
            return ResponseSnapshot(status_code=200, body="Welcome. page rendered.")

    container.gateway.transport = LfiOnlyTransport()
    reg = container.authorizer.submit_target(
        "sub1", "http://lfi.example.com", ["/"], {"q": "home"}, "LFI 靶场")
    container.authorizer.approve_target("app1", reg.id, "ok")
    result = container.pipeline.run_scan(reg.id, "sub1")
    assert result["candidates"] == 1
    assert result["pending_approval"] == 1  # 中危不自动执行

    dec = container.db.one(
        "SELECT * FROM decisions WHERE risk_level='medium'")
    container.pipeline.execute_approved(
        "app1", dec["id"], "reject", "暂不验证")
    con = container.db.one("SELECT * FROM conclusions")
    assert con["state"] == "INCONCLUSIVE"
    with pytest.raises(Exception):
        container.pipeline.sign_conclusion("sig1", con["id"], "x")
