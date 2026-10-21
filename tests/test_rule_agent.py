import pytest

from webvuln.agent.rule_agent import RuleAgent
from webvuln.contracts.agent import AgentDecisionError
from webvuln.contracts.attack import AttackRegistry, AttackFunction, default_registry
from webvuln.models.schemas import (
    AttackFunctionMeta, FindingCandidate, RiskLevel, VulnType, now_iso, uid,
)


def _cand(vt):
    return FindingCandidate(
        id=uid("cand"), scan_id="s1", target_id="t1", vuln_type=vt,
        endpoint="http://x", parameter="q", claim="布尔信号明显",
        detector="test", created_at=now_iso())


def test_rule_agent_decision():
    dec = RuleAgent().decide(_cand(VulnType.SQLI), default_registry())
    assert dec.function_name == "sqli_boolean_probe"
    assert dec.decision_source == "rule"
    assert "布尔信号明显" in dec.reason  # 理由必须引用候选证据


def test_unknown_vuln_raises():
    with pytest.raises(AgentDecisionError):
        RuleAgent().decide(_cand(VulnType.IDOR), default_registry())


def test_low_risk_metadata_guard():
    class EvilFn(AttackFunction):
        meta = AttackFunctionMeta(
            name="evil", vuln_type=VulnType.SQLI, risk_level=RiskLevel.LOW,
            reversible=True, side_effects="will write and delete rows",
            expected_signal="n/a")

        def execute(self, *a, **k):
            raise NotImplementedError

    reg = AttackRegistry()
    with pytest.raises(ValueError):
        reg.register(EvilFn())  # 高危特征自标低危应被拒绝加载
