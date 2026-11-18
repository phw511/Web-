"""可插拔 LLM Agent 的决策边界测试（计划书 M3b）。

为什么这些用例重要：LLM 是本平台唯一"非确定性"的决策来源。
若不把"只能选白名单函数""输出必须是合法 JSON""没有匹配函数时不决策"
钉成断言，接上真实模型后就会出现"模型自由发挥 → 执行了不该执行的函数"。
本文件全程用 ScriptedLLM（脚本化、不触网），因此可离线稳定复现。
"""
import pytest

from webvuln.agent.llm_agent import LLMAgent, ScriptedLLM
from webvuln.config import Settings
from webvuln.container import Container
from webvuln.contracts.agent import AgentDecisionError
from webvuln.contracts.attack import default_registry
from webvuln.models.schemas import FindingCandidate, VulnType, now_iso, uid


def _cand(vt=VulnType.SQLI) -> FindingCandidate:
    return FindingCandidate(
        id=uid("cand"), scan_id="s1", target_id="t1", vuln_type=vt,
        endpoint="http://x", parameter="q",
        claim="错误型信号：响应包含数据库错误特征", detector="sqli_error_boolean_v1",
        created_at=now_iso(),
    )


def test_llm_decision_uses_whitelisted_function():
    llm = ScriptedLLM(['{"function_name": "sqli_boolean_probe",'
                       ' "reason": "检测器报告错误型信号，优先用布尔复验",'
                       ' "expected_result": "长度差 > 20%"}'])
    dec = LLMAgent(llm).decide(_cand(), default_registry())

    assert dec.function_name == "sqli_boolean_probe"
    assert dec.decision_source == "llm"
    assert "错误型信号" in dec.reason          # 理由须可回溯到候选证据
    assert "白名单" in llm.prompts[0]          # 提示词禁选白名单外函数


def test_llm_cannot_pick_function_outside_vuln_type():
    # 候选是 SQLi，却选 XSS 函数：不在该类型的白名单内，必须拒绝
    llm = ScriptedLLM(['{"function_name": "xss_reflected_probe", "reason": "随便选"}'])
    with pytest.raises(AgentDecisionError):
        LLMAgent(llm).decide(_cand(), default_registry())


def test_llm_illegal_json_is_rejected():
    llm = ScriptedLLM(["我觉得应该用 sqli_boolean_probe"])
    with pytest.raises(AgentDecisionError):
        LLMAgent(llm).decide(_cand(), default_registry())


def test_no_matching_function_does_not_call_llm():
    # IDOR 尚无注册攻击函数：直接挂起，不该浪费一次模型调用
    llm = ScriptedLLM(["{}"])
    with pytest.raises(AgentDecisionError):
        LLMAgent(llm).decide(_cand(VulnType.IDOR), default_registry())
    assert llm.prompts == []


def test_llm_mode_requires_injected_provider(tmp_path):
    settings = Settings(db_path=str(tmp_path / "app.db"),
                        evidence_dir=str(tmp_path / "evidence"),
                        jwt_secret="t", agent_mode="llm")
    with pytest.raises(ValueError):
        Container(settings)          # 未注入 DecisionLLM，不应静默退回规则 Agent
