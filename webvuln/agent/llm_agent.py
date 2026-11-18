"""可插拔 LLM Agent（计划书 M3b 骨架）：只决策、不执行。

边界（刻意设计）：
- 本模块不引入任何 HTTP 客户端，`DecisionLLM` 是一个最小协议；
  真正接模型服务的适配器由使用者注入（`Container(llm_provider=...)`），
  因此**默认路径零外部依赖、零网络**，测试用 `ScriptedLLM` 即可覆盖。
- LLM 输出必须落在候选类型对应的白名单函数内，否则抛 `AgentDecisionError`：
  模型"自由发挥"选了一个不该调用的函数时，宁可不决策，也不放行。
- 输出解析失败同样抛 `AgentDecisionError`，由编排层决定降级（当前为候选挂起）。
"""
from __future__ import annotations

import json
from typing import Protocol, runtime_checkable

from webvuln.contracts.agent import AgentDecisionError, DecisionAgent
from webvuln.contracts.attack import AttackRegistry
from webvuln.models.schemas import AttackDecision, FindingCandidate, uid


@runtime_checkable
class DecisionLLM(Protocol):
    """最小 LLM 协议：给提示词，回一段文本。实现方负责超时、重试与计费。"""

    def complete(self, prompt: str) -> str: ...


class ScriptedLLM:
    """脚本化实现：按顺序返回预置文本。用于测试与离线演示，绝不触网。"""

    def __init__(self, responses: list[str]):
        self.responses = list(responses)
        self.prompts: list[str] = []

    def complete(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if not self.responses:
            return ""
        return self.responses.pop(0)


class LLMAgent(DecisionAgent):
    decision_source = "llm"

    def __init__(self, llm: DecisionLLM):
        self.llm = llm

    def decide(self, candidate: FindingCandidate, registry: AttackRegistry) -> AttackDecision:
        whitelist = [fn for fn in registry.all()
                     if fn.meta.vuln_type == candidate.vuln_type]
        if not whitelist:
            raise AgentDecisionError(
                f"攻击函数库中无匹配 {candidate.vuln_type} 的函数，候选挂起待扩展"
            )
        raw = self.llm.complete(self.build_prompt(candidate, whitelist))
        data = self._parse(raw)
        name = str(data.get("function_name", "")).strip()
        allowed = {fn.meta.name for fn in whitelist}
        if name not in allowed:
            raise AgentDecisionError(
                f"LLM 选择的函数 {name!r} 不在候选类型的白名单内（允许：{sorted(allowed)}），拒绝执行"
            )
        fn = next(f for f in whitelist if f.meta.name == name)
        return AttackDecision(
            id=uid("dec"),
            candidate_id=candidate.id,
            function_name=name,
            reason=str(data.get("reason") or "").strip() or "（LLM 未给出理由，如实标注）",
            expected_result=str(data.get("expected_result") or fn.meta.expected_signal),
            decision_source=self.decision_source,
        )

    @staticmethod
    def build_prompt(candidate: FindingCandidate, whitelist: list) -> str:
        catalogue = "\n".join(
            f"- {fn.meta.name}（风险 {fn.meta.risk_level.value}，"
            f"可逆={fn.meta.reversible}，副作用：{fn.meta.side_effects}，"
            f"预期信号：{fn.meta.expected_signal}）"
            for fn in whitelist
        )
        return (
            "你是 Web 漏洞复核平台的决策 Agent，只做决策，不执行任何请求。\n"
            f"候选漏洞类型：{candidate.vuln_type.value}\n"
            f"检测器：{candidate.detector}\n"
            f"检测器自述证据（ClaimOnly）：{candidate.claim}\n"
            "可选的模拟攻击函数（白名单，只能从中选一个）：\n"
            f"{catalogue}\n"
            '只输出 JSON：{"function_name": "...", "reason": "...", "expected_result": "..."}'
        )

    @staticmethod
    def _parse(raw: str) -> dict:
        text = (raw or "").strip()
        if text.startswith("```"):
            # 容忍模型习惯性包一层代码块
            text = text.strip("`")
            if text.lstrip().lower().startswith("json"):
                text = text.lstrip()[4:]
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, ValueError) as e:
            raise AgentDecisionError(f"LLM 输出不是合法 JSON，拒绝决策：{e}") from e
        if not isinstance(data, dict):
            raise AgentDecisionError("LLM 输出不是 JSON 对象，拒绝决策")
        return data
