"""规则 Agent（M3a）：候选特征 → 白名单攻击函数映射，给出结构化理由。

决策理由必须引用候选证据摘录，不允许无据决策；同一抽象接口
后续由 LLM Agent 实现（decision_source=llm），实现即插拔替换。
"""
from __future__ import annotations

from webvuln.contracts.agent import AgentDecisionError, DecisionAgent
from webvuln.contracts.attack import AttackRegistry
from webvuln.models.schemas import AttackDecision, FindingCandidate, uid


class RuleAgent(DecisionAgent):
    def decide(
        self, candidate: FindingCandidate, registry: AttackRegistry
    ) -> AttackDecision:
        fn = registry.for_vuln(candidate.vuln_type)
        if fn is None:
            raise AgentDecisionError(
                f"攻击函数库中无匹配 {candidate.vuln_type} 的函数，候选挂起待扩展"
            )
        meta = fn.meta
        reason = (
            f"候选 {candidate.id}（{candidate.vuln_type}，检测器 {candidate.detector}）"
            f"报告证据：{candidate.claim}；"
            f"选择模拟攻击函数 {meta.name}：风险 {meta.risk_level}，"
            f"可逆={meta.reversible}，副作用声明「{meta.side_effects}」；"
            f"预期信号：{meta.expected_signal}"
        )
        return AttackDecision(
            id=uid("dec"), candidate_id=candidate.id, function_name=meta.name,
            reason=reason, expected_result=meta.expected_signal,
            decision_source="rule",
        )
