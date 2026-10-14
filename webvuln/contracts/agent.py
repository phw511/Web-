"""Agent 编排契约：只决策、不执行（计划书 3.1：不直接执行攻击，只下发指令）。"""
from __future__ import annotations

from abc import ABC, abstractmethod

from webvuln.contracts.attack import AttackRegistry
from webvuln.models.schemas import AttackDecision, FindingCandidate


class AgentDecisionError(Exception):
    pass


class DecisionAgent(ABC):
    @abstractmethod
    def decide(
        self, candidate: FindingCandidate, registry: AttackRegistry
    ) -> AttackDecision:
        """分析候选，从白名单攻击函数库挑选匹配函数并给出理由。

        M3b 将接入真实 LLM（实现同一抽象，decision_source=llm）；
        初版为规则 Agent，保证 LLM 不可用时主线可用（计划书第 9 章降级策略）。
        """
