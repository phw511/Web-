"""攻击函数库契约：白名单注册 + 元数据运行期校验（防降级欺骗）。

新增漏洞只需新增"检测器 + 攻击函数"单元：攻击函数用 @register_attack
装饰即完成注册，不改动其余任何模块（可插拔扩展）。
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional

from webvuln.models.schemas import (
    AttackFunctionMeta, AttackResult, FindingCandidate, HttpSpec, RiskLevel,
)

if TYPE_CHECKING:
    from webvuln.authz.egress import EgressGateway

# 高危特征关键词：side_effects 中出现且自标低危的函数将被拒绝加载（计划书 4.2 治理）
HIGH_SIGNAL_KEYWORDS = (
    "write", "delete", "drop", "insert", "update", "exec",
    "upload", "file_put", "truncate", "grant",
)


class AttackFunction(ABC):
    meta: AttackFunctionMeta

    @abstractmethod
    def execute(
        self,
        gateway: "EgressGateway",
        candidate: FindingCandidate,
        base: HttpSpec,
        decision_id: str,
    ) -> AttackResult:
        """执行验证型模拟攻击。所有出站请求必须经 gateway.send()。"""


class AttackRegistry:
    def __init__(self) -> None:
        self._functions: dict[str, AttackFunction] = {}

    def register(self, fn: AttackFunction) -> None:
        meta = fn.meta
        lowered = meta.side_effects.lower()
        if meta.risk_level == RiskLevel.LOW and any(
            k in lowered for k in HIGH_SIGNAL_KEYWORDS
        ):
            raise ValueError(
                f"运行期元数据校验失败：函数 {meta.name} 含高危特征却自标低危，拒绝加载"
            )
        self._functions[meta.name] = fn

    def get(self, name: str) -> Optional[AttackFunction]:
        return self._functions.get(name)

    def for_vuln(self, vuln_type) -> Optional[AttackFunction]:
        for fn in self._functions.values():
            if fn.meta.vuln_type == vuln_type:
                return fn
        return None

    def all(self) -> list[AttackFunction]:
        return list(self._functions.values())


_default_registry = AttackRegistry()


def register_attack(cls):
    """装饰器：实例化并注册到默认白名单。"""
    _default_registry.register(cls())
    return cls


def default_registry() -> AttackRegistry:
    return _default_registry
