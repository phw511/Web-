"""授权控制层契约：目标注册审批、分级放行、出口管控的统一口径。"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from webvuln.models.schemas import (
    ApprovalRecord, TargetRegistration, TargetStatus,
)


class AuthorizationError(Exception):
    pass


class ApprovalForbidden(AuthorizationError):
    """审批人角色不足（中危需 approver、高危需 signer）。

    独立成子类，是为了让 Web 层把"角色不够"映射成 403、
    把其他授权错误映射成 400——判定规则只有授权层一份，路由只做映射。
    """


class EgressDenied(Exception):
    """未授权/超范围/SSRF 拦截：任何出站请求被拦前不得发包。"""


class Authorizer(ABC):
    @abstractmethod
    def submit_target(
        self, username: str, url: str, scope_paths: list[str],
        base_params: dict, justification: str, allow_private: bool = False,
    ) -> TargetRegistration: ...

    @abstractmethod
    def approve_target(
        self, actor: str, target_id: str, reason: str, allow_private: bool = False
    ) -> ApprovalRecord: ...

    @abstractmethod
    def reject_target(self, actor: str, target_id: str, reason: str) -> ApprovalRecord: ...

    @abstractmethod
    def get_target(self, target_id: str) -> Optional[TargetRegistration]: ...

    @abstractmethod
    def list_targets(self, status: Optional[TargetStatus] = None) -> list[TargetRegistration]: ...

    @abstractmethod
    def record_attack_approval(
        self, actor: str, decision_id: str, action: str, reason: str
    ) -> ApprovalRecord: ...

    @abstractmethod
    def attack_approved(self, decision_id: str) -> bool: ...

    @abstractmethod
    def assert_approval_allowed(self, actor_role: str, risk_level: str) -> None:
        """分级放行的唯一判定处：中危→approver、高危→signer（admin 兜底）。

        违规抛 ApprovalForbidden。此前该规则写在 Web 路由里，CLI/内部调用可绕过。
        """
