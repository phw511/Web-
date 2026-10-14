"""检测器契约：检测职责单一，不感知 Agent 与攻击，只输出候选。"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from webvuln.models.schemas import FindingCandidate, HttpSpec, TargetRegistration

if TYPE_CHECKING:  # 仅类型引用，避免循环依赖
    from webvuln.authz.egress import EgressGateway


class BaseDetector(ABC):
    name: str = "base"
    vuln_types: tuple = ()

    @abstractmethod
    def detect(
        self,
        gateway: "EgressGateway",
        target: TargetRegistration,
        base: HttpSpec,
        scan_id: str,
    ) -> list[FindingCandidate]:
        """对授权目标执行检测。所有出站请求必须经 gateway.send()。"""
