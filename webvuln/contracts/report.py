"""报告层契约：仅读证据层/DB 汇总数据，不触达检测与攻击（计划书 3.1）。"""
from __future__ import annotations

from abc import ABC, abstractmethod


class Reporter(ABC):
    @abstractmethod
    def render(self, scan_id: str, fmt: str) -> str:
        """fmt ∈ {json, md, html}。返回报告文本。"""
