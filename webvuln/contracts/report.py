"""报告层契约：仅读证据层/DB 汇总数据，不触达检测与攻击（计划书 3.1）。

v0.2.0 补 `summary()` 与 `metrics_global()`：Web 路由此前直接写 SQL 统计，
与报告层口径两份实现（PENDING 一处恒为 0），现在收归报告层唯一口径。
"""
from __future__ import annotations

from abc import ABC, abstractmethod


class Reporter(ABC):
    @abstractmethod
    def render(self, scan_id: str, fmt: str) -> str:
        """fmt ∈ {json, md, html}。返回报告文本。"""

    @abstractmethod
    def summary(self, scan_id: str) -> dict:
        """单次扫描的结构化汇总（报告与可视化共用同一份数据）。"""

    @abstractmethod
    def metrics_global(self) -> dict:
        """全局指标：TP/FP/INCONCLUSIVE/PENDING + 按漏洞类型分布。"""
