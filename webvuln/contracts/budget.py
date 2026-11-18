"""预算契约：计划书第 9 章四项数值化上限的唯一口径。

设计要点（高内聚低耦合）：
- 四项上限的"判定"属于预算模块，三项"强制点"分居三层各自最自然的位置：
  时长/轮次 → 编排层（pipeline）；请求数 → 唯一网络出口（egress）；并发 → 攻击执行器；
- 三层只依赖本契约，不认识 `BudgetGuard` 具体实现，因此可注入 NullBudget（离线模拟）
  或测试替身，不必改这三层任何一行代码。
"""
from __future__ import annotations

from abc import ABC, abstractmethod

# 超限种类：证据层 kind=budget_exceeded 的 payload 与测试断言共用这几个字面量
KIND_TIME = "时长"
KIND_ROUNDS = "轮次"
KIND_REQUESTS = "请求数"
KIND_CONCURRENCY = "并发"


class BudgetExceeded(Exception):
    """预算超限。编排层据 `kind` 决定"停扫描"还是"上抛给调用方"。"""

    def __init__(self, kind: str, limit, message: str = ""):
        self.kind = kind
        self.limit = limit
        detail = f"（{kind}上限 {limit}）"
        super().__init__(f"预算超限{detail}" + (f"：{message}" if message else ""))


class BudgetGuardContract(ABC):
    """四项上限的强制接口。实现方必须是线程安全的（FastAPI 多线程调用）。"""

    @abstractmethod
    def start_scan(self, scan_id: str, target_url: str) -> None:
        """开始一次扫描：重置计时与轮次，登记目标的攻击请求计数。"""

    @abstractmethod
    def check_time(self, phase: str = "") -> None:
        """检测/决策阶段超时即抛 BudgetExceeded(KIND_TIME)。"""

    @abstractmethod
    def check_round(self) -> None:
        """下发一次 Agent 决策前调用；超出轮次上限抛 BudgetExceeded(KIND_ROUNDS)。"""

    @abstractmethod
    def charge_attack_request(self, target_url: str) -> None:
        """攻击请求在唯一出口发包前记账；超限抛 BudgetExceeded(KIND_REQUESTS)。"""

    @abstractmethod
    def acquire_slot(self) -> None:
        """获取一个攻击并发槽位；无可用槽位抛 BudgetExceeded(KIND_CONCURRENCY)。"""

    @abstractmethod
    def release_slot(self) -> None:
        """释放并发槽位（与 acquire_slot 成对，必须在 finally 中调用）。"""

    @abstractmethod
    def snapshot(self) -> dict:
        """当前预算快照，用于写入证据层（budget_exceeded 的 payload）。"""
