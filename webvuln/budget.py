"""预算强制实现（计划书第 9 章四项数值化上限）。

为什么单独成模块：四项上限的数值口径、判定与记账集中于此，编排层/出口/执行器
只调用契约方法。这样"调数值"只需改 config，"换算法"只需换本文件实现。

线程安全：Web 层为同步路由（FastAPI 线程池），必须加锁；计数器用锁而非信号量，
是为了在超限时能给出"第几条被拦"的可核查信息。
"""
from __future__ import annotations

import threading
import time

from webvuln.config import Settings
from webvuln.contracts.budget import (
    KIND_CONCURRENCY, KIND_REQUESTS, KIND_ROUNDS, KIND_TIME,
    BudgetExceeded, BudgetGuardContract,
)

__all__ = [
    "BudgetGuard", "NullBudget", "BudgetExceeded",
    "KIND_TIME", "KIND_ROUNDS", "KIND_REQUESTS", "KIND_CONCURRENCY",
]


class BudgetGuard(BudgetGuardContract):
    def __init__(self, settings: Settings):
        self.settings = settings
        self._lock = threading.Lock()
        self._scan_id: str | None = None
        self._target_url: str | None = None
        self._deadline: float | None = None
        self._started_at: float | None = None
        self._rounds = 0
        self._attack_requests: dict[str, int] = {}
        self._in_use = 0

    # ---- 生命周期 ----
    def start_scan(self, scan_id: str, target_url: str) -> None:
        with self._lock:
            self._scan_id = scan_id
            self._target_url = target_url
            self._started_at = time.monotonic()
            self._deadline = self._started_at + float(self.settings.scan_timeout_seconds)
            self._rounds = 0
            self._attack_requests.setdefault(target_url, 0)

    # ---- 时长 ----
    def check_time(self, phase: str = "") -> None:
        if self._deadline is None:
            return
        if time.monotonic() >= self._deadline:
            raise BudgetExceeded(
                KIND_TIME, self.settings.scan_timeout_seconds,
                f"扫描 {self._scan_id} 已超过 {self.settings.scan_timeout_seconds}s 上限"
                f"（阶段：{phase or '未标注'}），停止并留痕",
            )

    # ---- 轮次 ----
    def check_round(self) -> None:
        with self._lock:
            self._rounds += 1
            nth = self._rounds
        limit = self.settings.llm_rounds_per_target
        if nth > limit:
            raise BudgetExceeded(
                KIND_ROUNDS, limit,
                f"决策轮次已达上限 {limit}，第 {nth} 轮不再下发（已处理部分保留）",
            )

    # ---- 攻击请求数（唯一出口记账）----
    def charge_attack_request(self, target_url: str) -> None:
        with self._lock:
            nth = self._attack_requests.get(target_url, 0) + 1
            self._attack_requests[target_url] = nth
        limit = self.settings.max_attack_requests_per_target
        if nth > limit:
            raise BudgetExceeded(
                KIND_REQUESTS, limit,
                f"目标 {target_url} 的攻击请求将达第 {nth} 条，超过上限 {limit}，"
                "已在唯一出口拦截（未发包）",
            )

    # ---- 并发 ----
    def acquire_slot(self) -> None:
        with self._lock:
            if self._in_use >= self.settings.max_concurrency:
                raise BudgetExceeded(
                    KIND_CONCURRENCY, self.settings.max_concurrency,
                    f"攻击并发已达上限 {self.settings.max_concurrency}",
                )
            self._in_use += 1

    def release_slot(self) -> None:
        with self._lock:
            if self._in_use > 0:
                self._in_use -= 1

    # ---- 观测 ----
    def snapshot(self) -> dict:
        elapsed = None
        if self._started_at is not None:
            elapsed = round(time.monotonic() - self._started_at, 3)
        with self._lock:
            return {
                "scan_id": self._scan_id,
                "target_url": self._target_url,
                "elapsed_seconds": elapsed,
                "rounds_used": self._rounds,
                "attack_requests": dict(self._attack_requests),
                "in_use": self._in_use,
                "limits": {
                    "llm_rounds_per_target": self.settings.llm_rounds_per_target,
                    "scan_timeout_seconds": self.settings.scan_timeout_seconds,
                    "max_attack_requests_per_target":
                        self.settings.max_attack_requests_per_target,
                    "max_concurrency": self.settings.max_concurrency,
                },
            }


class NullBudget(BudgetGuardContract):
    """不设限实现：离线模拟（sim）与单元测试的默认注入，行为等价于旧版本。"""

    def start_scan(self, scan_id: str, target_url: str) -> None: ...

    def check_time(self, phase: str = "") -> None: ...

    def check_round(self) -> None: ...

    def charge_attack_request(self, target_url: str) -> None: ...

    def acquire_slot(self) -> None: ...

    def release_slot(self) -> None: ...

    def snapshot(self) -> dict:
        return {"limits": None, "note": "NullBudget：未启用预算强制"}
