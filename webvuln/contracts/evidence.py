"""证据层契约：append-only + 哈希链，供复核与报告读取（计划书 5.2）。

v0.2.0 补 `manifest()`：计划书第 10 章把 manifest 作为评价方审查入口
（逐条索引哈希/类型/scan_id/关联结论/运行版本），此前只有实现里有一个
三道字段的简版，契约里根本没声明——契约不完整，依赖倒置就只做了一半。
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from webvuln.models.schemas import EvidenceRecord


class EvidenceStore(ABC):
    @abstractmethod
    def append(self, scan_id: str, kind: str, payload: dict) -> EvidenceRecord: ...

    @abstractmethod
    def get(self, evidence_id: str) -> EvidenceRecord | None: ...

    @abstractmethod
    def for_scan(self, scan_id: str) -> list[EvidenceRecord]: ...

    @abstractmethod
    def verify(self) -> bool:
        """重放全链校验哈希，防篡改。"""

    @abstractmethod
    def verify_scan(self, scan_id: str) -> bool:
        """校验某次扫描的子链完整性（含前驱可达性）。"""

    @abstractmethod
    def manifest(self) -> dict:
        """机器可读索引：head_hash / record_count / verified / app_version / records[]。"""
