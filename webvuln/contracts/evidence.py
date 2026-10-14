"""证据层契约：append-only + 哈希链，供复核与报告读取（计划书 5.2）。"""
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
    def verify_scan(self, scan_id: str) -> bool: ...
