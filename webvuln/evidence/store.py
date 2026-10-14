"""证据层实现：append-only JSONL 哈希链。

hash_i = SHA-256(prev_hash || canonical_json(record_i))，后一条包含前一条哈希，
任何篡改在 verify() 重放时暴露。SQLite evidence_index 表提供查询索引。
原始请求/响应的加密存储为后续增强点（计划书 5.4），本版先落盘+留痕。
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from webvuln.contracts.evidence import EvidenceStore
from webvuln.db.database import Database
from webvuln.models.schemas import EvidenceRecord, now_iso, uid

GENESIS = "GENESIS"


def canonical(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def compute_hash(prev_hash: str, record: dict) -> str:
    return hashlib.sha256((prev_hash + "|" + canonical(record)).encode("utf-8")).hexdigest()


class FileEvidenceStore(EvidenceStore):
    def __init__(self, root: str, db: Database):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.chain_path = self.root / "chain.jsonl"
        self.db = db
        self._last_hash = self._read_head()

    def _read_head(self) -> str:
        if not self.chain_path.exists():
            return GENESIS
        last = GENESIS
        with open(self.chain_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    last = json.loads(line)["hash"]
        return last

    def append(self, scan_id: str, kind: str, payload: dict) -> EvidenceRecord:
        rec = EvidenceRecord(
            id=uid("ev"), scan_id=scan_id, kind=kind, payload=payload,
            prev_hash=self._last_hash, created_at=now_iso(),
        )
        body = rec.model_dump(exclude={"hash"})
        rec.hash = compute_hash(rec.prev_hash, body)
        with open(self.chain_path, "a", encoding="utf-8") as f:
            f.write(canonical({**body, "hash": rec.hash}) + "\n")
        self._last_hash = rec.hash
        self.db.execute(
            "INSERT INTO evidence_index(id, scan_id, kind, hash, prev_hash, created_at)"
            " VALUES(?,?,?,?,?,?)",
            (rec.id, scan_id, kind, rec.hash, rec.prev_hash, rec.created_at),
        )
        return rec

    def _iter_records(self) -> list[EvidenceRecord]:
        if not self.chain_path.exists():
            return []
        out = []
        with open(self.chain_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(EvidenceRecord(**json.loads(line)))
        return out

    def get(self, evidence_id: str) -> EvidenceRecord | None:
        for rec in self._iter_records():
            if rec.id == evidence_id:
                return rec
        return None

    def for_scan(self, scan_id: str) -> list[EvidenceRecord]:
        return [r for r in self._iter_records() if r.scan_id == scan_id]

    def verify(self) -> bool:
        prev = GENESIS
        for rec in self._iter_records():
            body = rec.model_dump(exclude={"hash"})
            if rec.prev_hash != prev:
                return False
            if compute_hash(prev, body) != rec.hash:
                return False
            prev = rec.hash
        return True

    def verify_scan(self, scan_id: str) -> bool:
        if not self.verify():
            return False
        records = self.for_scan(scan_id)
        # 子链完整性：首条 prev_hash 必须指向链上真实存在的前驱
        if not records:
            return False
        known = {r.id for r in self._iter_records()}
        for rec in records:
            if rec.prev_hash == GENESIS:
                continue
            if not any(
                r.hash == rec.prev_hash and r.id in known for r in self._iter_records()
            ):
                return False
        return True

    def manifest(self) -> dict:
        records = self._iter_records()
        return {
            "head_hash": self._last_hash,
            "record_count": len(records),
            "verified": self.verify(),
        }
