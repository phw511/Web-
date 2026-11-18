"""证据层实现：append-only JSONL 哈希链。

hash_i = SHA-256(prev_hash || canonical_json(record_i))，后一条包含前一条哈希，
任何篡改在 verify() 重放时暴露。SQLite evidence_index 表提供查询索引。
原始请求/响应的加密存储为后续增强点（计划书 5.4），本版先落盘+留痕。

v0.2.0：
- 每条记录写入运行身份 `app_version`（计划书 5.2"能关联"）；
- `manifest()` 扩为逐条机器可读索引（计划书第 10 章评价方审查入口）；
- `verify_scan()` 去掉内层重复全量读取（原实现 O(n²)）。
- 兼容性：哈希计算对空 app_version 做排除，旧证据链升级后仍能通过校验。
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from webvuln.contracts.evidence import EvidenceStore
from webvuln.db.database import Database
from webvuln.models.schemas import EvidenceRecord, now_iso, uid

GENESIS = "GENESIS"
DEFAULT_APP_VERSION = "0.2.0"


def canonical(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def compute_hash(prev_hash: str, record: dict) -> str:
    return hashlib.sha256((prev_hash + "|" + canonical(record)).encode("utf-8")).hexdigest()


def _body(record: EvidenceRecord) -> dict:
    """参与哈希的正文：空 app_version 不入链（兼容 0.1.x 写入的旧记录）。"""
    body = record.model_dump(exclude={"hash"})
    if not body.get("app_version"):
        body.pop("app_version", None)
    return body


class FileEvidenceStore(EvidenceStore):
    def __init__(self, root: str, db: Database, app_version: str = DEFAULT_APP_VERSION):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.chain_path = self.root / "chain.jsonl"
        self.db = db
        self.app_version = app_version
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
            app_version=self.app_version,
        )
        body = _body(rec)
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
            if rec.prev_hash != prev:
                return False
            if compute_hash(prev, _body(rec)) != rec.hash:
                return False
            prev = rec.hash
        return True

    def verify_scan(self, scan_id: str) -> bool:
        if not self.verify():
            return False
        records = self._iter_records()
        if not records:
            return False
        sub = [r for r in records if r.scan_id == scan_id]
        if not sub:
            return False
        # 子链完整性：首条可指向 GENESIS，其余必须指向链上真实存在的前驱
        known = {r.hash for r in records}
        return all(r.prev_hash == GENESIS or r.prev_hash in known for r in sub)

    # ---- 机器可读索引（计划书 10 章：评价方审查入口） ----
    def _conclusion_map(self) -> dict[str, list[str]]:
        mapping: dict[str, list[str]] = {}
        for row in self.db.query("SELECT id, candidate_id FROM conclusions"):
            mapping.setdefault(row["candidate_id"], []).append(row["id"])
        return mapping

    def manifest(self) -> dict:
        records = self._iter_records()
        by_candidate = self._conclusion_map()
        entries = []
        for rec in records:
            payload = rec.payload or {}
            conclusion_ids: list[str] = []
            candidate_id = payload.get("candidate_id")
            if candidate_id:
                conclusion_ids.extend(by_candidate.get(candidate_id, []))
            if payload.get("conclusion_id"):
                conclusion_ids.append(payload["conclusion_id"])
            entries.append({
                "id": rec.id,
                "kind": rec.kind,
                "scan_id": rec.scan_id,
                "hash": rec.hash,
                "prev_hash": rec.prev_hash,
                "created_at": rec.created_at,
                "app_version": rec.app_version,
                "conclusion_ids": conclusion_ids,
                "signature": None,   # 预留位：签署密钥签名为增强项（计划书 5.2）
            })
        return {
            "app_version": self.app_version,
            "head_hash": self._last_hash,
            "record_count": len(records),
            "verified": self.verify(),
            "records": entries,
        }
