"""SQLite 持久化。仅本模块持有连接，其他模块通过 Database 执行 SQL。

选 sqlite3 标准库而非 ORM：减少依赖、满足"干净环境无手工修补"验收；
表结构即契约，schema 内联于本文件便于评审。
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  username TEXT PRIMARY KEY,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS targets(
  id TEXT PRIMARY KEY,
  url TEXT NOT NULL UNIQUE,
  scope TEXT NOT NULL,               -- JSON: list[str]
  base_params TEXT NOT NULL DEFAULT '{}',  -- JSON: dict[str,str]
  justification TEXT DEFAULT '',
  status TEXT NOT NULL,              -- pending/approved/rejected
  submitted_by TEXT NOT NULL,
  submitted_at TEXT NOT NULL,
  approved_by TEXT,
  approved_at TEXT,
  expires_at TEXT,
  allow_private INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS scans(
  id TEXT PRIMARY KEY,
  target_id TEXT NOT NULL,
  status TEXT NOT NULL,
  started_by TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT
);
CREATE TABLE IF NOT EXISTS candidates(
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL,
  target_id TEXT NOT NULL,
  vuln_type TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  parameter TEXT NOT NULL,
  claim TEXT NOT NULL,
  detector TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS decisions(
  id TEXT PRIMARY KEY,
  candidate_id TEXT NOT NULL,
  function_name TEXT NOT NULL,
  reason TEXT NOT NULL,
  expected_result TEXT NOT NULL,
  decision_source TEXT NOT NULL,
  risk_level TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS approvals(
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,                -- target / attack
  ref_id TEXT NOT NULL,
  action TEXT NOT NULL,              -- approve / reject
  actor TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS attack_runs(
  id TEXT PRIMARY KEY,
  decision_id TEXT NOT NULL UNIQUE,
  matched INTEGER NOT NULL,
  result_json TEXT NOT NULL,
  executed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS conclusions(
  id TEXT PRIMARY KEY,
  candidate_id TEXT NOT NULL UNIQUE,
  state TEXT NOT NULL,
  evidence_level TEXT NOT NULL,
  decided_by TEXT NOT NULL,
  signature_note TEXT DEFAULT '',
  signed_by TEXT,
  signed_at TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence_index(
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  hash TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);
"""


class Database:
    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        cur = self.conn.execute(sql, params)
        self.conn.commit()
        return cur

    def query(self, sql: str, params: tuple = ()) -> list[dict]:
        return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def one(self, sql: str, params: tuple = ()) -> dict | None:
        row = self.conn.execute(sql, params).fetchone()
        return dict(row) if row else None
