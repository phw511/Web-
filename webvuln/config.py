"""平台配置：全部支持环境变量覆盖，保证干净环境可启动（验收：可运行）。"""
import os
from dataclasses import dataclass


@dataclass
class Settings:
    db_path: str = "data/app.db"
    evidence_dir: str = "evidence"
    jwt_secret: str = "change-me-in-production"
    jwt_ttl_seconds: int = 8 * 3600
    http_timeout: int = 10
    # 预算控制（计划书第 9 章数值化口径）
    llm_rounds_per_target: int = 10
    scan_timeout_seconds: int = 300
    max_attack_requests_per_target: int = 50
    max_concurrency: int = 2


def load_settings() -> Settings:
    s = Settings()
    s.db_path = os.environ.get("WEBVULN_DB_PATH", s.db_path)
    s.evidence_dir = os.environ.get("WEBVULN_EVIDENCE_DIR", s.evidence_dir)
    s.jwt_secret = os.environ.get("WEBVULN_JWT_SECRET", s.jwt_secret)
    return s
