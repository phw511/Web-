"""平台配置：全部支持环境变量覆盖，保证干净环境可启动（验收：可运行）。

v0.2.0：补上计划书 5.2 要求的"运行身份"（app_version）与第 9 章四项预算的
环境变量覆盖——此前 plan 文档声称支持、代码里却只有 3 项。
"""
import os
from dataclasses import dataclass


@dataclass
class Settings:
    # 存储与鉴权
    db_path: str = "data/app.db"
    evidence_dir: str = "evidence"
    jwt_secret: str = "change-me-in-production"
    jwt_ttl_seconds: int = 8 * 3600
    http_timeout: int = 10

    # 运行身份（计划书 5.2：跨版本回归时能区分记录归属版本）
    app_version: str = "0.2.0"

    # Agent 模式：rule（默认，零外部依赖）/ llm（需注入 DecisionLLM 实现）
    agent_mode: str = "rule"

    # 预算控制（计划书第 9 章数值化口径）
    llm_rounds_per_target: int = 10
    scan_timeout_seconds: int = 300
    max_attack_requests_per_target: int = 50
    max_concurrency: int = 2


def _str_env(name: str, default: str) -> str:
    value = os.environ.get(name)
    return value if value not in (None, "") else default


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw in (None, ""):
        return default
    try:
        return int(raw)
    except ValueError:
        # 配置非法不静默吞掉：默认值继续可用，但把问题显式打出来
        print(f"[config] 环境变量 {name}={raw!r} 不是整数，回退默认值 {default}")
        return default


def load_settings() -> Settings:
    s = Settings()
    s.db_path = _str_env("WEBVULN_DB_PATH", s.db_path)
    s.evidence_dir = _str_env("WEBVULN_EVIDENCE_DIR", s.evidence_dir)
    s.jwt_secret = _str_env("WEBVULN_JWT_SECRET", s.jwt_secret)
    s.jwt_ttl_seconds = _int_env("WEBVULN_JWT_TTL", s.jwt_ttl_seconds)
    s.http_timeout = _int_env("WEBVULN_HTTP_TIMEOUT", s.http_timeout)

    s.app_version = _str_env("WEBVULN_APP_VERSION", s.app_version)
    s.agent_mode = _str_env("WEBVULN_AGENT_MODE", s.agent_mode).lower()

    s.llm_rounds_per_target = _int_env("WEBVULN_LLM_ROUNDS", s.llm_rounds_per_target)
    s.scan_timeout_seconds = _int_env("WEBVULN_SCAN_TIMEOUT", s.scan_timeout_seconds)
    s.max_attack_requests_per_target = _int_env(
        "WEBVULN_MAX_ATTACK_REQUESTS", s.max_attack_requests_per_target
    )
    s.max_concurrency = _int_env("WEBVULN_MAX_CONCURRENCY", s.max_concurrency)
    return s
