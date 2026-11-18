"""依赖组装根：唯一允许 import 各具体实现并接线的地方。

Web 层与 CLI 只依赖本容器与 contracts，实现高内聚低耦合：
替换任一模块实现（如 LLM Agent、真实 Transport）只需改本文件。

v0.2.0 接线：
- `BudgetGuard`（四项上限，计划书 9 章）注入到 pipeline / gateway / executor 三处强制点；
- `app_version` 注入证据层（运行身份，计划书 5.2）；
- 可选 `llm_provider`：`Settings.agent_mode == "llm"` 时启用 LLMAgent，否则规则 Agent 保底。
"""
from __future__ import annotations

from typing import Optional

from webvuln.agent.llm_agent import DecisionLLM, LLMAgent
from webvuln.agent.rule_agent import RuleAgent
from webvuln.attacker.attacks import *  # noqa: F401,F403  确保攻击函数白名单注册
from webvuln.attacker.executor import AttackExecutor
from webvuln.authz.egress import EgressGateway
from webvuln.authz.service import AuthorizerService
from webvuln.budget import BudgetGuard
from webvuln.config import Settings
from webvuln.contracts.agent import DecisionAgent
from webvuln.contracts.attack import default_registry
from webvuln.contracts.transport import Transport
from webvuln.db.database import Database
from webvuln.detector.engine import DetectorEngine
from webvuln.detector.lfi import LFIDetector
from webvuln.detector.sqli import SQLiDetector
from webvuln.detector.xss import XSSDetector
from webvuln.evidence.store import FileEvidenceStore
from webvuln.pipeline import Pipeline
from webvuln.report.reporter import ReporterService
from webvuln.web.security import TokenService, UserService


class RequestsTransport(Transport):
    """唯一允许使用 requests 的位置（唯一网络出口的内部实现）。"""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def send(self, spec):
        import requests

        resp = requests.request(
            spec.method, spec.url, headers=spec.headers,
            params=spec.params, data=spec.data, timeout=self.timeout,
        )
        from webvuln.models.schemas import ResponseSnapshot

        return ResponseSnapshot(
            status_code=resp.status_code,
            headers={k: v for k, v in resp.headers.items()},
            body=resp.text[:20000],
            elapsed_ms=int(resp.elapsed.total_seconds() * 1000),
        )


class Container:
    def __init__(self, settings: Settings, llm_provider: Optional[DecisionLLM] = None):
        self.settings = settings
        self.db = Database(settings.db_path)
        self.evidence = FileEvidenceStore(
            settings.evidence_dir, self.db, app_version=settings.app_version,
        )
        self.transport = RequestsTransport(timeout=settings.http_timeout)
        self.budget = BudgetGuard(settings)
        self.gateway = EgressGateway(self.db, self.transport, self.budget)
        self.authorizer = AuthorizerService(self.db)
        self.registry = default_registry()
        self.engine = DetectorEngine(self.gateway, [SQLiDetector(), XSSDetector(), LFIDetector()])
        self.agent = self._build_agent(settings, llm_provider)
        self.executor = AttackExecutor(self.registry, self.gateway, self.evidence, self.budget)
        self.reporter = ReporterService(self.db)
        self.pipeline = Pipeline(
            self.db, self.authorizer, self.engine, self.agent,
            self.executor, self.evidence, self.registry, self.budget,
        )
        self.users = UserService(self.db)
        self.tokens = TokenService(settings.jwt_secret, settings.jwt_ttl_seconds)

    @staticmethod
    def _build_agent(settings: Settings, llm_provider: Optional[DecisionLLM]) -> DecisionAgent:
        """Agent 选择集中在一处：LLM 不可用时规则 Agent 保证主线可用（计划书 6.2）。"""
        if settings.agent_mode == "llm":
            if llm_provider is None:
                raise ValueError(
                    "agent_mode=llm 但未注入 DecisionLLM 实现："
                    "请在 create_app/Container 处传入（规则 Agent 仍可作 fallback）"
                )
            return LLMAgent(llm_provider)
        return RuleAgent()
