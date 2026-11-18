"""FastAPI 应用入口：uvicorn webvuln.web.app:app 即可启动。"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from webvuln import __version__
from webvuln.config import Settings, load_settings
from webvuln.container import Container
from webvuln.web.routers import approvals, auth, conclusions, evidence, reports, scans, targets


def create_app(settings: Settings | None = None,
               container: Container | None = None) -> FastAPI:
    s = settings or load_settings()
    c = container or Container(s)
    app = FastAPI(title="WebVuln 平台", version=s.app_version or __version__)
    app.add_middleware(
        CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
    )
    app.state.container = c
    for r in (auth.router, targets.router, scans.router, approvals.router,
              conclusions.router, evidence.router, reports.router):
        app.include_router(r)

    @app.get("/api/health")
    def health():
        return {
            "status": "ok",
            "app_version": s.app_version,
            "agent_mode": s.agent_mode,
            "evidence": c.evidence.manifest(),
            "budget_limits": {
                "llm_rounds_per_target": s.llm_rounds_per_target,
                "scan_timeout_seconds": s.scan_timeout_seconds,
                "max_attack_requests_per_target": s.max_attack_requests_per_target,
                "max_concurrency": s.max_concurrency,
            },
        }
    return app


app = create_app()
