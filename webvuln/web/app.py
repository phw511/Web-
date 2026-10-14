"""FastAPI 应用入口：uvicorn webvuln.web.app:app 即可启动。"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from webvuln.config import Settings, load_settings
from webvuln.container import Container
from webvuln.web.routers import approvals, auth, conclusions, evidence, reports, scans, targets


def create_app(settings: Settings | None = None,
               container: Container | None = None) -> FastAPI:
    s = settings or load_settings()
    c = container or Container(s)
    app = FastAPI(title="WebVuln 平台", version="0.1.0")
    app.add_middleware(
        CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
    )
    app.state.container = c
    for r in (auth.router, targets.router, scans.router, approvals.router,
              conclusions.router, evidence.router, reports.router):
        app.include_router(r)

    @app.get("/api/health")
    def health():
        return {"status": "ok", "evidence": c.evidence.manifest()}
    return app


app = create_app()
