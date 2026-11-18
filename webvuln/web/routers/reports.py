from fastapi import APIRouter, Depends, Response

from webvuln.container import Container
from webvuln.web.deps import get_container, get_current_user

router = APIRouter(prefix="/api", tags=["reports"])


@router.get("/reports/{scan_id}")
def report(scan_id: str, format: str = "md",
           user: dict = Depends(get_current_user),
           c: Container = Depends(get_container)):
    media = {"json": "application/json", "md": "text/markdown",
             "html": "text/html; charset=utf-8"}
    body = c.reporter.render(scan_id, format)
    return Response(content=body, media_type=media.get(format, "text/plain"))


@router.get("/stats")
def stats(user: dict = Depends(get_current_user), c: Container = Depends(get_container)):
    """全局指标：实现只有 reporter.metrics_global 一份（口径与报告页一致）。"""
    return c.reporter.metrics_global()
