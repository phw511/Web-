from fastapi import APIRouter, Depends

from webvuln.container import Container
from webvuln.web.deps import get_container, get_current_user

router = APIRouter(prefix="/api/evidence", tags=["evidence"])


@router.get("/{scan_id}/chain")
def chain(scan_id: str, user: dict = Depends(get_current_user),
          c: Container = Depends(get_container)):
    return c.pipeline.replay(scan_id)


@router.get("/verify")
def verify(user: dict = Depends(get_current_user), c: Container = Depends(get_container)):
    return c.evidence.manifest()
