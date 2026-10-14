from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from webvuln.container import Container
from webvuln.contracts.authz import AuthorizationError
from webvuln.models.schemas import Role
from webvuln.web.deps import get_container, get_current_user, require_role

router = APIRouter(prefix="/api/scans", tags=["scans"])


class ScanIn(BaseModel):
    target_id: str


@router.post("", status_code=201)
def run_scan(body: ScanIn,
             user: dict = Depends(require_role(Role.SUBMITTER)),
             c: Container = Depends(get_container)):
    try:
        return c.pipeline.run_scan(body.target_id, user["username"])
    except AuthorizationError as e:
        raise HTTPException(400, str(e))


@router.get("")
def list_scans(user: dict = Depends(get_current_user),
               c: Container = Depends(get_container)):
    return c.db.query("SELECT * FROM scans ORDER BY started_at DESC")


@router.get("/{scan_id}")
def get_scan(scan_id: str,
             user: dict = Depends(get_current_user),
             c: Container = Depends(get_container)):
    summary = c.reporter.summary(scan_id)
    replay = c.pipeline.replay(scan_id)
    return {"summary": summary, "evidence": replay}
