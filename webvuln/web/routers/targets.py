from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from webvuln.container import Container
from webvuln.contracts.authz import AuthorizationError
from webvuln.models.schemas import Role, TargetStatus
from webvuln.web.deps import get_container, get_current_user, require_role

router = APIRouter(prefix="/api/targets", tags=["targets"])


class TargetIn(BaseModel):
    url: str
    scope_paths: list[str] = ["/"]
    base_params: dict[str, str] = {}
    justification: str = ""
    allow_private: bool = False


class ApproveIn(BaseModel):
    reason: str
    allow_private: bool = False


def _target_dict(t):
    return t.model_dump()


@router.get("")
def list_targets(status: TargetStatus | None = None,
                 user: dict = Depends(get_current_user),
                 c: Container = Depends(get_container)):
    return [_target_dict(t) for t in c.authorizer.list_targets(status)]


@router.post("", status_code=201)
def submit_target(body: TargetIn,
                  user: dict = Depends(require_role(Role.SUBMITTER)),
                  c: Container = Depends(get_container)):
    try:
        reg = c.authorizer.submit_target(
            user["username"], body.url, body.scope_paths, body.base_params,
            body.justification, body.allow_private,
        )
    except AuthorizationError as e:
        raise HTTPException(400, str(e))
    return _target_dict(reg)


@router.post("/{target_id}/approve")
def approve_target(target_id: str, body: ApproveIn,
                   user: dict = Depends(require_role(Role.APPROVER)),
                   c: Container = Depends(get_container)):
    try:
        rec = c.authorizer.approve_target(
            user["username"], target_id, body.reason, body.allow_private
        )
    except AuthorizationError as e:
        raise HTTPException(400, str(e))
    return rec.model_dump()


@router.post("/{target_id}/reject")
def reject_target(target_id: str, body: ApproveIn,
                  user: dict = Depends(require_role(Role.APPROVER)),
                  c: Container = Depends(get_container)):
    try:
        rec = c.authorizer.reject_target(user["username"], target_id, body.reason)
    except AuthorizationError as e:
        raise HTTPException(400, str(e))
    return rec.model_dump()
