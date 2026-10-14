from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from webvuln.container import Container
from webvuln.contracts.authz import AuthorizationError
from webvuln.models.schemas import Role
from webvuln.web.deps import get_container, get_current_user, require_role

router = APIRouter(prefix="/api/conclusions", tags=["conclusions"])


class SignIn(BaseModel):
    note: str


@router.get("")
def list_conclusions(scan_id: str | None = None,
                     user: dict = Depends(get_current_user),
                     c: Container = Depends(get_container)):
    if scan_id:
        return c.db.query(
            "SELECT con.*, c.vuln_type, c.parameter, c.scan_id FROM conclusions con"
            " JOIN candidates c ON c.id = con.candidate_id WHERE c.scan_id=?"
            " ORDER BY con.created_at", (scan_id,))
    return c.db.query(
        "SELECT con.*, c.vuln_type, c.parameter, c.scan_id FROM conclusions con"
        " JOIN candidates c ON c.id = con.candidate_id ORDER BY con.created_at DESC")


@router.post("/{conclusion_id}/sign")
def sign(conclusion_id: str, body: SignIn,
         user: dict = Depends(require_role(Role.SIGNER)),
         c: Container = Depends(get_container)):
    try:
        c.pipeline.sign_conclusion(user["username"], conclusion_id, body.note)
    except (AuthorizationError, ValueError) as e:
        raise HTTPException(400, str(e))
    return {"signed": conclusion_id, "by": user["username"]}
