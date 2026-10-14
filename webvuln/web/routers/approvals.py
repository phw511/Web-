from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from webvuln.container import Container
from webvuln.contracts.authz import AuthorizationError
from webvuln.models.schemas import RiskLevel, Role
from webvuln.web.deps import get_container, get_current_user

router = APIRouter(prefix="/api/approvals", tags=["approvals"])


class DecisionIn(BaseModel):
    decision_id: str
    action: str          # approve / reject
    reason: str


@router.get("/pending")
def pending(user: dict = Depends(get_current_user),
            c: Container = Depends(get_container)):
    """中高危且未审批、未执行的决策单。"""
    rows = c.db.query(
        "SELECT d.id AS decision_id, d.risk_level, d.function_name, d.reason,"
        "       c.id AS candidate_id, c.vuln_type, c.parameter, c.claim,"
        "       s.id AS scan_id, t.url AS target_url"
        " FROM decisions d"
        " JOIN candidates c ON c.id = d.candidate_id"
        " JOIN scans s ON s.id = c.scan_id"
        " JOIN targets t ON t.id = c.target_id"
        " WHERE d.risk_level != ?"
        "   AND NOT EXISTS (SELECT 1 FROM approvals a WHERE a.kind='attack'"
        "                   AND a.ref_id = d.id)"
        "   AND NOT EXISTS (SELECT 1 FROM attack_runs r WHERE r.decision_id = d.id)",
        (RiskLevel.LOW.value,),
    )
    return rows


@router.post("")
def decide(body: DecisionIn,
           user: dict = Depends(get_current_user),
           c: Container = Depends(get_container)):
    row = c.db.one("SELECT risk_level FROM decisions WHERE id=?",
                   (body.decision_id,))
    if row is None:
        raise HTTPException(404, "决策不存在")
    # 分级放行：中危需 approver，高危需 signer；reject 同样受角色约束
    needed = Role.APPROVER if row["risk_level"] == RiskLevel.MEDIUM.value else Role.SIGNER
    if user["role"] not in (Role.ADMIN.value, needed.value):
        raise HTTPException(403, f"{row['risk_level']} 风险需 {needed.value} 角色审批")
    if body.action not in ("approve", "reject"):
        raise HTTPException(400, "action 必须为 approve/reject")
    try:
        con = c.pipeline.execute_approved(user["username"], body.decision_id,
                                          body.action, body.reason)
    except (AuthorizationError, ValueError) as e:
        raise HTTPException(400, str(e))
    return con.model_dump()
