from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from webvuln.container import Container
from webvuln.contracts.authz import ApprovalForbidden, AuthorizationError
from webvuln.models.schemas import RiskLevel
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
    if body.action not in ("approve", "reject"):
        raise HTTPException(400, "action 必须为 approve/reject")
    # 分级放行的判定规则只在授权层（authz.service）一份，路由只透传角色并映射异常：
    # 角色不足 → 403；其他授权/业务错误 → 400。此前规则写在本文件里，CLI 可绕过。
    try:
        con = c.pipeline.execute_approved(
            user["username"], body.decision_id, body.action, body.reason,
            actor_role=user["role"],
        )
    except ApprovalForbidden as e:
        raise HTTPException(403, str(e))
    except (AuthorizationError, ValueError) as e:
        raise HTTPException(400, str(e))
    return con.model_dump()
