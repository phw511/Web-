"""授权控制层实现：目标注册双人审批、分级放行、审批证据留痕。"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Optional

from webvuln.contracts.authz import AuthorizationError, Authorizer
from webvuln.authz import egress as egress_mod
from webvuln.authz.egress import EgressGateway, is_restricted_ip
from webvuln.db.database import Database
from webvuln.models.schemas import (
    ApprovalKind, ApprovalRecord, TargetRegistration, TargetStatus, now_iso, uid,
)

APPROVAL_VALIDITY_DAYS = 30


def _row_to_target(row: dict) -> TargetRegistration:
    return TargetRegistration(
        id=row["id"], url=row["url"],
        scope_paths=json.loads(row["scope"]),
        base_params=json.loads(row["base_params"]),
        justification=row["justification"], status=row["status"],
        submitted_by=row["submitted_by"], submitted_at=row["submitted_at"],
        approved_by=row["approved_by"], approved_at=row["approved_at"],
        expires_at=row["expires_at"], allow_private=bool(row["allow_private"]),
    )


class AuthorizerService(Authorizer):
    def __init__(self, db: Database):
        self.db = db

    # ---- 目标注册与双人审批（计划书 4.3） ----
    def submit_target(
        self, username: str, url: str, scope_paths: list[str],
        base_params: dict, justification: str, allow_private: bool = False,
    ) -> TargetRegistration:
        origin = EgressGateway.origin_of(url)
        if self.db.one("SELECT id FROM targets WHERE url = ?", (origin,)):
            raise AuthorizationError(f"目标已存在: {origin}")
        reg = TargetRegistration(
            id=uid("tgt"), url=origin, scope_paths=scope_paths or ["/"],
            base_params=base_params, justification=justification,
            submitted_by=username, submitted_at=now_iso(),
            allow_private=allow_private,
        )
        self.db.execute(
            "INSERT INTO targets(id,url,scope,base_params,justification,status,"
            "submitted_by,submitted_at,allow_private) VALUES(?,?,?,?,?,?,?,?,?)",
            (reg.id, reg.url, json.dumps(reg.scope_paths),
             json.dumps(reg.base_params), justification, reg.status.value,
             username, reg.submitted_at, int(allow_private)),
        )
        return reg

    def _get_row(self, target_id: str) -> dict:
        row = self.db.one("SELECT * FROM targets WHERE id = ?", (target_id,))
        if row is None:
            raise AuthorizationError(f"目标不存在: {target_id}")
        return row

    def approve_target(
        self, actor: str, target_id: str, reason: str, allow_private: bool = False
    ) -> ApprovalRecord:
        row = self._get_row(target_id)
        if row["submitted_by"] == actor:
            raise AuthorizationError("提交人与审批人不得为同一人（双人审批，计划书 4.3）")
        host = row["url"].split("://", 1)[1].split(":")[0].split("/")[0]
        ip = egress_mod._resolve_ip(host)
        private = is_restricted_ip(ip)
        if private and not (allow_private and row["allow_private"]):
            raise AuthorizationError(
                "目标为内网/保留地址，须提交时声明 allow_private 且审批时显式放行"
            )
        expires = (datetime.now(timezone.utc) + timedelta(days=APPROVAL_VALIDITY_DAYS)).isoformat()
        self.db.execute(
            "UPDATE targets SET status=?, approved_by=?, approved_at=?, expires_at=?,"
            " allow_private=? WHERE id=?",
            (TargetStatus.APPROVED.value, actor, now_iso(), expires,
             int(bool(allow_private and private)) if private else int(row["allow_private"]),
             target_id),
        )
        return self._record(ApprovalKind.TARGET, target_id, "approve", actor, reason)

    def reject_target(self, actor: str, target_id: str, reason: str) -> ApprovalRecord:
        row = self._get_row(target_id)
        if row["submitted_by"] == actor:
            raise AuthorizationError("提交人与审批人不得为同一人")
        self.db.execute(
            "UPDATE targets SET status=?, approved_by=?, approved_at=? WHERE id=?",
            (TargetStatus.REJECTED.value, actor, now_iso(), target_id),
        )
        return self._record(ApprovalKind.TARGET, target_id, "reject", actor, reason)

    def get_target(self, target_id: str) -> Optional[TargetRegistration]:
        row = self.db.one("SELECT * FROM targets WHERE id = ?", (target_id,))
        return _row_to_target(row) if row else None

    def list_targets(self, status: Optional[TargetStatus] = None) -> list[TargetRegistration]:
        if status:
            rows = self.db.query("SELECT * FROM targets WHERE status=? ORDER BY submitted_at DESC", (status.value,))
        else:
            rows = self.db.query("SELECT * FROM targets ORDER BY submitted_at DESC")
        return [_row_to_target(r) for r in rows]

    # ---- 攻击审批（分级放行的证据留痕，计划书 4.1） ----
    def _record(self, kind: ApprovalKind, ref_id: str, action: str,
                actor: str, reason: str) -> ApprovalRecord:
        rec = ApprovalRecord(
            id=uid("apv"), kind=kind, ref_id=ref_id, action=action,
            actor=actor, reason=reason, created_at=now_iso(),
        )
        self.db.execute(
            "INSERT INTO approvals(id,kind,ref_id,action,actor,reason,created_at)"
            " VALUES(?,?,?,?,?,?,?)",
            (rec.id, rec.kind.value, rec.ref_id, rec.action, rec.actor,
             rec.reason, rec.created_at),
        )
        return rec

    def record_attack_approval(
        self, actor: str, decision_id: str, action: str, reason: str
    ) -> ApprovalRecord:
        if not reason.strip():
            raise AuthorizationError("审批必须填写理由（谁、何时、为什么放行）")
        return self._record(ApprovalKind.ATTACK, decision_id, action, actor, reason)

    def attack_approved(self, decision_id: str) -> bool:
        row = self.db.one(
            "SELECT 1 FROM approvals WHERE kind='attack' AND ref_id=? AND action='approve'",
            (decision_id,),
        )
        return row is not None
