"""跨层共享的数据模型（pydantic）。

设计约定：所有模块间传递的域对象必须来自本模块，层与层之间
不互相 import 实现，只依赖 contracts 中的抽象与本模块的模型。
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


def uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Role(str, Enum):
    ADMIN = "admin"
    SUBMITTER = "submitter"
    APPROVER = "approver"
    SIGNER = "signer"


class VulnType(str, Enum):
    SQLI = "sqli"
    LFI = "lfi"
    IDOR = "idor"
    CONFIG = "config"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class EvidenceLevel(str, Enum):
    CLAIM = "ClaimOnly"
    STATIC = "Static"
    OBSERVED = "Observed"
    REPRODUCED = "Reproduced"


class CandidateState(str, Enum):
    CANDIDATE = "CANDIDATE"
    ATTACKED = "ATTACKED"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class TargetStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class ApprovalKind(str, Enum):
    TARGET = "target"
    ATTACK = "attack"


class HttpSpec(BaseModel):
    """一次出站 HTTP 请求的描述。检测/攻击模块只构造 HttpSpec，
    实际发送只能经授权层 EgressGateway（唯一网络出口）。"""

    method: str = "GET"
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    params: dict[str, str] = Field(default_factory=dict)
    data: Optional[str] = None


class ResponseSnapshot(BaseModel):
    status_code: int
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    elapsed_ms: int = 0


class TargetRegistration(BaseModel):
    id: str
    url: str                                   # 规范化为 origin，如 http://host:port
    scope_paths: list[str] = Field(default_factory=lambda: ["/"])
    base_params: dict[str, str] = Field(default_factory=dict)
    justification: str = ""
    submitted_by: str
    submitted_at: str
    status: TargetStatus = TargetStatus.PENDING
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    expires_at: Optional[str] = None
    allow_private: bool = False                # SSRF 防护例外：本地靶场需走高危审批


class FindingCandidate(BaseModel):
    id: str
    scan_id: str
    target_id: str
    vuln_type: VulnType
    endpoint: str
    parameter: str
    claim: str                                 # 检测器自述证据（ClaimOnly 级）
    detector: str
    created_at: str


class AttackFunctionMeta(BaseModel):
    name: str
    vuln_type: VulnType
    risk_level: RiskLevel
    reversible: bool
    side_effects: str                          # 副作用声明（供授权层与运行期校验）
    expected_signal: str                       # 判定规则：命中即 CONFIRMED


class AttackDecision(BaseModel):
    id: str
    candidate_id: str
    function_name: str
    reason: str
    expected_result: str
    decision_source: str = "rule"              # rule / llm（M3b 接入真实 LLM 后区分）


class ApprovalRecord(BaseModel):
    id: str
    kind: ApprovalKind
    ref_id: str                                # target id 或 decision id
    action: str                                # approve / reject
    actor: str
    reason: str
    created_at: str


class AttackResult(BaseModel):
    decision_id: str
    request: HttpSpec
    response_status: int
    response_excerpt: str
    matched: bool
    executed_at: str


class EvidenceRecord(BaseModel):
    id: str
    scan_id: str
    kind: str          # scan_start/decision/approval/attack_request/attack_response/state_change/sign
    payload: dict[str, Any]
    prev_hash: str
    hash: str = ""
    created_at: str


class Conclusion(BaseModel):
    id: str
    candidate_id: str
    state: CandidateState
    evidence_level: EvidenceLevel
    decided_by: str                            # agent:rule / human-reject
    signature_note: str = ""
    signed_by: Optional[str] = None
    signed_at: Optional[str] = None
    created_at: str


class UserAccount(BaseModel):
    username: str
    role: Role
