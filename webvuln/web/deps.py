"""FastAPI 依赖：容器获取、当前用户解析、角色门禁。"""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from webvuln.container import Container
from webvuln.models.schemas import Role

_bearer = HTTPBearer(auto_error=False)


def get_container(request: Request) -> Container:
    return request.app.state.container


def get_current_user(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> dict:
    if creds is None:
        raise HTTPException(401, "未认证")
    container: Container = request.app.state.container
    try:
        payload = container.tokens.parse(creds.credentials)
    except ValueError as e:
        raise HTTPException(401, str(e))
    return {"username": payload["sub"], "role": payload["role"]}


def require_role(*roles: Role):
    def dep(user: dict = Depends(get_current_user)) -> dict:
        if user["role"] != Role.ADMIN.value and user["role"] not in [r.value for r in roles]:
            raise HTTPException(403, f"需要角色: {', '.join(r.value for r in roles)}")
        return user
    return dep
