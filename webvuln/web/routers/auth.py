from fastapi import APIRouter, Depends, HTTPException

from webvuln.container import Container
from webvuln.models.schemas import Role
from webvuln.web.deps import get_container, require_role
from pydantic import BaseModel

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginIn(BaseModel):
    username: str
    password: str


class UserIn(BaseModel):
    username: str
    password: str
    role: Role


@router.post("/login")
def login(body: LoginIn, c: Container = Depends(get_container)):
    user = c.users.verify(body.username, body.password)
    if user is None:
        raise HTTPException(401, "用户名或密码错误")
    token = c.tokens.issue(user["username"], user["role"])
    return {"token": token, "username": user["username"], "role": user["role"]}


@router.post("/users", status_code=201)
def create_user(body: UserIn,
                admin: dict = Depends(require_role(Role.ADMIN)),
                c: Container = Depends(get_container)):
    try:
        c.users.create(body.username, body.password, body.role)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"created": body.username}
