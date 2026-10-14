"""账号与令牌：PBKDF2 密码散列 + HS256 JWT（纯标准库实现，零额外依赖）。"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time

from webvuln.db.database import Database
from webvuln.models.schemas import Role, now_iso


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def hash_password(password: str, salt: bytes | None = None,
                  iterations: int = 200_000) -> str:
    salt = salt or os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2${iterations}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iters, salt_hex, hash_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), int(iters)
        )
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, AttributeError):
        return False


class TokenService:
    def __init__(self, secret: str, ttl_seconds: int = 8 * 3600):
        self.secret = secret.encode()
        self.ttl = ttl_seconds

    def issue(self, username: str, role: str) -> str:
        header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        payload = _b64url(json.dumps({
            "sub": username, "role": role,
            "iat": int(time.time()), "exp": int(time.time()) + self.ttl,
        }).encode())
        sig = _b64url(hmac.new(self.secret, f"{header}.{payload}".encode(),
                               hashlib.sha256).digest())
        return f"{header}.{payload}.{sig}"

    def parse(self, token: str) -> dict:
        try:
            header, payload, sig = token.split(".")
        except ValueError as e:
            raise ValueError("令牌格式非法") from e
        expected = _b64url(hmac.new(self.secret, f"{header}.{payload}".encode(),
                                    hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            raise ValueError("令牌签名无效")
        data = json.loads(_b64url_decode(payload))
        if data.get("exp", 0) < time.time():
            raise ValueError("令牌已过期")
        return data


class UserService:
    def __init__(self, db: Database):
        self.db = db

    def create(self, username: str, password: str, role: Role) -> None:
        if not username or len(password) < 6:
            raise ValueError("用户名非空且密码至少 6 位")
        if self.db.one("SELECT 1 FROM users WHERE username=?", (username,)):
            raise ValueError(f"用户已存在: {username}")
        self.db.execute(
            "INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
            (username, hash_password(password), role.value, now_iso()),
        )

    def verify(self, username: str, password: str) -> dict | None:
        row = self.db.one("SELECT * FROM users WHERE username=?", (username,))
        if row and verify_password(password, row["password_hash"]):
            return {"username": row["username"], "role": row["role"]}
        return None
