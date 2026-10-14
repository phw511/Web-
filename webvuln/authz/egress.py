"""EgressGateway：平台唯一网络出口（计划书修订要点 1）。

所有出站 HTTP 必须经此类：未注册目标、授权过期、超范围路径、
内网/保留地址（SSRF 防护）在未发包前即抛 EgressDenied。
检测器与攻击函数只构造 HttpSpec，无 requests/socket 访问权。
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from webvuln.contracts.authz import EgressDenied
from webvuln.contracts.transport import Transport
from webvuln.db.database import Database
from webvuln.models.schemas import HttpSpec, ResponseSnapshot


def _resolve_ip(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise EgressDenied(f"无法解析目标主机: {host}") from e
    return infos[0][4][0]


def is_restricted_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return (
        addr.is_private or addr.is_loopback or addr.is_link_local
        or addr.is_reserved or addr.is_multicast
    )


class EgressGateway:
    def __init__(self, db: Database, transport: Transport):
        self.db = db
        self.transport = transport

    @staticmethod
    def origin_of(url: str) -> str:
        p = urlparse(url)
        if not p.scheme or not p.hostname:
            raise EgressDenied(f"非法 URL: {url}")
        port = f":{p.port}" if p.port else ""
        return f"{p.scheme}://{p.hostname}{port}"

    def check(self, spec: HttpSpec) -> dict:
        """放行前置校验：通过则返回 targets 行；否则抛 EgressDenied（未发包）。"""
        origin = self.origin_of(spec.url)
        row = self.db.one("SELECT * FROM targets WHERE url = ?", (origin,))
        if row is None:
            raise EgressDenied(f"目标未注册: {origin}")
        if row["status"] != "approved":
            raise EgressDenied(f"目标未获批: {origin} (status={row['status']})")
        from webvuln.models.schemas import now_iso  # 局部导入避免循环

        if row["expires_at"] and row["expires_at"] < now_iso():
            raise EgressDenied(f"目标授权已过期: {origin}")

        path = urlparse(spec.url).path or "/"
        import json as _json

        scope = _json.loads(row["scope"])
        if not any(path == s or path.startswith(s.rstrip("/") + "/") or s == "/"
                   for s in scope):
            raise EgressDenied(f"请求路径超出授权范围: {path} not in {scope}")

        ip = _resolve_ip(urlparse(spec.url).hostname)
        if is_restricted_ip(ip) and not row["allow_private"]:
            raise EgressDenied(
                f"SSRF 防护：内网/保留地址被拦截: {ip}"
                "（本地靶场请在注册时声明 allow_private 并经双人审批）"
            )
        return row

    def send(self, spec: HttpSpec) -> ResponseSnapshot:
        self.check(spec)  # 未授权目标零发包
        return self.transport.send(spec)
