"""模拟传输层（离线，不触网）：按请求参数返回预置响应。

用途：模拟一个同时存在 SQL 注入与反射型 XSS 的靶标，用于"模拟演示"。
它不是真实网络接入，不打开任何 socket；EgressGateway 的授权校验照常生效，
仅最底层 Transport 被替换为预置响应（与测试注入 FakeTransport 同思路）。
"""
from __future__ import annotations

from webvuln.contracts.transport import Transport
from webvuln.models.schemas import HttpSpec, ResponseSnapshot

# 与检测器/攻击函数共用同一金丝雀常量，保证模拟信号口径一致
XSS_PROBE = "wvxss7k<svg>"


class MockTransport(Transport):
    """根据参数值子串返回 canned 响应，模拟靶标行为。"""

    def send(self, spec: HttpSpec) -> ResponseSnapshot:
        joined = " ".join(spec.params.values())

        if XSS_PROBE in joined:
            # 反射型 XSS：金丝雀原样（尖括号未转义）反射
            body = f"<div>Your input was echoed: {XSS_PROBE}</div>"
            status = 200
        elif "' AND '1'='2" in joined:
            # SQLi 恒假条件：极短响应（与恒真形成长度差 >20% 信号）
            body, status = "", 200
        elif "' AND '1'='1" in joined:
            # SQLi 恒真条件：长响应
            body, status = "A" * 600, 200
        elif "'" in joined:
            # SQLi 单引号：数据库报错特征（命中 ERROR_KEYWORDS）
            body, status = "Query failed: mysql syntax error near '' at line 1", 500
        else:
            # 基线：正常页面
            body, status = "Simulated target index page. Hello world!", 200

        return ResponseSnapshot(
            status_code=status, headers={}, body=body, elapsed_ms=5,
        )
