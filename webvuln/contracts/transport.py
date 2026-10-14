"""传输层契约：EgressGateway 依赖此抽象，测试可注入 FakeTransport。

这是平台"授权层为唯一网络出口"设计的落点：requests 只允许出现在
本契约的实现类中，检测器/攻击函数/Agent 均无网络原语访问权。
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from webvuln.models.schemas import HttpSpec, ResponseSnapshot


class TransportError(Exception):
    pass


class Transport(ABC):
    @abstractmethod
    def send(self, spec: HttpSpec) -> ResponseSnapshot:
        """发送请求并返回快照。实现不得自行做授权判断。"""
