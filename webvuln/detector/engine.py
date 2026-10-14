"""检测引擎：按类型调度检测器，产出候选。不感知 Agent 与攻击。"""
from __future__ import annotations

from webvuln.contracts.detector import BaseDetector
from webvuln.authz.egress import EgressGateway
from webvuln.models.schemas import FindingCandidate, HttpSpec, TargetRegistration


class DetectorEngine:
    def __init__(self, gateway: EgressGateway, detectors: list[BaseDetector]):
        self.gateway = gateway
        self.detectors = detectors

    def run(self, target: TargetRegistration, scan_id: str) -> list[FindingCandidate]:
        base = HttpSpec(url=target.url, params=dict(target.base_params))
        out: list[FindingCandidate] = []
        for detector in self.detectors:
            out.extend(detector.detect(self.gateway, target, base, scan_id))
        return out
