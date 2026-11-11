"""检测器判定逻辑自测（章节03第 11--12 页：判定办法也要能抓住已知错误）。

与 test_state_machine 的端到端测试分工：这里只回答"给定已知响应，
检测器判定对不对"；端到端测试回答"真实调用链下输出什么"。
两类检查互相不可替代，共同底线是不修改样例标准来凑通过。
"""
from webvuln.detector.lfi import LFIDetector
from webvuln.detector.sqli import SQLiDetector
from webvuln.detector.xss import XSSDetector
from webvuln.models.schemas import (
    HttpSpec, ResponseSnapshot, TargetRegistration, VulnType, now_iso,
)

SQLI_ERROR_BODY = "You have an error in your SQL syntax; check the manual"
NORMAL_BODY = "Welcome. Items: book, pen, cup, desk."


def _target() -> TargetRegistration:
    return TargetRegistration(id="t1", url="http://t.example.com",
                              submitted_by="sub1", submitted_at=now_iso())


def _base() -> HttpSpec:
    return HttpSpec(url="http://t.example.com", params={"q": "book"})


class _Gateway:
    """按规则返回 canned 响应的桩网关：只服务判定自测，不触网。"""

    def __init__(self, fn):
        self.fn = fn

    def send(self, spec) -> ResponseSnapshot:
        return self.fn(spec)


# ---- SQLi：已知漏洞必须命中，已知安全必须不命中 ----

def test_sqli_known_vulnerable_hit():
    def fn(spec):
        q = spec.params.get("q", "")
        if q.endswith("'"):
            return ResponseSnapshot(status_code=500, body=SQLI_ERROR_BODY)
        if "'1'='2" in q:
            return ResponseSnapshot(status_code=200, body="Empty.")
        return ResponseSnapshot(status_code=200, body=NORMAL_BODY)

    cands = SQLiDetector().detect(_Gateway(fn), _target(), _base(), "s1")
    assert len(cands) == 1
    assert cands[0].vuln_type == VulnType.SQLI
    assert "错误型信号" in cands[0].claim      # 判定依据写进 claim，可核查


def test_sqli_known_safe_no_false_positive():
    def fn(spec):
        return ResponseSnapshot(status_code=200, body=NORMAL_BODY)

    assert SQLiDetector().detect(_Gateway(fn), _target(), _base(), "s1") == []


def test_sqli_error_only_without_boolean_still_hit():
    # 仅错误型信号、无长度差也应命中（已知错误的另一形态）
    def fn(spec):
        q = spec.params.get("q", "")
        if q.endswith("'"):
            return ResponseSnapshot(status_code=500, body=SQLI_ERROR_BODY)
        return ResponseSnapshot(status_code=200, body=NORMAL_BODY)

    cands = SQLiDetector().detect(_Gateway(fn), _target(), _base(), "s1")
    assert len(cands) == 1 and "错误型信号" in cands[0].claim


# ---- XSS：未转义反射命中，转义形态不报 ----

def test_xss_unescaped_reflection_hit():
    def fn(spec):
        return ResponseSnapshot(status_code=200,
                                body=f"Echo: {spec.params['q']} rendered.")

    cands = XSSDetector().detect(_Gateway(fn), _target(), _base(), "s1")
    assert len(cands) == 1 and cands[0].vuln_type == VulnType.XSS


def test_xss_escaped_reflection_no_hit():
    # 已知安全输出：金丝雀被转义为 &lt; &gt;，不得报候选
    def fn(spec):
        return ResponseSnapshot(status_code=200, body="Echo: wvxss7k&lt;svg&gt;")

    assert XSSDetector().detect(_Gateway(fn), _target(), _base(), "s1") == []


# ---- LFI：路径穿越读到口令特征命中，正常响应不报 ----

def test_lfi_known_vulnerable_hit():
    def fn(spec):
        if "etc/passwd" in spec.params.get("q", ""):
            return ResponseSnapshot(
                status_code=200,
                body="root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33::/var/www:/usr/sbin/nologin")
        return ResponseSnapshot(status_code=200, body=NORMAL_BODY)

    cands = LFIDetector().detect(_Gateway(fn), _target(), _base(), "s1")
    assert len(cands) == 1 and cands[0].vuln_type == VulnType.LFI


def test_lfi_known_safe_no_hit():
    def fn(spec):
        return ResponseSnapshot(status_code=200, body=NORMAL_BODY)

    assert LFIDetector().detect(_Gateway(fn), _target(), _base(), "s1") == []
