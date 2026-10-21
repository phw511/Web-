from webvuln.evidence.store import FileEvidenceStore


def test_chain_append_and_verify(container):
    s: FileEvidenceStore = container.evidence
    s.append("scan-1", "scan_start", {"a": 1})
    s.append("scan-1", "decision", {"b": 2})
    assert s.verify() is True
    assert s.verify_scan("scan-1") is True


def test_tamper_detected(container):
    s: FileEvidenceStore = container.evidence
    s.append("scan-1", "scan_start", {"a": 1})
    with open(s.chain_path, "r+", encoding="utf-8") as f:
        content = f.read().replace('"a":1', '"a":999')
        f.seek(0)
        f.write(content)
    assert s.verify() is False
