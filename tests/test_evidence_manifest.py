"""证据运行身份（app_version）与 manifest 机器可读索引（计划书第 10 章）。

章节03 Observability 最小判断之"能关联"：知道记录属于哪一次运行、
哪个版本。manifest 是评价 Agent 的审查入口。
"""


def test_records_carry_app_version(container):
    container.evidence.append("scan-1", "scan_start", {"a": 1})
    rec = container.evidence.for_scan("scan-1")[0]
    assert rec.app_version == "0.2.0"   # 与 Settings.app_version 默认一致
    m = container.evidence.manifest()
    assert m["app_version"] == "0.2.0"
    entry = m["records"][0]
    assert entry["kind"] == "scan_start"
    assert entry["hash"] == rec.hash
    assert entry["signature"] is None   # 预留位：签署密钥签名为增强项（5.2）


def test_records_distinguish_versions(container):
    # 同一证据链中，不同版本写入的记录可按 app_version 区分归属
    store = container.evidence
    store.append("scan-1", "scan_start", {})
    store.app_version = "9.9.9"
    store.append("scan-2", "scan_start", {})
    versions = {r.app_version for r in store._iter_records()}
    assert versions == {"0.2.0", "9.9.9"}


def test_manifest_links_records_to_conclusions(container, approved_target):
    result = container.pipeline.run_scan(approved_target.id, "sub1")
    m = container.evidence.manifest()
    assert m["verified"] is True
    assert m["record_count"] == len(m["records"]) >= 4
    linked = set()
    for e in m["records"]:
        assert e["scan_id"] == result["scan_id"]
        assert len(e["hash"]) == 64            # SHA-256
        linked.update(e["conclusion_ids"])
    row = container.db.one("SELECT id FROM conclusions LIMIT 1")
    assert row is not None and row["id"] in linked


def test_manifest_tamper_flagged(container):
    container.evidence.append("scan-1", "scan_start", {"a": 1})
    with open(container.evidence.chain_path, "r+", encoding="utf-8") as f:
        f.write(f.read().replace('"a":1', '"a":999'))
    m = container.evidence.manifest()
    assert m["verified"] is False
