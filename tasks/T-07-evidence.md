# T-07 证据层：哈希链 + manifest + 运行身份

- 状态：✅ done
- 归属阶段：M5
- 依赖：T-02
- 关联需求：F9
- 关联测试：`tests/test_hash_chain.py`（2）、`tests/test_evidence_manifest.py`（4）

## 目标

证据不可篡改、可离线核对、可回答"这条证据属于哪次运行、哪个版本、支撑了哪条结论"。

## 交付物

| 文件 | 内容 |
|---|---|
| `contracts/evidence.py` | `EvidenceStore`（含 `manifest()`） |
| `evidence/store.py` | JSONL append-only + SHA-256 链 + `verify`/`verify_scan`/`manifest` |
| `models/schemas.py` | `EvidenceRecord.app_version` |

## 验收标准

| # | 判据 | 用例 |
|---|---|---|
| 1 | 追加后 `verify()` 为真 | `test_chain_append_and_verify` |
| 2 | 改一条正文 → `verify()` 为假 | `test_tamper_detected` |
| 3 | 每条记录带 `app_version` 且 manifest 顶层一致 | `test_records_carry_app_version` |
| 4 | 同链可区分不同版本记录 | `test_records_distinguish_versions` |
| 5 | manifest 逐条索引，含 `conclusion_ids`，长度 64 的 hash | `test_manifest_links_records_to_conclusions` |
| 6 | 篡改后 manifest 的 `verified` 为假 | `test_manifest_tampered_flagged` |

```powershell
python -m pytest tests/test_hash_chain.py tests/test_evidence_manifest.py -q     # 6 passed
```

## 未做/遗留

- 原文未加密（M5 增强项）；
- 签署密钥签名未做（`signature` 恒 `null`）；
- 全局单文件链：多进程并发追加需外部串行化；
- `verify_scan` 为 O(n)，大链时慢。
