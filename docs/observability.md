# 观测性约定（docs/conventions/observability.md）

> 课程口径的三问：**在哪记 / 记什么 / 怎么查**。本项目把"证据"作为一等公民，
> 日志只作诊断。本文给出可机器核对的验收标准。

## 1. 三问

| 问题 | 本项目的回答 | 落点 |
|---|---|---|
| 在哪记 | append-only JSONL（真身）+ SQLite 索引（查询） | `evidence/chain.jsonl`、`evidence_index` |
| 记什么 | 11 类 kind，覆盖"谁、何时、为什么、对谁、用什么、结果如何" | `design/spec/data-model.md` §2.3 |
| 怎么查 | manifest 逐条索引 + `scan_id` 关联 + `verify()` 重放 | `GET /api/evidence/verify`、`cli verify-evidence` |

## 2. 最小判断：能不能"关联"

一条记录若不能回答下列任一问题，就是**不可用记录**：

| 问题 | 需要的字段 | 现状 |
|---|---|---|
| 属于哪次运行？ | `scan_id` | ✅ 每条都有 |
| 属于哪个版本？ | `app_version` | ✅ v0.2.0 起每条都有 |
| 是第几步？ | `prev_hash` + 文件顺序 | ✅ 链式 |
| 支撑了哪条结论？ | `conclusion_ids`（payload 里的 `candidate_id` / `conclusion_id` 映射） | ✅ manifest 中给出 |
| 谁做的？ | `actor` / `decided_by` / `signer` | ✅ 审批、决策、签署三处 |

## 3. "不过量"与"不缺失"的边界

| 该记 | 不该记 |
|---|---|
| 请求的方法/URL/参数（可复现所需） | 完整 Cookie / Authorization 头 |
| 响应状态码 + 摘录（≤400 字符入证据，≤20000 字符入 Snapshot） | 响应中的用户隐私字段 |
| 判定依据（matched、expected_signal、命中位置） | 大段 HTML 原文 |
| 预算上限与用量快照 | 密钥、token |

原则：**够复现即可，多一个字段就多一份泄露面**。

## 4. 验收标准（可机器断言）

| # | 判据 | 验证方式 | 现状 |
|---|---|---|---|
| O1 | 每条证据有 `scan_id` 与 `app_version` | `tests/test_evidence_manifest.py::test_records_carry_app_version` | ✅ |
| O2 | manifest 逐条索引且字段齐全 | 同上 `test_manifest_links_records_to_conclusions` | ✅ |
| O3 | 篡改任意一条能被发现 | `test_manifest_tampered_flagged`、`test_hash_chain.py::test_tamper_detected` | ✅ |
| O4 | 子链前驱可达（防孤链伪造） | `verify_scan` + `test_state_machine.py` | ✅ |
| O5 | 报告与 API 指标口径一致 | `metrics_global` 唯一实现 | ✅ |
| O6 | 敏感原文不入证据 | 代码审查 + `logging.md` 红线 | ⚠️ 靠约定，未自动化 |
| O7 | 加密存储 | —— | ❌ 未做（M5 增强项） |

## 5. 审查入口（给评价方）

```powershell
# 1) 全量索引（人类可读）
.\.venv\Scripts\python.exe -m webvuln.cli verify-evidence

# 2) 机器可读（HTTP）
GET /api/evidence/verify        # 同一份 manifest

# 3) 独立重放（不依赖本平台代码）
#    读 chain.jsonl，逐行重算 SHA-256(prev_hash + "|" + 规范化JSON)，比对 hash 字段
```

manifest 结构见 `design/spec/contracts.md` §3.4。`signature` 恒为 `null`——**不假装已签名**。

## 6. 已知缺口（如实登记）

1. 证据原文未加密（M5）；
2. `verify_scan` 每次全量读文件，O(n)，大链时慢；
3. `head_hash` 来自内存缓存，外部直接改文件后该字段可能陈旧（`verified` 仍是实时计算，可信）；
4. 无 retention / 归档策略（历史证据永久保留，体积随使用增长）。
