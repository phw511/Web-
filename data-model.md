# 数据契约规约（design/spec/data-model.md）

> 数据库是 SQLite（`webvuln/db/database.py`，`SCHEMA` 内联）。**表结构即契约**：
> 改表必须同时改本文 + 迁移说明（当前无第三方 ORM / 无迁移框架，靠 `CREATE TABLE IF NOT EXISTS`）。

## 1. 表清单（9 张）

| 表 | 用途 | 主键 | 关键约束 |
|---|---|---|---|
| `users` | 账号与角色 | `username` | `role ∈ {admin,submitter,approver,signer}`；密码 PBKDF2-SHA256(200k) |
| `targets` | 授权目标 | `id` | `url` 唯一（规范化 origin）；`status ∈ {pending,approved,rejected}` |
| `scans` | 扫描运行 | `id` | `status ∈ {running,finished,stopped_budget,failed}`（0.2.0 新增后两个） |
| `candidates` | 检测候选 | `id` | 关联 `scan_id`、`target_id` |
| `decisions` | Agent 决策 | `id` | 关联 `candidate_id`；含 `risk_level`、`decision_source` |
| `approvals` | 审批记录 | `id` | `kind ∈ {target,attack}`、`action ∈ {approve,reject}`、`reason` 必填 |
| `attack_runs` | 攻击执行结果 | `id` | `decision_id` **UNIQUE**：同一决策不可重复执行 |
| `conclusions` | 结论 | `id` | `candidate_id` **UNIQUE**：一个候选只能有一个结论 |
| `evidence_index` | 证据索引 | `id` | 每条证据一行，便于 SQL 查询；真身在 chain.jsonl |

## 2. 状态与枚举

### 2.1 结论状态机（`CandidateState`）

```
CANDIDATE ──(放行并执行)──▶ ATTACKED ──┬─▶ CONFIRMED（matched）──▶ 可签署 → TP
                                       ├─▶ REJECTED（未 matched）─▶ 可签署 → FP
                                       └─▶ INCONCLUSIVE（人工否决/无法判定）─▶ 不可签署
```

- 数据库中只持久化终态 `CONFIRMED / REJECTED / INCONCLUSIVE`；
- `INCONCLUSIVE` 的证据等级为 `Observed`（计划书 5.3 的最低要求），且**禁止签署**。

### 2.2 证据等级（`EvidenceLevel`）

`ClaimOnly < Static < Observed < Reproduced`

- 检测器产出 = `ClaimOnly`（只是自述）；
- 攻击未命中 = `Observed`；命中 = `Reproduced`；
- 对外结论至少 `Observed`，关键结论要求 `Reproduced`。

### 2.3 证据记录 kind（`EvidenceRecord.kind`）

| kind | 何时写 | 关键 payload |
|---|---|---|
| `scan_start` | 扫描开始 | `target_id`、`url`、`by` |
| `decision` | Agent 决策后 | 完整 `AttackDecision` |
| `approval` | 放行审批 | `decision_id`、`action`、`actor`、`reason` |
| `pending_approval` | 中高危待审批 | `decision_id`、`risk_level` |
| `attack_request` | 攻击执行前 | 函数名、风险级别、副作用声明 |
| `attack_response` | 攻击执行后 | 完整 `AttackResult` |
| `state_change` | 结论落定 | `candidate_id`、`state`、`evidence_level`、`decided_by` |
| `sign` | 人工签署 | `conclusion_id`、`signer`、`note` |
| `budget_exceeded` | 预算超限 | `kind`（时长/轮次/请求数/并发）、`limit`、`reason`、`snapshot` |
| `candidate_suspended` | 无匹配攻击函数 | `candidate_id`、`vuln_type`、`reason` |
| `scan_failed` | 未预期异常 | `error`（类型 + 消息） |

> 新增 kind 必须登记到本表；`manifest()` 不对 kind 做白名单，但评价方据此核对完整性。

## 3. 领域模型（`models/schemas.py`）

| 模型 | 关键字段 | 说明 |
|---|---|---|
| `HttpSpec` | `method/url/headers/params/data/context` | `context ∈ {probe,attack}`，由出口打标 |
| `ResponseSnapshot` | `status_code/headers/body/elapsed_ms` | body 截断 20000 字符 |
| `TargetRegistration` | `url/scope_paths/base_params/status/allow_private/expires_at` | `allow_private` 为 SSRF 例外开关 |
| `FindingCandidate` | `vuln_type/endpoint/parameter/claim/detector` | `claim` 必须含可核查的响应摘录 |
| `AttackFunctionMeta` | `risk_level/reversible/side_effects/expected_signal` | 运行期防降级校验的输入 |
| `AttackDecision` | `function_name/reason/expected_result/decision_source` | `source ∈ {rule,llm}` |
| `AttackResult` | `matched/response_status/response_excerpt` | 判定结果唯一来源 |
| `EvidenceRecord` | `kind/payload/prev_hash/hash/app_version` | 空 `app_version` 不入哈希（兼容旧链） |
| `Conclusion` | `state/evidence_level/decided_by/signed_by` | 签署后计入指标 |

## 4. 哈希链算法

```
hash_i = SHA-256( prev_hash_i + "|" + canonical_json(record_i) )
canonical_json = json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",",":"))
prev_hash_0 = "GENESIS"
```

- 记录以 JSONL 追加写入 `<evidence_dir>/chain.jsonl`，**只增不改**；
- `verify()` 从头重放，任一环不匹配即 `False`；
- `verify_scan(scan_id)` 额外校验子链前驱可达（防"孤链伪造"）；
- 兼容性：`app_version` 为空时不参与哈希，保证 0.1.x 写入的旧链升级后仍校验通过。

## 5. 约束与索引

- `targets.url` UNIQUE：同一 origin 只能注册一次（防重复授权）；
- `attack_runs.decision_id` UNIQUE：**同一决策不可被重复审批执行**（幂等防线）；
- `conclusions.candidate_id` UNIQUE：避免同一候选产出两条结论；
- 证据的 `scan_id` 无外键（JSONL 为主存储，DB 只是索引）；查询靠 `evidence_index`。

## 6. 迁移策略（当前）

| 场景 | 做法 |
|---|---|
| 新增表 | 追加到 `SCHEMA`，`IF NOT EXISTS` 自动生效 |
| 新增列 | SQLite `ALTER TABLE ... ADD COLUMN`（手工，写进本次变更说明） |
| 破坏性变更 | 不允许静默执行：必须写迁移脚本 + 在 `release/rollback.md` 记回退方式 |
| 旧证据链 | 由哈希兼容规则保证；若确需重建，删除 `evidence/` 并重跑（会失去历史链，需在 release 记录） |
