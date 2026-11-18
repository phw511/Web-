# ADR-0008 manifest 逐条索引 + 真值集与 FN 口径

- 状态：已采纳（真值集部分：未执行，如实标注）
- 日期：2026-11-11
- 关联需求：F10；计划书第 10 章"评价 Agent 审查入口"

## 1. 背景

两个问题来自同一个根因：**指标要能被机器核对，而不是靠作者自述**。

1. 评价方要在"受限工具、禁止任意 shell"的条件下审查证据 → 需要一个索引文件，
   而不是让他读几十个 JSONL 行；
2. FN（漏报）必须有 ground truth 才算得出来 → 没有靶场就**不能**报一个数字。

## 2. 前置调研

### 2.1 审查入口形态

| 方案 | 可机器读 | 信息量 | 结论 |
|---|---|---|---|
| 只有一个 `head_hash` | ✅ | 无法定位具体记录 | ❌（v0.1 就是这样） |
| HTML 报告 | ❌ 需解析 | 好看但不可断言 | ❌ |
| **JSON manifest 逐条索引** | ✅ | 哈希/类型/scan_id/关联结论/版本/签名位 | ✅ |

### 2.2 靶场选型（供 M2 执行）

| 靶场 | 覆盖 | 部署成本 | 备注 |
|---|---|---|---|
| **DVWA** | SQLi、XSS、LFI、文件包含 | 低（单容器） | 与现有 3 个检测器正好对得上 → 首选 |
| WebGoat | 更全（含 XXE/越权） | 中 | 后续扩展 IDOR 时再上 |
| vulhub | 真实 CVE 场景 | 高（按漏洞起容器） | 适合专项验证，不适合当基线 |

## 3. 决策

1. `EvidenceStore.manifest()` 返回逐条索引，字段固定：
   `id/kind/scan_id/hash/prev_hash/created_at/app_version/conclusion_ids/signature`；
2. `signature` 恒为 `null`（增强项预留位），**不假装已签名**；
3. `app_version` 顶层 + 每条记录各一份，跨版本回归可归因；
4. FN：**没有真值集就返回 `null`**，报告、API、前端都显示 `null`，绝不填 0；
5. 真值集部署后才允许把 FN 从 `null` 改为数字，且必须同时提交靶场镜像版本。

## 4. 后果

**正面**

- 评价方一条命令拿到全量索引（`GET /api/evidence/verify` 或 `cli verify-evidence`）；
- 关联结论可查（`conclusion_ids`），能回答"这条证据最终支撑了哪条结论"；
- 指标不失真：`FN=null` 诚实地表示"未度量"，与 `FN=0`（度量过且无漏报）区分开。

**负面 / 未完成**

- 真值集未部署，FN/TN 至今为 `null` → 计划书 M2 遗留项，已在 `docs/COMPLETION.md` 标注；
- manifest 全量返回，证据量大时响应会变大（未做分页，当前规模可接受）；
- `conclusion_ids` 依赖 payload 里出现 `candidate_id`/`conclusion_id`，新增 kind 需遵守该约定。

## 5. 验证方式

```powershell
python -m pytest tests/test_evidence_manifest.py -q   # 4 passed（含篡改检测）
```
