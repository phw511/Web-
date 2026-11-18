# 接口契约规约（design/spec/contracts.md）

> 一句话：**模块之间只能通过 `webvuln/contracts/` 的抽象与 `models/schemas.py` 的模型通信**，
> 具体实现互不可见；唯一的"知道所有实现"的地方是 `container.py`（DI 组装根）。

## 1. 契约清单

| 契约文件 | 抽象 | 实现 | 依赖方 | 变更影响面 |
|---|---|---|---|---|
| `contracts/agent.py` | `DecisionAgent.decide()` | `RuleAgent`、`LLMAgent` | Pipeline | 换决策策略 |
| `contracts/attack.py` | `AttackFunction.execute()`、`AttackRegistry`、`@register_attack` | 3 个 probe + 注册表 | Executor、Agent | 新增漏洞验证能力 |
| `contracts/transport.py` | `Transport.send()` | `RequestsTransport`、`MockTransport`、测试 Fake | EgressGateway | 换网络栈 |
| `contracts/authz.py` | `Authorizer`（注册/审批/`assert_approval_allowed`）、`AuthorizationError`、`ApprovalForbidden`、`EgressDenied` | `AuthorizerService` | Pipeline、Web | 授权口径 |
| `contracts/budget.py` | `BudgetGuardContract`（7 方法）、`BudgetExceeded`、四个 `KIND_*` | `BudgetGuard`、`NullBudget` | Pipeline、Egress、Executor | 预算口径 |
| `contracts/detector.py` | `BaseDetector.detect()` | SQLi/XSS/LFI | DetectorEngine | 新增检测类型 |
| `contracts/evidence.py` | `EvidenceStore`（append/get/for_scan/verify/verify_scan/manifest） | `FileEvidenceStore` | Pipeline、Web、Report | 换存储介质 |
| `contracts/report.py` | `Reporter`（render/summary/metrics_global） | `ReporterService` | Web、CLI | 换报告格式 |

> 8 个契约对应计划书"7 个抽象基类 + 预算契约（v0.2.0 新增）"。

## 2. 依赖方向（只允许箭头方向）

```
web/  ─────▶ container ─────▶ 具体实现（detector / agent / attacker / authz / evidence / report）
  │              │
  └──▶ contracts └──▶ models/schemas
                    ▲
pipeline ───────────┘（只 import contracts + schemas，不 import 任何实现）
```

硬规则（评审必查）：

1. `pipeline.py` **不得** import `detector/sqli.py`、`agent/rule_agent.py` 等具体实现；
2. 检测器与攻击函数**不得** import `requests` / `socket`，只接收 `gateway` 参数；
3. `requests` 只允许出现在 `container.RequestsTransport`；
4. `db/database.py` 是唯一持有 sqlite 连接的文件，其他模块只经 `Database.execute/query/one`。

## 3. 关键契约的方法语义

### 3.1 `DecisionAgent.decide(candidate, registry) -> AttackDecision`

- 输入：候选（含 `claim` 证据摘录）+ 注册表；
- 输出：`function_name` 必须 ∈ 该 `vuln_type` 的白名单函数，且 `reason` 必须引用候选证据；
- 失败：抛 `AgentDecisionError`（无匹配函数 / LLM 输出非法 / LLM 越界选择）。
  **编排层捕获后把候选挂起，不中断整次扫描。**

### 3.2 `AttackFunction.execute(gateway, candidate, base, decision_id) -> AttackResult`

- 只读、可逆、副作用已在 `meta.side_effects` 声明；
- 所有出站必须走 `gateway.send_attack()`（自动打 `context=attack` 并计数）；
- `matched` 的判定规则与 `meta.expected_signal` 一一对应，可机器断言。

### 3.3 `BudgetGuardContract`

| 方法 | 调用方 | 超限时 |
|---|---|---|
| `start_scan` | Pipeline | — |
| `check_time(phase)` | Pipeline（检测前 + 每候选前） | 抛 `KIND_TIME` → 扫描 `stopped_budget` |
| `check_round()` | Pipeline（每次下发决策前） | 抛 `KIND_ROUNDS` → 扫描 `stopped_budget` |
| `charge_attack_request(url)` | EgressGateway（发包前） | 抛 `KIND_REQUESTS` → 上抛给调用方 |
| `acquire_slot/release_slot` | AttackExecutor | 抛 `KIND_CONCURRENCY` → 上抛 |
| `snapshot()` | Pipeline（写证据） | — |

### 3.4 `EvidenceStore.manifest()`

返回结构固定为：

```json
{
  "app_version": "0.2.0",
  "head_hash": "<64 hex>",
  "record_count": 6,
  "verified": true,
  "records": [
    {"id":"ev-…","kind":"scan_start","scan_id":"scan-…","hash":"…","prev_hash":"GENESIS",
     "created_at":"…","app_version":"0.2.0","conclusion_ids":[],"signature":null}
  ]
}
```

`signature` 为预留位（增强项），当前恒为 `null` —— 不假装已签名。

## 4. 扩展点（新增能力只碰这两处 + 一处注册）

| 想加什么 | 要改什么 | 不需要改什么 |
|---|---|---|
| 新漏洞类型 | `detector/` 加检测器 + `attacker/attacks/` 加函数 + `attacks/__init__.py` 注册 + `container.py` 一行 | pipeline / egress / evidence / report |
| 换决策策略（真实 LLM） | 实现 `DecisionLLM` 并传入 `Container(llm_provider=...)` | pipeline / 所有检测与攻击 |
| 换网络栈 | 实现 `Transport` 并替换 `container.transport` | 其余全部 |
| 换证据存储（如 DB/S3） | 实现 `EvidenceStore` 并替换容器一行 | pipeline / report |

## 5. 契约变更规则

1. 新增**抽象方法** = 破坏性变更：必须同步所有实现 + 在 `docs/COMPLETION.md` 记一条；
2. 新增**默认实现**（如 `HttpSpec.context` 有默认值）不算破坏性；
3. 任何契约变更必须附一条测试，证明旧调用方仍工作；
4. 契约文件顶部必须写明"谁依赖我、我不能依赖谁"。
