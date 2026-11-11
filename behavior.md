# 行为规约（design/spec/behavior.md）

> 本文定义"系统在什么条件下做什么"，是测试用例与代码评审的共同依据。
> 每条规则都标了**强制点**（代码位置）与**验证方式**（测试或命令）。

## 1. 扫描主流程（`Pipeline.run_scan`）

```
① 校验目标已 approved ──否则 AuthorizationError（不建扫描）
② 建扫描记录 status=running，写 scan_start 证据
③ 预算：start_scan；check_time("检测启动")
④ 检测：engine.run → 候选列表
⑤ 逐个候选：
   a. check_time → check_round
   b. 存候选
   c. Agent 决策 ── AgentDecisionError → 写 candidate_suspended，continue
   d. 存决策 + decision 证据
   e. 低危 → approval(system(auto)) → 执行攻击 → 结论 → state_change
      中高危 → pending_approval，计数
⑥ status=finished，返回统计
```

**异常语义（关键）**

| 情况 | 扫描状态 | 证据 | 是否上抛 |
|---|---|---|---|
| 超时长（`KIND_TIME`） | `stopped_budget` | `budget_exceeded` | 否，正常返回 |
| 超轮次（`KIND_ROUNDS`） | `stopped_budget` | `budget_exceeded` | 否，正常返回 |
| 攻击请求超限（`KIND_REQUESTS`） | `failed` | `budget_exceeded` | **是**（`BudgetExceeded`） |
| 并发超限（`KIND_CONCURRENCY`） | `failed` | `budget_exceeded` | **是** |
| 其他未预期异常 | `failed` | `scan_failed` | 是 |
| 无匹配攻击函数 | 不受影响 | `candidate_suspended` | 否 |

> 设计理由：时长/轮次是"编排层能兜住"的全局约束，停下并如实留痕即可；
> 请求数/并发是"某一条攻击被拦"，调用方必须知道（否则会误以为扫描完整）。
> 两者都不允许"静默跳过"。

## 2. 返回结构（`run_scan`）

```json
{
  "scan_id": "scan-…",
  "candidates": 2,
  "auto_executed": 2,
  "pending_approval": 0,
  "suspended": 0,
  "budget_stopped": "",
  "status": "finished"
}
```

`budget_stopped` 未触发时为空串（调用方无需判断 key 是否存在）。

## 3. 分级放行（唯一判定处）

```
risk=low    → 无人工节点，Agent 自动放行，证据 actor="system(auto)"
risk=medium → approver（admin 兜底）
risk=high   → signer（admin 兜底）
```

- 判定实现：`AuthorizerService.assert_approval_allowed(actor_role, risk_level)`；
- **不允许**在 Web 路由里重写这套规则（v0.1 就是写在路由里，CLI 可绕过）；
- 违规抛 `ApprovalForbidden`（路由映射 403），审批理由为空抛 `AuthorizationError`（400）；
- 同一 `decision_id` 只能执行一次（`attack_runs.decision_id` UNIQUE + `_get_decision` 预检）。

## 4. 出口管控（`EgressGateway`）

每次出站按顺序校验，任一步失败即 `EgressDenied`，**一个字节都不发**：

1. URL 合法（有 scheme + host）→ 取 origin；
2. 目标已注册；
3. 目标 `status == approved`；
4. 授权未过期（`expires_at`）；
5. 请求路径在 `scope` 内（`/` 表示整站）；
6. 目标 IP 非内网/保留段，或已声明 `allow_private` 且审批通过。

攻击流量额外两步（`send_attack`）：打 `context=attack` 标记 → 预算记账 → 才发包。

## 5. 预算四项（计划书第 9 章）

| 项 | 默认值 | 强制点 | 触发效果 |
|---|---|---|---|
| 决策轮次 | 10 | `Pipeline` 每次决策前 | 扫描 `stopped_budget` |
| 检测总时长 | 300s | `Pipeline` 检测前 + 每候选前 | 扫描 `stopped_budget` |
| 攻击请求数 | 50 | `EgressGateway.send_attack` 发包前 | 抛 `BudgetExceeded` |
| 攻击并发 | 2 | `AttackExecutor.execute` 信号量 | 抛 `BudgetExceeded` |

全部可用环境变量覆盖：`WEBVULN_LLM_ROUNDS`、`WEBVULN_SCAN_TIMEOUT`、
`WEBVULN_MAX_ATTACK_REQUESTS`、`WEBVULN_MAX_CONCURRENCY`。

## 6. 证据写入规则

1. 任何状态变化必须先写证据、后改数据库（顺序：证据 → DB），保证"有记录才有状态"；
2. 证据只追加，不修改、不删除；
3. 每条记录带 `app_version`；
4. 同一次扫描的证据构成子链，`verify_scan` 校验前驱可达；
5. 证据写入失败 = 流程失败（不允许"继续跑但没有证据"）。

## 7. 报告与指标口径

- `TP = CONFIRMED`、`FP = REJECTED`、`INCONCLUSIVE` 单列、`PENDING = 有候选但无结论`；
- `FN` 无真值集时为 `null`，报告与 API 都显式写 `null`，**不填 0 冒充**；
- 单次扫描汇总（`summary`）与全局指标（`metrics_global`）**只有一份实现**（`ReporterService`）。

## 8. Web 层行为

| 端点 | 认证 | 角色 | 失败映射 |
|---|---|---|---|
| `POST /api/auth/login` | 否 | — | 401 |
| `POST /api/auth/users` | 是 | admin | 400 |
| `POST /api/targets` | 是 | submitter | 400 |
| `POST /api/targets/{id}/approve` | 是 | approver | 400 |
| `POST /api/scans` | 是 | submitter | 400 |
| `GET /api/approvals/pending` | 是 | 任意登录 | — |
| `POST /api/approvals` | 是 | 由风险级别决定 | 403 / 400 |
| `POST /api/conclusions/{id}/sign` | 是 | signer | 400 |
| `GET /api/reports/{id}` | 是 | 任意登录 | — |
| `GET /api/stats` | 是 | 任意登录 | — |

## 9. 不可违反的硬约束（评审红线）

1. 未注册目标零发包（`test_egress.py` 断言 transport 请求列表为空）；
2. 提交人 ≠ 审批人（服务层校验，非仅前端）；
3. 低危函数不得含高危特征（运行期元数据校验，`test_rule_agent.py`）；
4. INCONCLUSIVE 不可签署（`test_state_machine.py`）；
5. 预算声明了数值就必须有强制点（否则视为"未运行"，见 `docs/conventions/observability.md`）。
