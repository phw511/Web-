# 日志规范（docs/conventions/logging.md）

## 1. 基本原则

**证据优先于日志。** 本项目的"事实来源"是 `evidence/chain.jsonl`（不可篡改、可校验），
日志只承担"运行时诊断"，不承担"事后举证"。因此：

- 任何**会影响结论**的事件 → 必须写证据，而不是写日志；
- 日志丢失不影响结论的可追溯性；证据丢失则流程失败。

## 2. 分级与去向

| 级别 | 用途 | 示例 |
|---|---|---|
| ERROR | 流程无法继续 | `scan_failed`：检测器抛未预期异常 |
| WARNING | 降级/挂起但可继续 | `candidate_suspended`：无匹配攻击函数 |
| INFO | 关键状态变化 | 扫描开始/结束、审批放行、预算超限 |
| DEBUG | 排障细节 | 出口校验的每一次拒绝原因 |

当前实现：`logging` 未接 handler（默认 stderr），INFO 级关键节点已由**证据**覆盖；
接入生产时只加 `logging.basicConfig`，不改业务代码。

## 3. 必须记录（已实现为证据）

| 事件 | 证据 kind | 字段 |
|---|---|---|
| 扫描开始 | `scan_start` | target_id、url、by |
| 决策 | `decision` | 函数名、理由、expected_result、decision_source |
| 审批 | `approval` / `pending_approval` | actor、action、reason、risk_level |
| 攻击请求/响应 | `attack_request` / `attack_response` | 函数、副作用、matched、响应摘录 |
| 结论 | `state_change` | state、evidence_level、decided_by |
| 签署 | `sign` | signer、note |
| 预算超限 | `budget_exceeded` | kind、limit、reason、snapshot |
| 扫描失败 | `scan_failed` | 异常类型 + 消息 |

## 4. 禁止记录（脱敏红线）

| 禁止 | 原因 |
|---|---|
| 完整 `Cookie` / `Authorization` 头 | 可直接复用凭据 |
| 响应中的用户数据（姓名、手机号、身份证、订单） | 隐私合规 |
| 密码、token、密钥 | 一眼即事故 |
| 真实目标的内网 IP 段清单 | 攻击面信息 |

已实现的约束：`ResponseSnapshot.body` 截断 20000 字符；报告层对 URL/参数做 `html.escape`；
证据里的请求只存 `HttpSpec`（headers 默认为空，未采集敏感头）。

> 已知不足：**证据原文未加密**（计划书 5.4 增强项），当前靠"访问受控 + 展示脱敏"缓解，
> 已在 `docs/COMPLETION.md` 第 7 节标注为未完成。

## 5. 日志格式（接入时）

```
2026-11-11T12:03:07+08:00 INFO  webvuln.pipeline scan=scan-… target=tgt-… status=running
2026-11-11T12:03:07+08:00 INFO  webvuln.budget budget_stopped kind=轮次 limit=10
2026-11-11T12:03:08+08:00 WARN  webvuln.pipeline candidate_suspended cand=… reason=无匹配函数
```

要求：单行、键值对、时间用 ISO8601 带时区、不含多行堆栈（堆栈单独 `DEBUG`）。

## 6. 与证据的对应关系

```
日志(诊断, 可丢)  ──┐
                   ├─▶ 同一次 scan_id 可关联
证据(举证, 不可丢) ──┘
```

排查时先用日志定位"哪一步"，再用 `scan_id` 到 `chain.jsonl` 找**事实**。
两者的关联键永远是 `scan_id`（+ `decision_id` / `candidate_id`）。
