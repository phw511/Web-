# ADR-0006 离线模拟：只替换 Transport，其余复用真实实现

- 状态：已采纳
- 日期：2026-11-11
- 关联需求：演示与验收（无可测目标时仍要证明闭环可用）

## 1. 背景

课程演示与评测常常没有可测目标（不能打公网、靶场未部署）。
若为演示另写一套"假流程"，就会出现"演示能跑、真实不能用"的经典问题，
而且演示产物不能作为证据。

## 2. 前置调研

| 方案 | 复用真实逻辑 | 能否产出证据 | 风险 |
|---|---|---|---|
| 另写一份 demo 脚本 | ❌ | ❌ | 两套实现漂移 |
| Mock 掉 Pipeline | 部分 | ❌ | 编排逻辑没被验证 |
| **只替换最底层 Transport** | ✅ 全链路 | ✅ 真实证据链 | MockTransport 行为若与真实靶标不同，结论会有偏差 |

## 3. 决策

`sim/` 只做三件事：

1. `MockTransport`：按请求参数返回预置响应（不含 socket，不触网）；
2. `runner.build_pipeline()`：用**真实**的 `Pipeline / RuleAgent / Authorizer / EvidenceStore / Reporter` 组装，
   唯一不同是把 `RequestsTransport` 换成 `MockTransport`，预算换成 `NullBudget`；
3. `viz`：把同一份 `summary` 数据渲染成 HTML/TXT/MD。

## 4. 后果

**正面**

- 演示产物就是真实管线的产物：`sim_out/evidence/chain.jsonl` 是**真链**，可以 `verify()`；
- 检测器、Agent、授权、预算、证据、报告的任何回归都会在 sim 里暴露；
- 无需网络即可演示，脱机也能验收。

**负面 / 限制（必须如实说）**

- 模拟靶标的响应是我们自己写的 → **不能**用它证明"检测器对真实站点的准确率"；
  它证明的是"给定响应时判定逻辑正确"，这由 `test_detector_judgment.py` 的成对断言承担；
- `sim-demo` 使用 `NullBudget`，**不验证**预算强制（预算由 `test_budget.py` 单独验证）；
- sim 的 TP=2 只说明"在这两个构造响应下闭环走通"，不代表真实环境准确率。

## 5. 验证方式

```powershell
python -m webvuln.cli sim-demo --out .\sim_out
# 实测：candidates=2 / auto_executed=2 / status=finished
# 产物：report.html、report.txt、report.md、report.json、evidence/chain.jsonl
```
