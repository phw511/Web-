# 需求契约（brief）

> 本文是需求的唯一定义处。计划书（`docs/Web漏洞检测工具项目计划书.md`）提供背景与课程口径，
> 本文提供**可判定的验收口径**与**到测试用例的映射**。冲突时以本文 + 计划书 2.1/2.2/2.3 为准。

## 1. 项目目标

在**已授权**目标上自动完成"检测 → Agent 决策 → 分级授权 → 验证型模拟攻击 → 证据留痕 → 复核签署"闭环，
产出可追溯、可追责、可机器校验的漏洞结论。

成功判据（任一不成立即未达标）：

1. 干净环境按 README 可启动，无手工修补；
2. 同一输入的结论可由 CLI / Web / API 三条路径互证；
3. 每条结论可回溯到请求/响应/决策/审批证据，且证据链可独立校验；
4. 未授权目标零发包，可被测试证明；
5. 全部指标口径可机器断言，含"未运行"的如实标注。

## 2. 功能需求（F1–F10）

| 编号 | 需求 | 验收口径（可判定） | 落点 |
|---|---|---|---|
| F1 | 目标输入 | 界面/CLI 接受 URL 或请求模板；**未注册目标无法发包** | `targets.py`、`egress.py`、`test_egress.py` |
| F2 | 漏洞检测 | 注入/目录敏感文件类漏洞产出候选，且**已知安全响应不误报、已知漏洞响应必命中** | `detector/{sqli,xss,lfi}.py`、`test_detector_judgment.py` |
| F3 | Agent 决策 | 只能从白名单挑选函数，理由须引用候选证据；无匹配函数时挂起不崩 | `agent/rule_agent.py`、`agent/llm_agent.py`、`test_rule_agent.py`、`test_llm_agent.py` |
| F4 | 授权控制 | 低危自动放行、中危 approver、高危 signer；每次放行留审批证据 | `pipeline.py`、`authz/service.py`、`test_budget.py` |
| F5 | 模拟攻击 | 只调白名单函数，出站走唯一出口，采集响应证据 | `attacker/`、`egress.py` |
| F6 | 复核闭环 | 结论须有状态机判定 + 人工签署；INCONCLUSIVE 不可签署 | `pipeline.py`、`conclusions.py`、`test_state_machine.py` |
| F7 | 界面操作 | 配置目标、查看候选、审批攻击、查看结果、导出报告 | `frontend/`、`web/routers/` |
| F8 | 结果可视化 | 表格 + 状态徽标 + 分布图（**图表为后续项，当前仅表格**） | `frontend/src/views/`、`sim/viz.py` |
| F9 | 证据与报告 | 记录请求/响应/调用/审批；导出 JSON/MD/HTML | `evidence/store.py`、`report/reporter.py` |
| F10 | 指标统计 | TP/FP/INCONCLUSIVE 可算；FN 无真值集时**如实为 null** | `reporter.py`、`eval/truth-set.md` |

## 3. 范围与反例

| 边界 | 属于范围 | 不属于范围（反例） |
|---|---|---|
| 目标 | 已注册且双人审批通过的 URL | 未授权目标、他人系统 |
| 攻击强度 | 验证型、副作用最小化且可预期 | 数据篡改、写操作、getShell、不可逆变更 |
| 授权 | 白名单注册 + 可逆性分级放行 | 无授权控制的全自动执行 |
| 形态 | Web 界面 + CLI/API 双入口 | 复杂后台、SaaS 多租户 |
| 检测方式 | 单请求/响应为主 + 固定词表受限探测 | 主动爬虫、大规模目标发现 |

**明确不做**：真实漏洞利用、批量扫描互联网、绕过 WAF、留存敏感原文的明文导出。

## 4. 授权分级

| 级别 | 判定依据 | 放行方式 | 本仓库实例 |
|---|---|---|---|
| 低危 | 只读、无副作用、可逆 | Agent 自动放行，证据记 `system(auto)` | `sqli_boolean_probe`、`xss_reflected_probe` |
| 中危 | 只读但影响面较大 | approver 人工确认 + 必填理由 | `lfi_traversal_probe` |
| 高危 | 不可逆/破坏性 | signer 逐条确认 + 记录理由 | 当前无（元数据防线禁止自标低危） |

## 5. 验收项 ↔ 测试用例对照矩阵

| 验收项 | 判据 | 用例 |
|---|---|---|
| 可运行 | 干净环境按 README 启动 | 手工 + `sim-demo` |
| 可复现 | 证据快照重放一致；重扫差异由证据解释 | `test_hash_chain.py`、`test_state_machine.py` |
| 可判定 | 结论落 CONFIRMED/REJECTED/INCONCLUSIVE | `test_state_machine.py` |
| 授权合规 | 双人审批、提交≠审批、分级放行 | `test_egress.py::test_same_person_cannot_approve`、`test_api_roles.py` |
| 出口管控 | 未注册目标零发包、越范围拦截、SSRF 拦截 | `test_egress.py`（4 条） |
| 预算约束 | 四项上限超限即停并留痕 | `test_budget.py`（4 条） |
| 判定自测 | 已知安全不误报 / 已知漏洞必命中 | `test_detector_judgment.py`（7 条） |
| 运行身份与 manifest | 每条证据带 app_version，manifest 逐条可查 | `test_evidence_manifest.py`（4 条） |
| 可追溯 | 结论回溯到候选→决策→审批→攻击证据 | `test_state_machine.py::test_full_pipeline_low_risk` |
| 复核闭环 | CONFIRMED/REJECTED 可签署，INCONCLUSIVE 不可 | `test_state_machine.py::test_sign_*` |
| 可回滚 | 旧 tag 干净启动 + 证据恢复后 verify 通过 | 流程见 `release/rollback.md`（需 git 操作，未自动化） |

## 6. 非功能约束

| 约束 | 数值/口径 | 实现位置 |
|---|---|---|
| 单目标决策轮次 | ≤ 10 | `BudgetGuard.check_round` |
| 单目标检测总时长 | ≤ 300s | `BudgetGuard.check_time` |
| 单目标攻击请求 | ≤ 50 条 | `EgressGateway.send_attack` |
| 全局攻击并发 | ≤ 2 | `BudgetGuard.acquire_slot` |
| 依赖 | 仅 fastapi/uvicorn/pydantic/requests/httpx + pytest | `requirements.txt` |
| 证据完整性 | 哈希链不可篡改，篡改必被 `verify()` 发现 | `evidence/store.py` |

## 7. 变更记录

| 版本 | 变更 |
|---|---|
| 0.1.0 | 四段闭环 MVP：SQLi 单类全链路、双人审批、哈希链、Web/CLI 双入口 |
| 0.2.0 | 补预算四项强制、app_version、manifest 逐条索引；审批角色下沉；LLM Agent 可插拔骨架；修复 `test_budget` 密码 bug |
