# 六项交付完成情况对照

> 对应课程"完成情况"勾选项（共 6 项）。本表只写**仓库里真实存在**的文件与**实测**结果。
> 最后核对时间：2026-11-11　版本：0.2.0

## 总览

| # | 勾选项 | 状态 | 主要落点 |
|---|---|---|---|
| 1 | 需求 | 完成 | `brief/requirements.md` |
| 2 | 规约 | 完成 | `design/spec/contracts.md`、`data-model.md`、`behavior.md` |
| 3 | ADR（含前置调研） | 完成 | `design/adr/ADR-0001…0008` |
| 4 | 项目级 Harness | 完成 | `AGENTS.md`、`CONTRIBUTING.md`、`docs/conventions/*` |
| 5 | Global / Plan / Tasks | 完成 | `global.md`、`plan.md`、`tasks/T-01…T-10` |
| 6 | 可执行/验证的部分代码 + 评测证据 | 完成 | `webvuln/`、`tests/`（35 passed）、`eval/evidence-2026-11-11.md` |

## 1. 需求

| 内容 | 位置 |
|---|---|
| 功能需求 F1–F10（含验收口径） | `brief/requirements.md` §2 |
| 范围与反例（做什么 / 不做什么） | `brief/requirements.md` §3 |
| 验收项 ↔ 测试用例对照矩阵 | `brief/requirements.md` §5 |
| 授权分级（低/中/高危放行方式） | `brief/requirements.md` §4、`design/spec/behavior.md` §3 |

## 2. 规约

| 内容 | 位置 |
|---|---|
| 8 个抽象契约与依赖方向（谁可以 import 谁） | `design/spec/contracts.md` |
| 数据库 9 张表 + 领域模型字段 + 证据 kind 枚举 | `design/spec/data-model.md` |
| 四段闭环、结论状态机、预算四项强制点、异常语义 | `design/spec/behavior.md` |

## 3. ADR（含前置调研）

| 编号 | 决策 | 是否含调研 |
|---|---|---|
| ADR-0001 | 技术栈：Python + FastAPI + Vue3 + SQLite + 标准库 JWT | ✅ 框架/存储/鉴权三组备选对比 |
| ADR-0002 | 授权层作为唯一网络出口 | ✅ |
| ADR-0003 | 目标注册双人审批 + SSRF 拦截 | ✅ |
| ADR-0004 | 证据 append-only + SHA-256 哈希链 | ✅ 三种防篡改方案对比 |
| ADR-0005 | 规则 Agent 先行、LLM 可插拔 | ✅ 模型选型与降级调研 |
| ADR-0006 | 离线模拟只替换 Transport | ✅ |
| ADR-0007 | 预算四项各自的强制点选择 | ✅ 三类方案对比 |
| ADR-0008 | manifest 逐条索引 + 真值集与 FN 口径 | ✅ 靶场选型调研 |

## 4. 项目级 Harness

| 内容 | 位置 |
|---|---|
| AI 操作约定（可改/不可改、验证门槛、禁止事项） | `AGENTS.md` |
| 开发规范（分支、提交、评审、测试门槛） | `CONTRIBUTING.md` |
| 代码规范（分层、命名、异常、契约变更） | `docs/conventions/code-style.md` |
| 日志规范（谁记、记什么、级别、脱敏） | `docs/conventions/logging.md` |
| 观测性约定（三问：在哪记/记什么/怎么查 + manifest 口径） | `docs/conventions/observability.md` |

## 5. Global / Plan / Tasks

| 内容 | 位置 |
|---|---|
| 项目级目标、边界、成功判据 | `global.md` |
| 初期计划 M1–M7 + 实际完成情况 | `plan.md` |
| 任务分解规范与 10 个任务卡（含验收与关联测试） | `tasks/README.md`、`tasks/T-01…T-10` |

## 6. 可执行代码 + 评测证据

**代码**：`webvuln/`（CLI / Web / API 三入口）、`frontend/`、`tests/`

**真实运行结果（2026-11-11，Windows + Python venv）**：

```
$ .\.venv\Scripts\python.exe -m pytest -q
35 passed, 1 warning in 11.96s

$ .\.venv\Scripts\python.exe -m webvuln.cli sim-demo --out .\sim_out
scan_id  scan-2af0e09f0a07
candidates 2 / auto_executed 2 / pending_approval 0 / suspended 0
budget_stopped "" / status finished
```

- 详细证据与复现步骤：`eval/evidence-2026-11-11.md`
- 判定标准与真值集口径：`eval/truth-set.md`
- 唯一告警为第三方弃用提示（`starlette.testclient` 建议 httpx2），非本项目代码问题

## 7. 尚未完成（如实标注，不勾选）

| 项 | 原因 | 归属 |
|---|---|---|
| 靶场真值集部署（DVWA/WebGoat） | 未部署，FN/TN 无法计算，报告写 `null` | 计划 M2 |
| LLM 真实接入 | 仅有可插拔骨架 + 不触网测试 | 计划 M3b |
| 证据原文加密、签署密钥签名 | 增强项，已列为 M5 | 计划 M5 |
| 组间证据挑战记录 | 组织项，未执行 | 计划第 7 章 |
