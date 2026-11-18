# CONTRIBUTING.md — 开发与评审规范

## 1. 环境

| 项 | 要求 |
|---|---|
| Python | 3.10+（实测 3.12/3.13 均可） |
| 依赖 | `python -m pip install -r requirements.txt`（根部那份，Dockerfile 也用它） |
| 虚拟环境 | 推荐 `.venv`（已在 `.gitignore`） |
| 前端 | Node 20+，`npm install` |
| 无需 | 数据库服务、消息队列、外部模型 API |

## 2. 分支与提交

```
main            ← 可交付状态，必须测试全绿
feat/<topic>    ← 功能
fix/<topic>     ← 修复
docs/<topic>    ← 仅文档
```

提交信息格式（一句话说清"做了什么 + 为什么"）：

```
feat(budget): 补齐四项上限强制点并接线到容器

- 新增 contracts/budget.py 与 BudgetGuard（时长/轮次/请求数/并发）
- 时长与轮次在 pipeline 停扫描；请求数在出口记账；并发在执行器
- 修复 test_budget 建账号密码不足 6 位导致必然失败的问题
验证：pytest -q → 35 passed
```

**每个提交都必须能独立通过测试**（不要提交"半条链路"）。

## 3. 评审清单（评审人逐条确认）

| 维度 | 检查点 |
|---|---|
| 契约 | 新能力是否通过 `contracts/` + DI 接线？有没有跨层 import 实现？ |
| 出口 | 是否新增了绕过 `EgressGateway` 的发包路径？`grep -r "requests\." webvuln/` 应只有容器一处 |
| 安全 | 新增攻击函数是否自标低危但含写操作特征？`side_effects` 是否如实？ |
| 预算 | 新的循环/批量请求是否受四个上限约束？ |
| 证据 | 新的状态变化是否写证据？kind 是否登记到 `design/spec/data-model.md`？ |
| 测试 | 是否覆盖"已知安全不误报"和"已知漏洞必命中"两个方向？ |
| 文档 | 版本号、命令、文件名是否同步？ |

## 4. 依赖政策

- 运行期依赖保持 **4 个**（fastapi / uvicorn / pydantic / requests）+ 测试 2 个（pytest / httpx）；
- 新增依赖必须满足：① 标准库确实做不了；② 有明确安全维护记录；③ 提交信息说明理由；
- 禁止引入：ORM（与"表结构即契约"冲突）、打包的前端 UI 框架（体积）、任何遥测 SDK。

## 5. 代码风格

见 `docs/conventions/code-style.md`（分层、命名、异常、注释）。

## 6. 日志与观测

见 `docs/conventions/logging.md` 与 `docs/conventions/observability.md`。
**核心要求**：证据优先于日志；日志不得含敏感原文。

## 7. 发布流程

见 `release/rollback.md`（git tag、证据归档、回滚验证）。
发布前必须：`pytest -q` 全绿 + `sim-demo` 跑通 + `docs/COMPLETION.md` 更新。
