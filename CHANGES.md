# 变更清单（批次 1 代码 + 批次 2 文档）

> 版本：0.2.0　基准：`Web--main`（你桌面那份的全量文件）
>
> **批次 1（代码/测试/脚本）已在你机器上实测通过**：
> `pytest -q → 35 passed, 1 warning in 11.96s`；`sim-demo → candidates=2 / auto_executed=2 / finished`。
>
> **批次 2（六项交付文档）** 在本文第七节，全部数字取自上述实测结果（不再有"文档超前于代码"）。

## 一、怎么用（**合并覆盖，不要删除原目录**）

> ⚠️ 本目录只含"改动过的文件"，**不含**未改动的 `__init__.py`、`db/`、`detector/` 等。
> 所以只能"覆盖同名文件"，**不能**先删掉原项目的 `webvuln/` 再拷过去。

## 一、怎么用（**合并覆盖，不要删除原目录**）

> ⚠️ 本目录只含"改动过的文件"，**不含**未改动的 `__init__.py`、`db/`、`detector/` 等。
> 所以只能"覆盖同名文件"，**不能**先删掉原项目的 `webvuln/` 再拷过去。
>
> ⚠️ 四个脚本（`.cmd` / `.ps1`）**刻意只用英文字符**：`cmd.exe` 按系统代码页
> （中日文环境是 932/936）读取批处理，`.ps1` 在 PowerShell 5.1 下无 BOM 也按 ANSI 读，
> 写中文会导致整行被拆坏。要改脚本请保持 ASCII。

**第 1 步：合并覆盖到项目（自动备份 `.bak-v01`）**

```powershell
cd D:\OneDrive\ドキュメント\deepseek-harness\default-workspace\web--main-upgrade

.\scripts\apply-upgrade.cmd "C:\Users\Lenovo\Desktop\Web--main" dry   # 预演，只看清单
.\scripts\apply-upgrade.cmd "C:\Users\Lenovo\Desktop\Web--main"       # 真写
```

> 不想用脚本也可以纯手抄（最不容易出岔子）：
> ```cmd
> cd /d D:\OneDrive\ドキュメント\deepseek-harness\default-workspace\web--main-upgrade
> xcopy webvuln   C:\Users\Lenovo\Desktop\Web--main\webvuln   /E /Y /I
> xcopy tests     C:\Users\Lenovo\Desktop\Web--main\tests     /E /Y /I
> xcopy frontend  C:\Users\Lenovo\Desktop\Web--main\frontend  /E /Y /I
> xcopy scripts   C:\Users\Lenovo\Desktop\Web--main\scripts   /E /Y /I
> copy  requirements.txt C:\Users\Lenovo\Desktop\Web--main\
> ```

**第 2 步：验证**（在项目根目录）

```powershell
cd C:\Users\Lenovo\Desktop\Web--main
python -m pip install -r requirements.txt
.\scripts\verify.cmd
```

**第 3 步**：把 `verify.cmd` 的完整输出贴给我，我据此写批次 2 的文档（只写"已验证"的事）。

**手动方式**：把本目录下的 `webvuln/`、`tests/`、`frontend/`、`scripts/`、`requirements.txt`
逐个覆盖到 `C:\Users\Lenovo\Desktop\Web--main\` 对应位置（同名替换，其余保留）。

> 若已有 `data/app.db` 与 `evidence/chain.jsonl`：建议先备份再删掉重建（见下文"兼容性"）。
> 只是快速验证的话，直接删即可。

## 二、新增文件

| 文件 | 作用 |
|---|---|
| `webvuln/contracts/budget.py` | 预算契约：`BudgetExceeded` 异常 + `BudgetGuardContract` 抽象（四项口径唯一来源） |
| `webvuln/budget.py` | `BudgetGuard` 实现：时长/轮次/请求数/并发四闸；`NullBudget` 供离线模拟使用 |
| `webvuln/agent/llm_agent.py` | 可插拔 LLM Agent（M3b 骨架）+ `ScriptedLLM`（脚本化、**不触网**） |
| `tests/test_llm_agent.py` | LLM Agent 白名单校验 / 决策来源 / 降级路径测试（不触网） |
| `scripts/verify.ps1` | 一键校验：语法编译 + pytest + 离线演示 |
| `requirements.txt` | 移到仓库根（原 `docs/requirements.txt` 是 Dockerfile 找不到的那个） |

## 三、修改文件

| 文件 | 改了什么 | 对应计划书条目 |
|---|---|---|
| `webvuln/config.py` | 新增 `app_version`、`agent_mode`；四项预算与版本全部支持环境变量覆盖 | 5.2、9 章 |
| `webvuln/models/schemas.py` | `HttpSpec.context`（probe/attack）、`EvidenceRecord.app_version` | 5.2、4.1 |
| `webvuln/authz/egress.py` | 新增 `send_attack()`：标记 `context=attack`、按目标计数、**发包前**拦截 | 9 章请求数上限 |
| `webvuln/authz/service.py` | 新增 `assert_approval_allowed()`：中危→approver、高危→signer 的唯一判定处 | 4.1 |
| `webvuln/attacker/executor.py` | 并发信号量（经 BudgetGuard）+ 攻击流量走 `send_attack` | 9 章并发上限 |
| `webvuln/attacker/attacks/*.py` | 三个攻击函数改调 `gateway.send_attack()` | 4.2 |
| `webvuln/evidence/store.py` | 写入 `app_version`；`manifest()` 扩成逐条索引（含 conclusion_ids / signature 预留位）；`verify_scan` 去掉 O(n²) | 5.2、10 章 |
| `webvuln/pipeline.py` | 时长/轮次强制；`stopped_budget`/`budget_exceeded`；`AgentDecisionError` 改为候选挂起；异常→`failed`；审批角色下沉 | 2.3、5.3、9 章 |
| `webvuln/container.py` | 接线 `BudgetGuard`、`app_version`、可选 LLM Provider | 3.1 |
| `webvuln/contracts/{authz,evidence,report}.py` | 补契约：`assert_approval_allowed`、`manifest`、`summary`/`metrics_global` | 3.1 契约唯一 |
| `webvuln/report/reporter.py` | 新增 `metrics_global()`：`/api/stats` 与报告层口径合一 | 2.3 可复现 |
| `webvuln/web/routers/{approvals,reports}.py` | 审批把角色传给服务层；stats 改调 reporter | 4.1、2.3 |
| `webvuln/web/app.py` | 版本号 0.2.0；health 带 `app_version` | 5.2 |
| `webvuln/sim/runner.py` | 证据存储带 `app_version` | 5.2 |
| `tests/test_budget.py` | **只修测试自身的 bug**：建账号密码 `a1`/`s1` 不足 6 位（`UserService` 要求 ≥6），断言一字未改 | — |
| `frontend/src/{api.js,views/*.vue}` | 401 跳转、审批按钮按角色显示、审批理由非空校验、版本号 0.2.0 | F7 |
| `webvuln/__init__.py` | `__version__ = "0.2.0"` | — |

## 四、明确**没有**改的（避免误解）

- **没有**改任何测试断言来凑通过；改的只有 `test_budget.py` 里那两个短密码。
- **没有**改数据库表结构（`db/database.py` 原样），老库可直接用。
- **没有**真接 LLM API（按你的选择，只做可插拔骨架 + 不触网的 `ScriptedLLM`）。
- **没有**加第三方依赖（预算/并发/JWT 全用标准库）。
- **没有**动 `webvuln/db/`、`webvuln/detector/`、`webvuln/contracts/{agent,attack,detector,transport}.py`。

## 五、兼容性说明（会咬人的两点）

1. **证据链**：`EvidenceRecord` 新增 `app_version`。为了让**旧链仍然校验通过**，
   哈希计算时对空的 `app_version` 字段做了排除（`_body()`），所以老 `chain.jsonl`
   不会因为升级而"假篡改"。但如果你是拿新库跑新链，无需关心。
2. **扫描状态**：新增 `stopped_budget` / `failed` 两个值。旧数据里只有
   `running` / `finished`，不影响读取。若有前端/脚本按状态做全等判断，需要补这两个分支。

## 六、本批的验收口径（已实测）

| 期望 | 实测 |
|---|---|
| 9 个原有测试文件 + 1 个新增，全绿 | **35 passed, 1 warning in 11.96s** |
| 预算四项都真被执行 | `test_budget.py` 4 条全过 |
| 运行身份与 manifest 逐条索引 | `test_evidence_manifest.py` 4 条全过 |
| 离线演示仍能跑通 | candidates=2 / auto_executed=2 / status=finished |
| 证据链可独立校验 | `sim_out/evidence/chain.jsonl` 生成成功 |

唯一告警：`starlette.testclient` 对 httpx 的弃用提示（第三方，非本项目代码）。

## 七、批次 2：六项交付文档

| 勾选项 | 文件 |
|---|---|
| ① 需求 | `brief/requirements.md` |
| ② 规约 | `design/spec/contracts.md`、`design/spec/data-model.md`、`design/spec/behavior.md` |
| ③ ADR（含前置调研） | `design/adr/ADR-0001…0008`（8 篇，每篇都有"前置调研"） |
| ④ 项目级 Harness | `AGENTS.md`、`CONTRIBUTING.md`、`docs/conventions/{code-style,logging,observability}.md` |
| ⑤ Global / Plan / Tasks | `global.md`、`plan.md`、`tasks/README.md` + `tasks/T-01…T-10` |
| ⑥ 代码 + 评测证据 | 代码见批次 1；`eval/evidence-2026-11-11.md`、`eval/truth-set.md` |
| 索引 | `README.md`（仓库根，重写）、`docs/README.md`（改为迁移说明）、`docs/COMPLETION.md`（六项对照） |
| 交付配套 | `release/rollback.md`、`review/README.md` |

> 文档中所有"已验证"均指向 `eval/evidence-2026-11-11.md` 的原始输出；
> 未完成项统一列在 `docs/COMPLETION.md` 第 7 节。
