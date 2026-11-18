# T-10 评测与交付（测试 / 证据 / 文档 / 回滚）

- 状态：⚠️ partial（用例与文档完成；真值集与回滚自动化未做）
- 归属阶段：M6 / M7
- 依赖：T-01…T-09
- 关联需求：F10 + 全部验收项
- 关联测试：全量 9 文件 35 条

## 目标

让"做了什么、做到什么程度"可被第三方核对：测试可跑、证据可查、文档与代码一致、版本可回滚。

## 交付物

| 类别 | 文件 |
|---|---|
| 测试 | `tests/` 9 个文件 35 条（含判定自测、预算、manifest、LLM 边界） |
| 证据 | `eval/evidence-2026-11-11.md`（实测输出）、`eval/truth-set.md`（口径） |
| 文档 | `README.md`、`docs/COMPLETION.md`、`brief/`、`design/`、`global.md`、`plan.md`、`tasks/`、`AGENTS.md`、`CONTRIBUTING.md`、`docs/conventions/` |
| 回滚 | `release/rollback.md`（tag 流程 + 证据恢复校验） |
| 脚本 | `scripts/verify.cmd`（一键校验）、`scripts/apply-upgrade.cmd`（合并覆盖） |

## 验收标准

| # | 判据 | 命令 | 实测 |
|---|---|---|---|
| 1 | 全量测试通过 | `pytest -q` | **35 passed, 1 warning in 11.96s** |
| 2 | 离线闭环可跑 | `cli sim-demo` | candidates=2 / auto_executed=2 / finished |
| 3 | 文档数字有出处 | 每个数字指向 `eval/` | ✅ |
| 4 | 未完成项显式列出 | `docs/COMPLETION.md` §7 | ✅ |

## 未做/遗留

- **靶场真值集未部署** → FN/TN 为 `null`（最高优先级待办）；
- 回滚演练未自动化（`release/rollback.md` 是流程文档，需人工执行）；
- 无 CI（测试靠本地 `verify.cmd`）；
- 唯一告警为第三方弃用提示（`starlette.testclient` → httpx2），非本项目问题。
