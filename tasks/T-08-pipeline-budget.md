# T-08 编排、预算四项与扫描状态机

- 状态：✅ done
- 归属阶段：M3a
- 依赖：T-03、T-05、T-06、T-07
- 关联需求：F4、F6；计划书 2.3"预算约束"
- 关联测试：`tests/test_budget.py`（4）、`tests/test_state_machine.py`（4）

## 目标

把四段链路串起来，并让"超限即停"成为可断言的行为；扫描永远不留在 `running`。

## 交付物

| 文件 | 内容 |
|---|---|
| `pipeline.py` | `run_scan` / `execute_approved` / `sign_conclusion` / `replay` |
| `contracts/budget.py` + `budget.py` | 四项上限 + `BudgetExceeded`（带 `kind`） |
| `--` | 扫描状态：`running / finished / stopped_budget / failed` |

## 验收标准

| # | 判据 | 用例 |
|---|---|---|
| 1 | 时长超限 → `stopped_budget` + `budget_exceeded` 证据 + 链可校验 | `test_scan_time_budget_stops_scan` |
| 2 | 轮次超限 → 已处理部分保留（executed=1/candidates=2） | `test_decision_round_budget_stops_partial` |
| 3 | 攻击请求超限 → 出口拦截、第 2 条未发出、异常上抛 | `test_attack_request_cap_blocks_at_gateway` |
| 4 | 并发上限 → 第 3 次获取即抛，释放后可再取 | `test_concurrency_guard` |
| 5 | 完整链路证据顺序 | `test_full_pipeline_low_risk` |
| 6 | 负样本不产出候选 | `test_negative_target_rejected` |
| 7 | 中危不自动执行、人工否决 → INCONCLUSIVE 且不可签 | `test_sign_inconclusive_forbidden` |

```powershell
python -m pytest tests/test_budget.py tests/test_state_machine.py -q     # 8 passed
```

## 未做/遗留

- 预算状态是进程内对象：多 worker 时并发上限为"每 worker N"；
- 无扫描取消/中断接口（只有超限自动停）；
- 无重试策略（检测请求失败即跳过该参数）。
