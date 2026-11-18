# T-06 攻击函数库与执行器（白名单 + 分级放行）

- 状态：✅ done
- 归属阶段：M3a
- 依赖：T-03、T-04
- 关联需求：F4、F5
- 关联测试：`tests/test_state_machine.py`（端到端）、`tests/test_rule_agent.py::test_low_risk_metadata_guard`

## 目标

攻击能力只能通过注册获得；每个函数自带风险元数据；执行前经授权放行、执行后留证据。

## 交付物

| 文件 | 风险 | 副作用 |
|---|---|---|
| `attacks/sqli_probe.py` | 低危 | 2 次只读 GET（恒真/恒假） |
| `attacks/xss_probe.py` | 低危 | 1 次只读 GET（金丝雀反射） |
| `attacks/lfi_probe.py` | 中危 | 1 次只读 GET（路径穿越） |
| `contracts/attack.py` | — | 注册表 + `HIGH_SIGNAL_KEYWORDS` 运行期校验 |
| `attacker/executor.py` | — | 证据前后留痕 + 并发信号量 |

## 验收标准

1. 未注册函数不可执行：`registry.get()` 返回 `None` → `ValueError`；
2. 自标低危但 `side_effects` 含 `write/delete/drop/...` → 注册即抛 `ValueError`；
3. 低危自动执行并留 `approval(system(auto))`；
4. 中危进 `pending_approval`，不自动执行；
5. 同一决策不可重复执行（`attack_runs.decision_id` UNIQUE）。

```powershell
python -m pytest tests/test_state_machine.py tests/test_rule_agent.py -q
```

## 未做/遗留

- 无高危函数实例（只有防线，没有样例）——引入时须补测试；
- 无"执行后回滚/清理"实现（当前所有函数都是只读，无需回滚；若引入写操作必须补）；
- 无超时控制（依赖 transport 的 10s timeout）。
