# T-05 Agent：规则决策 + LLM 可插拔

- 状态：✅ done（LLM 仅骨架，未接真实 API）
- 归属阶段：M3b
- 依赖：T-04（候选来源）、T-06（白名单来源）
- 关联需求：F3
- 关联测试：`tests/test_rule_agent.py`（3）、`tests/test_llm_agent.py`（5）

## 目标

Agent 只做决策、不执行；只能从白名单挑函数；理由必须引用候选证据；
LLM 不可用时规则 Agent 保住主线。

## 交付物

| 文件 | 内容 |
|---|---|
| `agent/rule_agent.py` | 类型 → 白名单函数 + 证据引用式理由 |
| `agent/llm_agent.py` | `DecisionLLM` 协议、`LLMAgent`、`ScriptedLLM`（不触网） |
| `container._build_agent` | `agent_mode=rule/llm` 的选择点（唯一） |

## 验收标准

| # | 判据 | 用例 |
|---|---|---|
| 1 | 规则 Agent 选中 `sqli_boolean_probe` 且理由含 claim | `test_rule_agent_decision` |
| 2 | 无匹配类型 → `AgentDecisionError` | `test_unknown_vuln_raises` |
| 3 | 自标低危但含 write/delete → 拒绝加载 | `test_low_risk_metadata_guard` |
| 4 | LLM 只能在白名单内选 | `test_llm_decision_uses_whitelisted_function` |
| 5 | LLM 跨类型选择 → 拒绝 | `test_llm_cannot_pick_function_outside_vuln_type` |
| 6 | LLM 输出非法 JSON → 拒绝 | `test_llm_illegal_json_is_rejected` |
| 7 | 无匹配函数时不调用 LLM | `test_no_matching_function_does_not_call_llm` |
| 8 | `agent_mode=llm` 未注入 provider → 构造期报错 | `test_llm_mode_requires_injected_provider` |

```powershell
python -m pytest tests/test_rule_agent.py tests/test_llm_agent.py -q     # 8 passed
```

## 未做/遗留

- **未接真实模型 API**（无网络/无 key 场景下的默认选择）；`decision_source=llm` 无生产记录；
- 无决策缓存（计划书 M3b 提到，未实现）；
- 规则 Agent 的理由是模板拼接，深度有限。
