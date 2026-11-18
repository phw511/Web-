# T-04 检测器：SQLi / XSS / LFI

- 状态：✅ done
- 归属阶段：M2
- 依赖：T-03
- 关联需求：F2
- 关联测试：`tests/test_detector_judgment.py`（7 条）

## 目标

命中已知漏洞响应、放过已知安全响应；判定依据写进 `claim`，可被人工核查。

## 交付物

| 文件 | 信号口径 | 保守策略 |
|---|---|---|
| `detector/sqli.py` | 数据库错误关键字 + 恒真/恒假长度差 >20% | 两者满足其一即候选 |
| `detector/xss.py` | 非执行型金丝雀 `wvxss7k<svg>` 原样反射 | 转义形态不报 |
| `detector/lfi.py` | 路径穿越后出现 `root:x:0:0:` 等特征 | 只读、单请求 |
| `detector/engine.py` | 按注册顺序调度 | 检测器不感知 Agent/攻击 |

## 验收标准（成对断言）

| 场景 | 期望 | 用例 |
|---|---|---|
| SQLi 错误型 | 命中 1 条 | `test_sqli_known_vulnerable_hit` |
| SQLi 正常响应 | 0 条 | `test_sqli_known_safe_no_false_positive` |
| SQLi 仅错误、无长度差 | 命中 | `test_sqli_error_only_without_boolean_still_hit` |
| XSS 未转义反射 | 命中 | `test_xss_unescaped_reflection_hit` |
| XSS 已转义 | 0 条 | `test_xss_escaped_reflection_no_hit` |
| LFI 读到 passwd | 命中 | `test_lfi_known_vulnerable_hit` |
| LFI 正常响应 | 0 条 | `test_lfi_known_safe_no_hit` |

```powershell
python -m pytest tests/test_detector_judgment.py -q     # 7 passed
```

## 未做/遗留

- 仅 3 类（IDOR、配置类未实现；无对应攻击函数时候选会挂起）；
- 阈值（20%）是经验值，未用真值集校准（依赖 M2 靶场）；
- 每参数会重复发基线请求（性能可优化，但会改变证据条数，需同步测试）。
