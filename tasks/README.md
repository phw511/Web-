# tasks/ — 任务分解规范与索引

## 1. 任务卡格式（每个 `T-xx.md` 必须包含）

```markdown
# T-xx 标题
- 状态：done / partial / todo
- 归属阶段：M1…M7
- 依赖：T-xx, …
- 关联需求：F1…F10
- 关联测试：tests/xxx.py::test_yyy

## 目标
一句话说清"做完之后能做什么"。

## 交付物
具体文件/命令/证据路径。

## 验收标准（可判定）
1. …（能跑的命令 + 期望输出）
2. …

## 未做/遗留
如实列出。
```

## 2. 任务索引

| 编号 | 任务 | 阶段 | 状态 | 关联测试 |
|---|---|---|---|---|
| T-01 | 项目骨架、配置与环境变量 | M1 | ✅ done | — |
| T-02 | 数据模型与 SQLite 表结构 | M1 | ✅ done | `test_api_roles.py`（间接） |
| T-03 | 授权层：注册/双人审批/SSRF/唯一出口 | M2 | ✅ done | `test_egress.py`（4） |
| T-04 | 检测器：SQLi / XSS / LFI | M2 | ✅ done | `test_detector_judgment.py`（7） |
| T-05 | Agent：规则决策 + LLM 可插拔 | M3b | ✅ done | `test_rule_agent.py`（3）、`test_llm_agent.py`（5） |
| T-06 | 攻击函数库与执行器（白名单 + 分级） | M3a | ✅ done | `test_state_machine.py`（部分） |
| T-07 | 证据层：哈希链 + manifest + 运行身份 | M5 | ✅ done | `test_hash_chain.py`（2）、`test_evidence_manifest.py`（4） |
| T-08 | 编排与预算四项强制 + 状态机 | M3a | ✅ done | `test_budget.py`（4）、`test_state_machine.py`（4） |
| T-09 | Web 层与前端四页 | M4 | ⚠️ partial | `test_api_roles.py`（2） |
| T-10 | 评测与交付（测试/证据/文档/回滚） | M6/M7 | ⚠️ partial | 全量 35 条 + `sim-demo` |

## 3. 任务拆分原则

1. **一个任务 = 一个可独立验收的能力**，不与"写文档"混在一起；
2. 每个任务必须至少关联一个测试或一条可运行命令，否则不算完成；
3. 任务的"未做"要写进 `## 未做/遗留`，并同步到 `docs/COMPLETION.md` 第 7 节；
4. 任务状态只有三种：`done` / `partial` / `todo`，禁止"基本完成"。
