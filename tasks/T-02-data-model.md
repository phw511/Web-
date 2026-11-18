# T-02 数据模型与 SQLite 表结构

- 状态：✅ done
- 归属阶段：M1
- 依赖：T-01
- 关联需求：F9、F10
- 关联测试：`test_api_roles.py`（间接覆盖写入路径）、`test_state_machine.py`

## 目标

领域对象与持久化结构一致，表结构即契约，评审可一眼看完，不需要 ORM。

## 交付物

| 文件 | 内容 |
|---|---|
| `webvuln/models/schemas.py` | 9 个领域模型 + 5 个枚举 + `uid()`/`now_iso()` |
| `webvuln/db/database.py` | 9 张表的 `SCHEMA` + `execute/query/one` 三个方法 |

## 验收标准

1. 全新目录启动自动建表（`CREATE TABLE IF NOT EXISTS`）；
2. `attack_runs.decision_id` UNIQUE → 同一决策重复审批执行会失败；
3. `conclusions.candidate_id` UNIQUE → 同一候选不会产出两条结论；
4. `EvidenceRecord.app_version` 有默认值 `""`，旧证据仍可解析。

```powershell
python -m webvuln.cli init-db
python -m pytest tests/test_state_machine.py -q
```

## 未做/遗留

- 无迁移框架：加列需手工 `ALTER TABLE` 并记入本次变更（见 `design/spec/data-model.md` §6）；
- 无外键约束（SQLite 默认不启用 `PRAGMA foreign_keys`），一致性靠服务层。
