# 发布与回滚（release/rollback.md）

> 验收项"可回滚"的落地口径：**旧版本能干净启动，历史证据能恢复并通过 `verify()`**。
> 现状：流程已定义；本仓库交付时**没有 `.git` 目录**，所以第 0 步必须先初始化版本库。

## 1. 版本记录

| 版本 | 内容 | 证据 |
|---|---|---|
| 0.1.0 | 四段闭环 MVP（SQLi 单类）、双人审批、哈希链、Web/CLI | `docs/README01.md` |
| 0.2.0 | 预算四项强制、app_version、manifest 逐条索引、审批角色下沉、LLM 骨架 | `eval/evidence-2026-11-11.md` |

## 2. 第一次发布（初始化版本库）

```powershell
cd C:\Users\Lenovo\Desktop\Web--main

git init
git add .
git commit -m "chore: v0.2.0 baseline (35 tests passed, sim-demo finished)"
git tag -a v0.2.0 -m "v0.2.0: budget guard + app_version + manifest index"

# 可选：推到远端
git remote add origin <repo-url>
git push -u origin main --tags
```

> 提交前确认 `.gitignore` 已忽略 `data/`、`evidence/`、`sim_out/`、`.venv/`、`node_modules/`，
> 避免把运行产物和虚拟环境提交进去。

## 3. 日常发布流程

```powershell
git checkout -b release/0.3.0
# … 改动 …
.\.venv\Scripts\python.exe -m pytest -q          # 必须全绿
.\.venv\Scripts\python.exe -m webvuln.cli sim-demo --out .\sim_out
# 更新 docs/COMPLETION.md 与 eval/evidence-<日期>.md
git commit -am "release: 0.3.0"
git tag -a v0.3.0 -m "v0.3.0"
```

**发布门（缺一不可）**

- [ ] `pytest -q` 全绿，输出已贴进 `eval/evidence-<日期>.md`
- [ ] `sim-demo` 跑通（status=finished）
- [ ] `docs/COMPLETION.md` 的"未完成项"已更新
- [ ] 版本号三处一致：`webvuln/__init__.py`、`webvuln/config.py`、`frontend/package.json`
- [ ] 无新增未评审依赖

## 4. 回滚

### 4.1 代码回滚（保留历史）

```powershell
git checkout v0.2.0                     # 临时查看/验证旧版本
# 或：另开分支基于旧 tag 修复
git switch -c hotfix/from-0.2.0 v0.2.0
```

### 4.2 撤销某次提交（推荐，保留审计轨迹）

```powershell
git revert <commit>
```

> 不要用 `git reset --hard` 推送到共享分支——会抹掉历史，与"可追溯"原则冲突。

## 5. 证据恢复验证（"历史证据可恢复"的机器断言）

```powershell
# 1) 备份当前证据目录
Copy-Item .\evidence -Destination .\evidence-backup-20261111 -Recurse

# 2) 恢复到"新目录"，模拟换机/迁移
Copy-Item .\evidence-backup-20261111 -Destination .\evidence-restored -Recurse

# 3) 用恢复后的目录校验（不改代码，只改配置）
$env:WEBVULN_EVIDENCE_DIR=".\evidence-restored"
.\.venv\Scripts\python.exe -m webvuln.cli verify-evidence
# 期望："verified": true，且 record_count 与原目录一致
```

**判定标准**：`manifest.verified == true` 且 `record_count` 不变 → 证据可恢复。
若为 `false`，说明备份/恢复过程破坏了链（例如用了会改换行符的工具），需重来。

## 6. 数据（SQLite）回滚

- SQLite 是索引层，真身是 `chain.jsonl`；**证据链优先恢复**；
- 若 DB 与证据不一致：以证据为准，删 `data/app.db` 与 `evidence/evidence_index` 重建即可
  （代价：失去 SQL 查询索引，但证据本身完整）；
- 破坏性 schema 变更必须写迁移脚本 + 在此处记录回退语句。

## 7. 已知限制

- 未做自动化回滚脚本（`scripts/` 下暂无 `rollback.ps1`）；
- 回滚演练未在 CI 中执行，靠人工按本文操作；
- 证据链是全局单文件：若跨版本追加，旧版本程序也能读（`app_version` 为空不入哈希），
  但**旧版本程序不认识新 kind**（如 `budget_exceeded`）——读取时不报错，只是不解读。
