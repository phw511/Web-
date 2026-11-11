# ADR-0001 技术栈选型：Python + FastAPI + Vue3 + SQLite + 标准库 JWT

- 状态：已采纳（v0.1.0 定案，v0.2.0 复核仍成立）
- 日期：2026-11-11（重写归档）
- 影响范围：全局

## 1. 背景

课程环境要求"干净环境按文档可启动、无手工修补"，同时不允许依赖外部 SaaS。
需要在"实现成本 / 可评审性 / 依赖体积"三者间取舍，且项目本身要演示"安全工具"，
不适合引入一大堆第三方库来增加审计面。

## 2. 前置调研（备选对比）

### 2.1 Web 框架

| 方案 | 优点 | 缺点 | 结论 |
|---|---|---|---|
| **FastAPI** | 自动 OpenAPI（`/docs` 直接可评审）、依赖注入、pydantic 校验 | 需 uvicorn | ✅ 采用 |
| Flask | 轻、文档多 | 无内建校验/文档，角色门禁用装饰器拼装易漏 | ❌ |
| Django | 自带 admin/ORM/鉴权 | 太重，ORM 与"契约即表结构"的评审口径冲突 | ❌ |

### 2.2 存储

| 方案 | 优点 | 缺点 | 结论 |
|---|---|---|---|
| **SQLite（stdlib）** | 零部署、单文件、可随证据一起交付 | 并发写弱（本项目单进程够用） | ✅ 采用 |
| PostgreSQL | 强一致、并发好 | 要起服务，违反"干净环境可启动" | ❌ |
| JSON 文件 | 最简单 | 查询/关联差，指标统计难 | ❌（仅用于证据链，见 ADR-0004） |

### 2.3 鉴权

| 方案 | 优点 | 缺点 | 结论 |
|---|---|---|---|
| **stdlib PBKDF2 + HS256 JWT（手写 ~90 行）** | 零依赖、算法透明、可逐行评审 | 需自己对时序攻击用 `compare_digest` | ✅ 采用 |
| PyJWT | 省事 | 多一个依赖，且默认算法需额外约束 | ❌ |
| session + cookie | 简单 | 前后端分离下跨域麻烦 | ❌ |

### 2.4 前端

| 方案 | 结论 |
|---|---|
| **Vue3 + Vite**：构建快、单文件组件、模板直观 | ✅ |
| React：生态更大但样板多，本项目界面简单 | ❌ |

## 3. 决策

Python 3.10+ / FastAPI + uvicorn / pydantic v2 / SQLite（stdlib）/ 手写 HS256 JWT + PBKDF2 / Vue3 + Vite。
运行期依赖仅 4 个，测试另加 pytest + httpx。

## 4. 后果

**正面**

- `pip install -r requirements.txt` 后即可启动，无外部服务；
- 表结构直接内联在 `db/database.py`，评审时可一眼看完；
- 依赖少 → 供应链与审计面小（对一个安全工具很重要）。

**负面 / 代价**

- 手写 JWT 需要自己保证 `hmac.compare_digest`、过期校验（已做，见 `web/security.py`）；
- SQLite 并发写弱，扫描与审批并发时可能 `database is locked`（当前单进程场景未触发）；
- 无 ORM → 改表要手工写迁移（见 `design/spec/data-model.md` §6）。

## 5. 验证方式

- `python -m webvuln.cli serve` 后访问 `/docs` 能看到全部端点；
- `tests/test_api_roles.py` 覆盖登录与角色门禁；
- 本机实测：`python -m venv .venv` + `pip install -r requirements.txt` 一次装完（35 个包），
  `pytest -q` → **35 passed**。
