# 代码规范（docs/conventions/code-style.md）

## 1. 分层与依赖

| 层 | 允许 import | 禁止 import |
|---|---|---|
| `contracts/` | 标准库、`models/schemas` | 任何实现、任何第三方 |
| `models/` | 标准库、pydantic | 任何其它项目模块 |
| `detector/`、`attacker/attacks/` | `contracts/`、`models/` | `requests`、`socket`、`pipeline`、`web` |
| `authz/`、`budget/`、`evidence/`、`report/` | `contracts/`、`models/`、`db/` | `web/`、`detector/` |
| `pipeline.py` | `contracts/`、`models/`、`db/` | 任何具体实现（detector/agent/attacker 的具体类） |
| `container.py` | 全部（组装根，唯一例外） | — |
| `web/` | `container`、`contracts`、`models` | — |

违反以上任一行的 import，评审直接打回。

## 2. 命名

| 对象 | 规则 | 例 |
|---|---|---|
| 模块 | 小写下划线 | `rule_agent.py` |
| 类 | PascalCase | `AttackExecutor` |
| 契约抽象 | 名词，不加 `I`/`Base` 前缀（除 `BaseDetector` 历史命名） | `Authorizer`、`Transport` |
| 实现 | 抽象名 + 具体限定 | `RequestsTransport`、`FileEvidenceStore` |
| 常量 | UPPER_SNAKE | `DIFF_THRESHOLD`、`KIND_TIME` |
| 证据 kind | 小写下划线 | `budget_exceeded` |

## 3. 函数与异常

- 单个函数 ≤ 60 行；超过就拆私有方法（`_check_time`、`_save_decision`）；
- 一个函数只做一件事：`run_scan` 只编排，判定规则放 `BudgetGuard`/`AuthorizerService`；
- 异常必须带**可读中文原因**，且区分"用户错误"与"系统错误"：

| 场景 | 异常 | HTTP |
|---|---|---|
| 未授权/未注册/过期 | `EgressDenied` | — |
| 业务规则不允许（自审、重复执行、INCONCLUSIVE 签署） | `AuthorizationError` | 400 |
| 审批角色不足 | `ApprovalForbidden`（`AuthorizationError` 子类） | 403 |
| 预算超限 | `BudgetExceeded`（带 `kind`） | 视 kind 上抛 |
| 找不到记录 | `ValueError` | 400 |

- 禁止裸 `except:`；捕获后必须有注释说明"为什么可以继续"（如检测器里的网络异常 → 该参数跳过）。

## 4. 注释与文档字符串

- 模块顶部 docstring 写**职责边界 + 不可违反的约束**（例：`egress.py` 写"所有出站必经此类"）；
- 内部注释解释**为什么**，不复述代码（"先校验再记账，因为被授权拦下的请求不该消耗预算"）；
- 任何"看起来奇怪"的顺序（先写证据后改 DB）必须留一句理由。

## 5. 类型与数据

- 跨层数据只用 `models/schemas.py` 的 pydantic 模型，禁止传裸 dict 当契约；
- 新增字段必须有默认值（保证旧数据/旧调用可用），例：`HttpSpec.context = "probe"`；
- 可空的"数量/指标"用 `None` 表示"未度量"，不用 `0`（FN 的口径就是这条）。

## 6. 前端

- 组件只做展示与调用 API，不写业务判定（角色可见性只是"别让人白点"，后端必须再校验）；
- 错误提示优先显示后端 `detail`，不要只显示状态码；
- 不引入重型 UI 框架；样式沿用 `App.vue` 的极简约定。

## 7. 文件与编码

- Python/Vue/Markdown 一律 UTF-8；
- **`.cmd` / `.ps1` 一律只用 ASCII**（`cmd.exe` 按 OEM 代码页解析、PS 5.1 无 BOM 按 ANSI 读，
  中文会把整行拆坏——本项目已踩过这个坑）；
- 行宽 100 字符以内，缩进 4 空格（Python）/ 2 空格（JS、Vue）。
