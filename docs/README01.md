# WebVuln 平台 v0.1 —— 检测·决策·攻击·复核 四段闭环 MVP

基于 AI Agent 授权的 Web 漏洞自动检测和复核平台（课程项目，对应计划书 v1.1）。
初版按既定决策落地：**FastAPI + Vue3 前后端分离 / 规则 Agent（LLM 抽象可插拔）/
SQLi 单类全链路 / SQLite + 证据文件哈希链 / 完整角色账号体系 / 源码 + Docker 双交付**。

## 快速开始

```bash
# 1. 后端（Python 3.11+）
pip install -r requirements.txt
python -m webvuln.cli init-db
python -m webvuln.cli create-user -u admin    -p admin123  -r admin
python -m webvuln.cli create-user -u sub1     -p subpass1  -r submitter
python -m webvuln.cli create-user -u app1     -p apppass1  -r approver
python -m webvuln.cli create-user -u sig1     -p sigpass1  -r signer
python -m webvuln.cli serve              # API 文档 http://localhost:8000/docs

# 2. 前端（Node 20+）
cd frontend && npm install && npm run dev   # http://localhost:5173（代理至 8000）

# 3. 或一体化 Docker
docker compose up -d --build                # 前端 http://localhost:8080
docker compose --profile lab up -d dvwa     # 靶场 http://localhost:8081
```

## 默认角色与最小演示路径

| 角色 | 账号 | 能做什么 |
|---|---|---|
| admin | admin/admin123 | 建账号、兜底审批 |
| submitter | sub1/subpass1 | 注册目标、发起扫描 |
| approver | app1/apppass1 | 审批目标（双人审批第二人）、中危攻击审批 |
| signer | sig1/sigpass1 | 高危攻击审批、结论签署 |

演示：sub1 注册目标（勾"本地靶场"若用 DVWA）→ app1 批准 → sub1 扫描
→ 低危函数自动放行执行 → 结论 CONFIRMED → sig1 签署 → 导出报告 /
证据页回放哈希链。

## 架构与高内聚低耦合约定

```
Web 层(FastAPI) ──▶ Pipeline(四段闭环编排) ──▶ ┌ DetectorEngine ── SQLiDetector ─┐
        ▲              │ 证据逐段留痕            │ RuleAgent(决策,不执行)          │
        │              ▼                        │ AttackExecutor ── 白名单函数库   │
   Container(DI 组装根)                     所有出站请求 ──▶ EgressGateway(唯一网络出口)
        │              ▼                        └──────── 仅经 Transport 实现发包 ──┘
   SQLite(DB) ◀── FileEvidenceStore(JSONL 哈希链) ◀── Reporter(仅读汇总)
```

1. **契约唯一**：`webvuln/contracts/` 的抽象基类是模块间唯一依赖；具体实现互不可见。
2. **出口收敛**：`requests` 仅存在于 `container.RequestsTransport`；
   未注册目标在发包前即被 `EgressGateway` 拦截（有测试证明零发包），内网/保留地址默认拦截（SSRF 防护），本地靶场须注册时声明 + 审批人显式放行。
3. **可插拔**：新增漏洞 = `detector/` 加一个 `BaseDetector` 实现 + `attacker/attacks/` 加一个 `@register_attack` 函数（含风险元数据，高危特征自标低危会被运行期拒绝加载）。其余模块零改动。
4. **Agent 可替换**：实现 `contracts/agent.py` 的 `DecisionAgent`（如 LLM 版，`decision_source=llm`），在 `container.py` 换一行接线；LLM 不可用时规则 Agent 保证主线可用。

## 验收对照（计划书 2.3）

| 验收项 | 落点 |
|---|---|
| 可运行 | pip install 后 uvicorn 直接启动，无手工修补 |
| 可复现 | 证据快照回放一致（`/api/evidence/{scan_id}/chain` 重放校验）；活体重扫差异由证据层解释 |
| 可判定 | 结论状态机 CANDIDATE→ATTACKED→CONFIRMED/REJECTED/INCONCLUSIVE |
| 授权合规 | 双人审批（提交人≠审批人有服务层校验）、分级放行（低危自动/中高危人工）、审批必录理由 |
| 复核闭环 | Agent 自检理由引用候选证据 + 签署人签署（INCONCLUSIVE 不签署） |
| 可追溯 | 每条结论回溯到请求/响应/决策/审批证据，哈希链防篡改 |
| 出口管控 | 未注册目标零发包、越范围路径拦截、SSRF 地址段拦截（均有 pytest 用例） |

## 测试与指标

```bash
pytest -v          # 6 个文件：哈希链/出口管控/Agent 决策/元数据防线/状态机/API 角色门禁
```

- TP=CONFIRMED 数，FP=REJECTED 数，INCONCLUSIVE 单列，**FN 需靶场真值集**
  （`docker compose --profile lab up dvwa` 后按 eval 口径统计，当前如实标注为 null）。
- 指标口径与"负向实验结果"如实报告约定见计划书 5.1 / 6.2。

## 已知边界（v0.1 诚实声明）

- 证据原文未加密落盘（计划书 5.4 的增强点，当前为落盘+哈希链+访问留痕）；
- 预算数值已配置化（`config.py`：LLM 轮次/扫描时长/攻击条数上限），强制执行中断为后续项；
- 检测器仅 SQLi 一类（初版决策 Q4A：单类打通全链路）；
- 审批以角色+记录实现，未做审批超时升级与委托。

## 目录速览

```
webvuln/contracts/   接口契约（7 个抽象基类）
webvuln/{detector,agent,attacker,authz,evidence,report}/  各高内聚模块
webvuln/{pipeline,container}.py  闭环编排与 DI 组装根
webvuln/web/         FastAPI 路由 + stdlib JWT + 角色门禁
webvuln/cli.py       与 Web 同容器互证的命令行入口
frontend/            Vue3 + Vite（开发代理 /api → :8000）
tests/               pytest 用例（含 FakeTransport 模拟易受攻击端点）
```
