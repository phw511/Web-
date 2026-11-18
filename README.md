# 基于 AI Agent 授权的 Web 漏洞自动检测与复核平台

> 对**已授权目标**自动检测 Web 漏洞 → AI Agent 从白名单攻击函数库中挑选"验证型模拟攻击"完成复核 → 人工签署形成可追溯、可追责的结论。
> 课程项目 · Python 3.10+ · 版本 **0.2.0**

| 项 | 现状 |
|---|---|
| 自动化测试 | **35 passed / 9 个文件**（2026-11-11 实测，耗时 11.96s） |
| 离线闭环演示 | `sim-demo` 跑通：candidates=2、auto_executed=2、status=finished（TP=2） |
| 预算四项强制 | 已实现并有 4 条自动化用例（时长/轮次/请求数/并发） |
| 证据链 | append-only JSONL + SHA-256 哈希链 + 逐条 manifest 索引 |
| AI Agent | 规则 Agent 为默认；LLM Agent 为可插拔实现（**未接真实模型 API**） |

---

## 一、快速开始（Windows，本机实测命令）

```powershell
cd C:\Users\Lenovo\Desktop\Web--main

# 1) 建虚拟环境（若本机 python 不在 PATH，可用任意 3.10+ 解释器创建）
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

# 2) 语法检查 + 全量测试
.\.venv\Scripts\python.exe -m compileall -q webvuln tests
.\.venv\Scripts\python.exe -m pytest -q          # 期望：35 passed

# 3) 离线闭环演示（不触网，产出可视化报告 + 证据链）
.\.venv\Scripts\python.exe -m webvuln.cli sim-demo --out .\sim_out
```

Linux / macOS 把 `.\.venv\Scripts\python.exe` 换成 `.venv/bin/python` 即可。

> `scripts\verify.cmd` = 上面 2)+3) 的一键版；`scripts\apply-upgrade.cmd` 用于把补丁层合并覆盖到项目。
> 四个脚本**刻意只用 ASCII**：`cmd.exe` 按 OEM 代码页解析批处理，`.ps1` 在 PowerShell 5.1 下无 BOM 按 ANSI 读，写中文会把行拆坏。

## 二、三种入口（产物一致，互为复现证据）

```powershell
# A. 命令行
python -m webvuln.cli init-db
python -m webvuln.cli create-user -u admin -p admin123 -r admin
python -m webvuln.cli scan --target <target_id> --user admin
python -m webvuln.cli replay --scan <scan_id>
python -m webvuln.cli report --scan <scan_id> --format md
python -m webvuln.cli verify-evidence          # 打印证据链 manifest

# B. Web（FastAPI，API 文档在 /docs）
python -m webvuln.cli serve                    # http://localhost:8000

# C. 前端（Vue3 + Vite，代理 /api → :8000）
cd frontend && npm install && npm run dev      # http://localhost:5173

# D. 一体化 Docker
docker compose up -d --build                   # 前端 http://localhost:8080
docker compose --profile lab up -d dvwa        # 靶场 http://localhost:8081（未部署默认禁用）
```

## 三、默认角色与最小演示路径

| 角色 | 账号（示例） | 能做什么 |
|---|---|---|
| admin | admin/admin123 | 建账号、兜底审批 |
| submitter | sub1/subpass1 | 注册目标、发起扫描 |
| approver | app1/apppass1 | 审批目标（双人审批的第二人）、**中危**攻击审批 |
| signer | sig1/sigpass1 | **高危**攻击审批、结论签署 |

路径：sub1 注册目标 → app1 批准 → sub1 扫描 → 低危函数由 Agent 自动放行执行
→ 中高危进审批单（app1/sig1 按风险级别处理）→ 结论 CONFIRMED → sig1 签署
→ 导出报告 / 证据页回放哈希链。

## 四、架构（依赖方向单向，契约唯一）

```
Web(FastAPI) ─▶ Pipeline(四段闭环编排) ─▶ ┌ DetectorEngine ─ 检测器
     ▲              │ 证据逐段留痕          │ DecisionAgent（规则 / LLM 可插拔）
     │              ▼                        │ AttackExecutor ─ 白名单attack函数
 Container(DI 组装根)                    └ 所有出站请求 ─▶ EgressGateway（唯一网络出口）
     │              ▼
 SQLite ◀── FileEvidenceStore(JSONL 哈希链) ◀── Reporter(只读汇总)

 BudgetGuard：时长/轮次 → Pipeline；攻击请求数 → EgressGateway；并发 → AttackExecutor
```

1. **契约唯一**：模块间只依赖 `webvuln/contracts/` 的抽象与 `models/schemas.py` 的模型。
2. **出口收敛**：`requests` 只存在于 `container.RequestsTransport`；未注册目标在发包前拦截。
3. **可插拔**：新增漏洞 = `detector/` 加一个检测器 + `attacker/attacks/` 加一个 `@register_attack` 函数，其余模块零改动；缺攻击函数时该候选**挂起**而不是崩扫描。
4. **Agent 可替换**：实现 `contracts.agent.DecisionAgent` 即可；规则 Agent 保证 LLM 不可用时主线可用。

## 五、测试与指标

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

| 测试文件 | 覆盖内容 | 用例数 |
|---|---|---|
| `test_api_roles.py` | 登录、双人审批、扫描→报告→签署全流程、角色门禁 | 2 |
| `test_budget.py` | 预算四项强制执行（时长/轮次/请求数/并发） | 4 |
| `test_detector_judgment.py` | 检测器判定自测：已知安全不误报、已知漏洞必命中 | 7 |
| `test_egress.py` | 未注册零发包、越范围拦截、SSRF、自审拦截 | 4 |
| `test_evidence_manifest.py` | 运行身份 app_version、manifest 逐条索引、篡改检测 | 4 |
| `test_hash_chain.py` | 哈希链追加与篡改检测 | 2 |
| `test_llm_agent.py` | LLM 只能选白名单函数、非法 JSON 拒绝、无函数不调用 | 5 |
| `test_rule_agent.py` | 规则决策、未知类型、元数据降级防线 | 3 |
| `test_state_machine.py` | 端到端状态机、负样本、签署与不可签署 | 4 |
| **合计** | | **35** |

指标口径：TP=CONFIRMED，FP=REJECTED，INCONCLUSIVE 单列；**FN 需要靶场真值集**，当前如实标注为 `null`（见 `eval/truth-set.md`）。

## 六、目录

```
brief/      需求契约（F1–F10、范围/反例、验收项↔测试对照）
design/     规约（contracts / data-model / behavior）+ ADR（含前置调研）
auth/       授权注册与审批记录（运行时落 data/，导出见 manifest）
eval/       判定标准、真值集说明、真实运行证据
evidence/   运行证据（chain.jsonl + manifest，运行时生成）
release/    发布与回滚（git tag 流程、证据恢复验证）
review/     互评、变更记录、签署
webvuln/    源码（契约、检测、决策、授权、攻击、证据、报告、Web）
frontend/   Vue3 界面
tests/      pytest（9 文件 35 用例）
scripts/    verify.cmd / verify.ps1 / apply-upgrade.*
```

## 七、已知边界（诚实声明）

1. **LLM Agent 未接真实模型 API**：`LLMAgent` 与 `DecisionLLM` 协议已就绪，测试用不触网的 `ScriptedLLM`；接入只需传 `llm_provider`。
2. **靶场真值集未部署**：FN/TN 无法计算，报告如实写 `null`，不编造指标。
3. **证据原文未加密**：当前为落盘 + 哈希链 + 访问留痕（计划书 M5 增强项）。
4. **签署未做密钥签名**：manifest 预留 `signature: null` 字段。
5. **检测器仅 SQLi / XSS / LFI 三类**：IDOR、配置类为规划中（无对应攻击函数时候选会挂起并留痕）。
6. **前端未做图表可视化**：表格 + 状态徽标 + 导出 MD/HTML（F8 的图表为后续项）。

## 八、安全与合规

仅用于**已获得书面授权**的目标。平台内置三重约束：目标注册须双人审批、出站请求唯一出口校验、内网/保留地址默认拦截（本地靶场须显式声明并经审批）。
越权使用造成的一切后果由使用者承担。

## License

MIT
