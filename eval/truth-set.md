# 真值集与 FN/TN 口径（eval/truth-set.md）

> **当前状态：未部署。** 因此本仓库所有地方（报告、API、前端）的 `FN` 都是 `null`，
> 不是 0。这是刻意的：`null` 表示"未度量"，`0` 表示"度量过且无漏报"，两者不能混。

## 1. 为什么需要真值集

TP/FP 可以用"平台自己的结论"算（CONFIRMED / REJECTED），但 **FN（漏报）必须知道"实际有多少漏洞"**。
没有 ground truth 就没有 FN，也不该硬编一个数字出来。

| 指标 | 定义 | 数据来源 | 当前 |
|---|---|---|---|
| TP | 检出且经攻击复验确认 | `conclusions.state = CONFIRMED` | ✅ 可算 |
| FP | 报错但实际不存在 | `conclusions.state = REJECTED` | ✅ 可算（但需人工确认） |
| INCONCLUSIVE | 证据不足 | 同上 | ✅ 单列 |
| **FN** | 实际存在但未检出 | **真值集** − 已检出 | ❌ `null` |
| **TN** | 实际不存在且未报 | 真值集里的安全项 | ❌ `null` |

## 2. 选型（M2 执行）

| 靶场 | 覆盖 | 部署 | 结论 |
|---|---|---|---|
| **DVWA**（`vulnerables/web-dvwa`） | SQLi / XSS / LFI / 文件包含 | 单容器，`docker compose --profile lab up -d dvwa` | **首选**：与现有 3 个检测器一一对应 |
| WebGoat | 更全（XXE、越权等） | 中 | 扩展 IDOR 时再引入 |
| vulhub | 真实 CVE 场景 | 高（按漏洞起容器） | 专项验证用，不适合当基线 |

## 3. 部署步骤（未执行，仅方案）

```powershell
docker compose --profile lab up -d dvwa       # 8081:80
# 首次进入 http://localhost:8081 完成安装，安全级别设为 low
# 在平台注册目标（必须 allow_private=True + 双人审批）
python -m webvuln.cli create-user -u sub1 -p subpass1 -r submitter
python -m webvuln.cli create-user -u app1 -p apppass1 -r approver
```

## 4. 真值表（待填）

| 编号 | 靶场 | 漏洞类型 | 入口 | 是否存在 | 平台结论 | 判定 |
|---|---|---|---|---|---|---|
| G-01 | DVWA | SQLi | `/vulnerabilities/sqli/?id=1` | 是 | 待跑 | — |
| G-02 | DVWA | XSS（reflected） | `/vulnerabilities/xss_r/?name=` | 是 | 待跑 | — |
| G-03 | DVWA | LFI | `/vulnerabilities/fi/?page=` | 是 | 待跑 | — |
| G-04 | DVWA | SQLi | `/vulnerabilities/sqli_blind/` | 是 | 待跑 | — |
| N-01 | DVWA | — | 首页 | 否 | 待跑 | 期望 0 候选 |

> 填表规则：`是否存在` 必须由**靶场源码/官方说明**确认，不能由平台结论反推（否则 FN 永远为 0）。

## 5. 计算方式

```
TP = 真值表"存在"且平台 CONFIRMED 的条数
FP = 真值表"不存在"但平台 CONFIRMED 的条数
FN = 真值表"存在"但平台未 CONFIRMED（漏报/REJECTED/INCONCLUSIVE）的条数
TN = 真值表"不存在"且平台未报的条数
```

精度 `P = TP/(TP+FP)`、召回 `R = TP/(TP+FN)`，两者都必须在报告里给出，不允许只报召回。

## 6. 未部署期间的报告口径

报告与 API 均输出：

```json
{"TP": 1, "FP": 0, "INCONCLUSIVE": 0, "PENDING": 0, "FN": null}
```

并在文案中注明"FN 需靶场真值集后统计"。**禁止**把 `FN` 写成 0 或省略该字段。

## 7. 验收

- [ ] DVWA 起得来且安全级别为 low
- [ ] 真值表 ≥ 4 条正例 + 2 条反例
- [ ] 报告 FN 从 `null` 变为数字，且同时记录靶场镜像版本
- [ ] `eval/` 下留存一次完整运行的 `report.json` 与 `chain.jsonl`
