# ADR-0003 目标注册的双人审批与 SSRF 拦截

- 状态：已采纳
- 日期：2026-11-11
- 关联需求：F1、F4；验收项"授权合规"

## 1. 背景

"仅对授权目标测试"如果只写在文档里，等于没写。平台必须让**越权在技术上不可能**，
至少要让"要用这个工具，必须先有一个第二人点过同意"成为硬流程。

## 2. 前置调研

| 方案 | 漏洞 | 结论 |
|---|---|---|
| 提交即可扫描 | 单人即可对任意 URL 发包，责任无法追溯 | ❌ |
| 提交 + 同一人确认 | 等于自审，"双人"名存实亡 | ❌ |
| **提交 + 不同角色第二人审批** | 需要两个账号，留 `submitted_by/approved_by` 双记录 | ✅ |
| 再加：审批带有效期 | 授权过期后自动失效，防"一次批准永久有效" | ✅ |

SSRF 维度：

| 方案 | 问题 |
|---|---|
| 只在注册时校验 IP | 攻击者可用域名解析到内网绕过 |
| **注册 + 每次发包前都校验** | 成本低（一次 `getaddrinfo`），能挡住大部分内网探测 | ✅ |
| 白名单域名 | 对课程靶场不现实 |

## 3. 决策

1. `submit_target` 记录 `submitted_by`；
2. `approve_target` 强制 `submitted_by != actor`，否则 `AuthorizationError`；
3. 审批写入 `approved_by/approved_at/expires_at`（默认 30 天）；
4. 内网/保留地址：注册时 `allow_private=True` **且** 审批时 `allow_private=True` 才放行；
5. 每次出站前重新解析 IP 并校验（`EgressGateway.check`）。

## 4. 后果

**正面**

- 单人无法自建自批（服务层拦截，不只前端）；
- 内网靶场（DVWA）可以测，但必须显式两次声明 + 留痕；
- 授权过期后自动拒绝，`EgressDenied("目标授权已过期")`。

**负面**

- 演示需要两个账号，比"一键跑"麻烦；
- 每次请求多一次 DNS 解析；
- `allow_private` 一旦置 1，该目标后续所有请求都放行内网 → 依赖审批时的谨慎（记录在案）。

## 5. 验证方式

```powershell
python -m pytest tests/test_egress.py -q      # 含 same_person_cannot_approve、private_ip_blocked
python -m pytest tests/test_api_roles.py -q   # 含 403 角色门禁
```

> 注：`test_egress.py::test_private_ip_blocked_unless_flagged` 的第一段
> 因目标尚未审批，会在"目标未获批"处就抛错——它能通过，但**并未真正覆盖 SSRF 分支**。
> 这是已知的测试强度不足，已在 `docs/COMPLETION.md` 的待办里登记。
