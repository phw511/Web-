# T-03 授权层：注册 / 双人审批 / SSRF / 唯一出口

- 状态：✅ done
- 归属阶段：M2
- 依赖：T-01、T-02
- 关联需求：F1、F4
- 关联测试：`tests/test_egress.py`（4 条）

## 目标

让"未授权目标零发包"成为**结构性保证**而非约定：检测/攻击模块没有网络原语，
所有出站必经 `EgressGateway`，且目标必须双人审批通过。

## 交付物

| 文件 | 内容 |
|---|---|
| `contracts/authz.py` | `Authorizer`、`AuthorizationError`、`ApprovalForbidden`、`EgressDenied` |
| `authz/service.py` | 注册、审批、拒绝、`assert_approval_allowed` |
| `authz/egress.py` | 唯一出口：注册/审批/有效期/范围/SSRF + `send` / `send_attack` |
| `contracts/transport.py`、`container.RequestsTransport` | 唯一允许 `requests` 的位置 |

## 验收标准

| # | 判据 | 用例 |
|---|---|---|
| 1 | 未注册目标 → `EgressDenied`，transport 请求列表为空 | `test_unregistered_target_zero_packets` |
| 2 | 越范围路径 → 拒绝 | `test_out_of_scope_path_blocked` |
| 3 | 内网地址未声明 → 拒绝；声明 + 审批 → 放行 | `test_private_ip_blocked_unless_flagged` |
| 4 | 提交人不能审批自己的目标 | `test_same_person_cannot_approve` |
| 5 | 授权 30 天过期后拒绝 | 代码路径（`expires_at` 比较），无用例 |

```powershell
python -m pytest tests/test_egress.py -q     # 4 passed
```

## 未做/遗留

- 用例 3 的"拒绝"分支实际由"目标未获批"先触发，**未真正覆盖 SSRF 分支**（测试强度不足，已登记）；
- DNS 重绑定窗口未彻底防御（见 ADR-0002 §5）；
- 无授权续期接口（只有重新注册/重审批的替代路径）。
