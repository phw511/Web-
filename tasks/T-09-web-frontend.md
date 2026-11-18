# T-09 Web 层与前端四页

- 状态：⚠️ partial（页面可用；F8 图表未做）
- 归属阶段：M4
- 依赖：T-08
- 关联需求：F7（完成）、F8（部分）
- 关联测试：`tests/test_api_roles.py`（2）

## 目标

四页可用：目标配置/审批、发起扫描与签署、审批单、证据回放；角色门禁在后端强制。

## 交付物

| 层 | 文件 |
|---|---|
| 后端 | `web/app.py`、`web/deps.py`、`web/security.py`（JWT+PBKDF2）、`web/routers/{auth,targets,scans,approvals,conclusions,evidence,reports}.py` |
| 前端 | `App.vue`（导航+样式）、`main.js`（路由+登录守卫）、`api.js`（统一请求）、`views/{Login,Targets,Scans,Approvals,Evidence}.vue` |

## 验收标准

| # | 判据 | 用例/命令 |
|---|---|---|
| 1 | 登录失败 401、成功返回 token+role | `test_login_and_dual_approval` |
| 2 | submitter 审批目标 → 403 | 同上 |
| 3 | 扫描→报告→签署全流程 | `test_scan_report_sign_flow` |
| 4 | 报告 MD 含 `TP=1` | 同上 |
| 5 | `/api/stats` 与报告口径一致 | 同上 |

```powershell
python -m pytest tests/test_api_roles.py -q     # 2 passed
```

## 未做/遗留

- **F8 图表（类型分布/严重度/交互筛选）未实现**，只有表格与状态徽标；
- 前端 401 只做清 token + 跳登录，无静默续期；
- 审批理由用 `prompt()` 采集，UI 观感一般；
- 无 E2E 前端测试（仅后端 API 层）。
