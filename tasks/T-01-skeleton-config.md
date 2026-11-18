# T-01 项目骨架、配置与环境变量

- 状态：✅ done
- 归属阶段：M1
- 依赖：无
- 关联需求：可运行验收
- 关联测试：`sim-demo` 冒烟 + `python -m compileall`

## 目标

干净环境一条命令装依赖、一个模块入口能启动，配置全部支持环境变量覆盖，无需改代码。

## 交付物

| 文件 | 说明 |
|---|---|
| `requirements.txt` | 运行期 4 依赖 + 测试 2 依赖 |
| `webvuln/config.py` | `Settings` dataclass + `load_settings()`（9 个环境变量） |
| `webvuln/container.py` | DI 组装根（唯一允许 import 全部实现的地方） |
| `webvuln/__init__.py` | `__version__ = "0.2.0"` |
| `Dockerfile.backend` / `docker-compose.yml` | 容器化启动 |

## 验收标准

```powershell
python -m pip install -r requirements.txt      # 应一次装完
python -m compileall -q webvuln tests          # 无语法错误
$env:WEBVULN_APP_VERSION="9.9.9"; python -m webvuln.cli verify-evidence   # manifest 顶层体现版本
```

环境变量清单：`WEBVULN_DB_PATH`、`WEBVULN_EVIDENCE_DIR`、`WEBVULN_JWT_SECRET`、
`WEBVULN_JWT_TTL`、`WEBVULN_HTTP_TIMEOUT`、`WEBVULN_APP_VERSION`、`WEBVULN_AGENT_MODE`、
`WEBVULN_LLM_ROUNDS`、`WEBVULN_SCAN_TIMEOUT`、`WEBVULN_MAX_ATTACK_REQUESTS`、`WEBVULN_MAX_CONCURRENCY`。

## 未做/遗留

- 无 `.env` 文件加载（计划书 README 曾提到，实际未实现，已在根 README 删除该段）；
- Docker 镜像未固定 digest（可复现性弱）。
