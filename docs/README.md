# 文档入口已迁移

本目录原有的 `README.md` 是与实际代码不符的早期模板（命令指向不存在的 `app` 包），
已于 v0.2.0 重写并移到**仓库根目录**：

- 安装与运行：见 [../README.md](../README.md)
- 六项交付完成情况：见 [COMPLETION.md](COMPLETION.md)
- 需求契约：见 [../brief/requirements.md](../brief/requirements.md)
- 接口/数据/行为规约：见 [../design/spec/](../design/spec/)
- 架构决策与调研：见 [../design/adr/](../design/adr/)

本目录保留的其它文档：

| 文件 | 说明 | 状态 |
|---|---|---|
| `Web漏洞检测工具项目计划书.md` | 课程计划书 v1.2（需求与验收的源头） | 有效 |
| `更新说明.md` | 两次功能更新的变更记录（反射型 XSS、离线模拟+可视化） | 有效 |
| `章节03对照审查记录.md` | 章节03 Evaluation/Observability 对照审查 | 有效；其中"本轮变更清单"已于 v0.2.0 补齐代码 |
| `README01.md` | v0.1 MVP 的交付说明（历史快照） | 历史存档，不代表当前状态 |
| `requirements.txt` | 依赖清单（已复制到仓库根，Dockerfile 用根部那份） | 冗余但无害 |

> 历史存档类文档不删除：它们是"版本演进"的证据；但**以根 README 与 `brief/`、`design/` 为准**。
