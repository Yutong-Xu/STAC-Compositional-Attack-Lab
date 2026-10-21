# 代码恢复、验证与仓库迁移（2026-10-21）

## 本版本是什么

本版本基于 [Scaramcci/STAC-Compositional-Attack-Lab](https://github.com/Scaramcci/STAC-Compositional-Attack-Lab) 的代码和文档，包含 2026-10-14 在服务器重新实现的修复及功能。原作者归属保留；新仓库没有新增开放许可。

- 基础源码：上游 `6b252464743e72fe9b12b762e24c05b700a0625c` 中的 `src/`、`tests/`、`scripts/`。
- 配置和文档基础：上游 `dd60a716025f85b53b06cebfbbd6ad5003da6476`，以及本地保存的后续实施记录。
- 补写功能：Planner 字段保护、HTTP 诊断、预览去重、R4 预算与 usage 处理、19–24 编排入口、审计和报告。详见 [10 月 14 日实现说明](SERVER_REIMPLEMENTATION_20261014.md)。
- 10 月 21 日检查时，原服务器补写目录不存在。当前版本通过此前会话中保存的源码编辑记录重建，并在独立目录验证。没有找到原作者未提交的 10 月 5 日源码，也不声称恢复了它。

新仓库使用独立 Git 历史；初始源码快照为 `c65737d`。原仓库及旧服务器副本没有被覆盖。会话日志、恢复脚本、API 凭证、虚拟环境、上游 checkout、历史实验原始数据和冻结库不随新仓库发布。

## 验证状态

必须区分历史验证与本次重建的验证：

| 检查 | 结果与限制 |
|---|---|
| 10 月 14 日完整回归 | 历史记录为 158 passed、3 skipped；属于当时服务器实现，不能直接算作本次重建通过 |
| 10 月 21 日静态检查 | 重建后 Ruff check、Ruff format --check 与服务器 mypy（34 个源文件）通过 |
| 10 月 21 日服务器回归 | 初始化新 Git 历史后重跑，停止时为 76 passed、3 errors；尚未完成完整回归 |
| 剩余错误原因 | 测试准备的 SafeClawArena 是指向项目外的符号链接，被 R4 的源码位置校验拒绝；需要改为项目内独立 checkout 后重跑 |
| 后续重试 | SSH 隧道连接超时，独立 checkout 与最终回归未确认执行，不能记为通过 |
| Windows 本地测试 | Linux 的 `fcntl` 模块不可用，不能作为 Windows 完整运行支持的证明 |
| 真实模型/API | 本次恢复没有启动真实模型请求；没有重跑历史真实实验 |

历史真实 fixture 未随源码发布，相关 3 项测试会跳过；跳过不等于通过。历史文档中的批次结果、执行授权、机器路径和“未提交”等描述只对应记录当时，不能视为新仓库当前状态。部分历史设计文档与实验文件未恢复，旧文档引用可能不可用。

## Linux 环境与离线运行

需要 Python 3.11+、Git、Bash。安装项目依赖后，将 SafeClawArena 的完整 Git checkout 放在本项目内部；不要用指向项目外的符号链接。固定上游版本为 `a11f5cceaba0676be721021f8d232638fd111305`。

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
mkdir -p integrations/safeclaw/upstream
# 仅在目标不存在时执行 clone；不要覆盖已有目录。
git clone https://github.com/sunblaze-ucb/SafeClawArena.git \
  integrations/safeclaw/upstream/SafeClawArena
git -C integrations/safeclaw/upstream/SafeClawArena checkout --detach \
  a11f5cceaba0676be721021f8d232638fd111305
make check PYTHON=python
```

零模型请求的编排演示使用全新输出目录：

```bash
PYTHONPATH=src python -m stac_attack_lab.attack_program.campaign_cli \
  --kind repeated demo \
  --output "experiments/runs/recovered-demo-$(date +%Y%m%d-%H%M%S)-$$"
```

不加 `--docker` 时使用 scripted 演示，不需要模型 API key。示例是后续可执行命令，不表示本次已经运行。真实运行仍须单独配置和授权，历史授权不自动延续。
