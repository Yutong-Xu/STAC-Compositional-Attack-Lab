# 正常轨迹驱动的两组实验（2026-11-03）

目标：先执行一个无攻击的正常任务，保存真实轨迹并审核原语证据，再比较正常轨迹组与正常轨迹加原语组。初始输入不提供完整成功攻击范例。两组共享任务、影响目标、修改权限、模型、预算和正常轨迹。相同或相似攻击不跳过执行。

## 当前实现

新增 `attack_program/trajectory_pair.py`，独立于旧三臂 campaign，旧批次行为保持原样。提供：

- `prepare(baseline, settings)`：检查正常任务完成声明、公开视图审核声明、事件唯一身份与顺序、标注引用和审核状态，生成两组输入及哈希。只凭模型自述的标注拒绝准入。
- `execution_slots(plan, candidates)`：校验计划哈希、候选修改位置与长度；两组即使 patch 完全相同也产生两个待执行位置，并记录相同标记。
- CLI 只写默认禁用的计划，不调用模型，不执行候选，不覆盖已有输出。

这是离线准备层，不是已经完成真实实验。`public_review=approved` 与 `review_status=verified` 是外部审核记录的输入声明；当前代码只能检查引用和字段一致性，不能自动证明标注语义正确、没有攻击或材料已经脱敏。不得把自行填写这些字段当成完成审核。真实输入接入前，还需绑定原始轨迹、审核记录及公开投影的文件指纹，并接入现有敏感内容扫描。

## 输入格式

baseline 使用 `benign-trajectory/1`：task_id、public_task、scope（synthetic 或 real_development）、attack_present=false、task_completed=true、initial_snapshot_sha256、public_review、public_events、annotations。

事件至少包含 event_id、递增且唯一的 sequence、kind 与公开的事件描述。标注包含 primitive、evidence_refs、review_status、rationale。九类原语定义在模块内；未标注的原语不意味着失败或未发生。当前接收经过人工审核的标注，不自动把任意工具调用推断为持久化、语义采用或执行成功。

settings 包含 attack_goal、allowed_surfaces（每项 pointer/max_chars）、planner_model、victim_model、planner_request_limit、victim_request_limit、seed。两组只改变 primitive_definitions 和 primitive_annotations。保留原始轨迹可避免把新增轨迹信息的作用误归因于原语。

```bash
PYTHONPATH=src python -m stac_attack_lab.attack_program.trajectory_pair \
  --baseline reviewed-baseline.json --settings pair-settings.json --output new-pair-plan.json
PYTHONPATH=src python -m pytest -q tests/integration/test_trajectory_pair.py
```

## 下一步运行适配

1. 明确一个真正的无攻击任务版本，去掉攻击载荷但保留正常任务语义；不能把原始对抗 benchmark 任务直接称作良性基线。
2. 运行正常任务，保存工具事件、响应、状态前后快照及正常任务完成检查；标注每个原语引用的证据，缺证据保留 unknown。
3. 给两组分别一次生成机会，复用现有模型边界、敏感值扫描和请求账本。生成失败、弃权保留分母。
4. 在两个独立环境恢复同一初始快照，核查实际快照指纹与独立记忆/工具状态，再执行各组候选。prepared slot 本身不证明隔离成功。
5. 报告每组是否实际执行、攻击是否成功、官方分数、正常任务完成情况和证据支持的行为偏离；单对案例先报告成败，不能推断稳定成功率。事件先后关系不等于因果关系。

真实基线 runner、自动原语提议及审核工作流、Planner/Victim 适配、配对结果报告尚未完成。当前没有新增真实请求或复用历史批次授权。
