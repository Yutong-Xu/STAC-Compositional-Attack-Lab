# 服务器代码补写与验证（2026-10-14）

## 范围与版本

用户要求只在服务器修改和测试，不更新Git，同时自行找回10.5原代码。
目标：/home/kunyuan/snap/Zky_Agent_Attack/STAC-Compositional-Attack-Lab。
HEAD仍为dd60a716025f85b53b06cebfbbd6ad5003da6476，未add/commit/push/pull/reset/clean。
本地Windows仓库未同步新修改，另一份服务器项目未修改。

以9.30的6b25246恢复代码为基础，依据现存10.5文档重新实现；不是找回原始10.5文件。
不声称逐字兼容历史脚本接口或旧运行快照。
原文件备份：experiments/runs/server-reimplementation-20261014-v1/before.tar.gz，
不含.env、虚拟环境、上游checkout或实验原始数据。

## 功能对应

| 文档要求 | 本轮服务器实现 |
|---|---|
| 遗留质量问题 | 修复诊断usage类型/缺失语义、格式和行长；18入口由伪装成.py的Bash改为Python，另留.sh包装 |
| R4新预算 | 显式Victim最多24、session最高720秒、episode最高1800秒；旧默认12/360/900保留；embedding默认禁用 |
| schema | measurement_relation为对象；embedding三个环境名默认值与10.5 schema一致；R3输出最高32768 |
| 来源/使用量 | sim-google TSV多行正文校验；usage缺失保持unknown；runtime_review输出来源、会话、文件版本、usage、cleanup及范围 |
| 真实开发预览 | 每条导入重新校验来源与审计；真实开发不标synthetic；重复测量保留分母，相同内容不重复计样本 |
| Planner诊断 | 有界JSON/字段扫描、重复键/深度/节点限制、字段名匿名、整包及解码规则计数；usage仅留数值 |
| 响应保护 | 精确凭证/私有值阻断；严格归档与required-fields投影分开；投影不保存reasoning/原始HTTP；安全归档在校验和物化之后 |
| 生产客户端 | 复用HTTP客户端与发送前持久账本，保存请求hash、HTTP存在/状态/字节、失败层级及安全诊断；缺失正文hash为null |
| 19–22入口 | 公开预览、三臂pilot、两既有候选Victim-only测量、Planner修复/诊断；输入显式提供，不绑定历史机器路径 |
| 23重复pilot | 9位置、三块三臂轮换、共同样本顺序、独立A/B、预检/确认/冻结/查收 |
| 24采集 | 30位置、5批×6、seed10001–10030、全primitive；每位置最多一次Planner，Victim最多24；零重试、不补位、24小时期限 |
| 去重与停止 | pointer/value精确hash跳过重复B；5-gram相似度仅描述；整批无唯一候选停止；不确定发送/封存/审计/cleanup错误停止 |
| 续接与导出 | 显式resume、锁、排他reservation/seal；已有reservation而缺完整seal时拒绝重发；全计划JSON/CSV、逐案页、候选及代表案例 |

公开structured不直接复制私有证据正文；occurrences/relations保守为空并声明边界。
字段存在不证明原语结构完整或方法优越。历史真实导入原始数据缺失，不能用合成数据冒充其正向端到端验证。

## 离线入口

~~~bash
cd /home/kunyuan/snap/Zky_Agent_Attack/STAC-Compositional-Attack-Lab
STAC_PYTHON=.venv/bin/python bash scripts/attack_program/23_r3_repeated_development_pilot.sh --help
STAC_PYTHON=.venv/bin/python bash scripts/attack_program/24_primitive_development_campaign.sh --help
.venv/bin/python -m stac_attack_lab.attack_program.campaign_cli --kind diagnostic --help
~~~

demo --output <全新目录>为零模型HTTP的scripted演示。
增加--docker使用本机模拟Planner及隔离Docker，不调用真实模型。
prepare创建不可覆盖的新计划；preflight只读/零请求；a --block N和b --block N分阶段；
run按新计划执行；status/summary/audit/export用于查收。

真实执行需与当前计划hash、阶段和预算完全匹配的明确授权文件和旗标。
本轮真实模型/真实Victim请求0，无正式库冻结，无沿用旧授权。
21入口只消费显式提供的两个候选，Planner请求恒为0。

## 实际验证

- 第一轮新功能及相关旧链专项：39 passed in 66.72s。
- 重复测量反例先1 failed（3次测量错误计3样本），修复后纳入全库回归。
- 最终完整pytest：**158 passed, 3 skipped in 214.54s**。跳过3项因历史真实fixture缺失，不能当通过。
- 期间完整回归153/3与157/3是不同代码检查点，不相加。最后另补审计语义篡改反例，先1 failed后修复；最终158包含该反例。
- 最终Ruff format --check：73文件格式正确；Ruff check通过，mypy34源文件通过，pip check及git diff --check通过。
- 最终全库日志：experiments/runs/server-reimplementation-20261014-v1/release.log及release.xml。
- 最终Docker新入口：experiments/runs/attack-program/rebuilt-pilot-fake-20261014-v2/campaign/。
  3/3模拟Planner HTTP，2个有效唯一候选、1重复；Victim完成2，模拟HTTP共12。
  独立campaign审计valid，2案cleanup completed/owned_remaining=false，2案memory_commit=observed；
  teacher导出保留3行。真实请求0。fake token缺失保持unknown，不记为0。
- 查收文件：experiments/runs/server-reimplementation-20261014-v1/docker-final-receipt.json；
  模拟日志docker-pilot-v2.log。额外runtime_review-final复核通过。
- v1为较早源码检查点；一次人工audit命令误指向演示外层目录而得到FileNotFoundError。
  正确--run路径含campaign/。v2已按正确路径完成独立审计，不将那次失败说成通过。
- baseline/候选运行保留pinned memory precondition警告并继续；模拟正例不作为真实攻击结论。
- 30-slot编排由完整回归覆盖：默认固定模拟生成器产生重复内容，第二个6-slot批次无新候选时停止，
  仍保留30个计划位置，其中18未启动。没有跑30次真实模型采集。
- 当前独立审计会重新解析准入Planner计划、重算选样/候选身份/物化和结果结论；
  重复候选也保留安全投影和候选证据，确保不只依赖可重算的文件hash。


## 原代码找回后的比较

比较新增模块、共享HTTP/R4修改及schema，不覆盖整个工作区。
新计划保存执行源snapshot；历史manifest/ledger/raw没有改写。
按行为和测试对照，不能仅按同名文件覆盖。
