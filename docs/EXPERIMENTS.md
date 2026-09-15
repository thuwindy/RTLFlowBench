# 多人实验操作清单

本页是协作流程，不是“实验已经可启动”的声明。当前公开预览的 `evaluate` 会返回 BLOCK。

## 角色分工

- **维护者**：版本锁、依赖、私有 oracle、校准和离线评分；给出允许启动的精确 experiment lock。
- **运行者**：只拿 public packet/source projection、工作流 runtime 和分配的 slots；运行并导出 submission。
- **分析者**：使用同一 cohort 的完整结果与缺失原因；不把历史版本混入新版本。

一个人可以兼任，但运行目录和可见输入必须分开。不要把维护者私有目录整体挂进 workflow 容器。

## 同一服务器、不同账号协作

各自使用本人账号、SSH 私钥和独立 clone/workspace，不修改别人的执行快照。
私有判分材料由维护者按项目限定授权；不要开放整个 home 或共享 API key。
公共工具可以先独立开发，完整判分则需要受控环境交接，不能从公共 clone 猜路径或配置。
任务领取、负责人和交付物在 issue/PR 中记录；私有证据只放受控渠道，公开摘要不放服务器路径。

## 开跑前交接八件东西

1. Benchmark 内容锁：十二题 public input、私有 evaluator、runner、评分规则的精确身份。
2. 当前绑定的校准矩阵及原始证据定位，包含失败/成功对照，而不只有汇总 PASS。
3. 环境锁：OCI digest、工具版本、依赖、资源限制、超时和环境稳定性证据。
4. QoR：基准实现身份、功能保持条件、面积/时序判据、物理重复测量与噪声处理。
5. 五个 workflow 的 runtime/adapter 配置及新输入检查：启动、工具反馈、导出和停止行为。
6. 统一模型/provider、采样、seed、调用数及输入/输出预算；发送前估算、响应后真实 usage 结算。
7. 无重叠 slot 分工表：`cohort_id, slot_id, task_id, workflow_id, repeat_id, seed, owner, status`。
8. 实际验证过的启动、状态、submission 导出、离线评分和结果汇总命令。

缺少其中一项，先报告具体缺口，不让运行者猜命令、预算或模型。
单任务预算不是多人全局开销上限；并发数量和总费用上限也需由负责人明确。

## 每批怎么运行

1. 校验本批 lock/runtime/input 哈希、账号权限、可用余额及资源容量；不同人使用自己的授权账号。
2. 领取唯一 slot，使用全新 workspace 和输出目录。不要从另一 slot 复制生成代码或 checkpoint。
3. 运行受控 native workflow，记录真实 token/cache usage、LLM/EDA 调用、耗时和人工干预。
4. 相同错误连续出现、usage 缺失、预算异常或 INFRA 时按既定规则停止；不自动无限重试。
5. 原始运行目录封存后，将 submission 导出到独立后处理目录；维护者另行离线判分。
6. 批后核对余额与 ledger、完整性、重复 slot 和缺失结果，再决定下一批。

只允许按照已冻结策略接受一次在途请求的累计输入超额；不能把它解释成没有 token 硬约束。
重试必须保留原始失败，注明原因和新 attempt；更换模型、题目或预算不能冒充原运行续跑。

## 怎么解释结果

- PASS：真实 evaluator 及完整结果校验支持通过，不是工作流自称成功。
- FAIL：功能、协议、DV 或 QoR 条件未满足，保留具体子类。
- BLOCK：合同规定的安全拒绝或已证明的能力边界；接入故障不能伪装成能力不足。
- INFRA：供应商、网络、环境或工具故障，不是 RTL 失败。
- 缺失：保留 `null/not_available` 与原因；不要用 0 填充成本、覆盖率或 PPA。

主报告保留十二题 × 所有系统的完整矩阵。正式独立运行次数与 EDA 物理重复测量次数分别统计。
预算计划的 200 slots 是五个系统各做十道非 QoR 题三次、两道 QoR 题五次；
真正执行前以审批后的不可变 schedule 为准。不能挑题后只报告支持子集。

## 运行者交回什么

提交 artifact bundle + submission receipt + 运行身份/usage ledger + 错误分类与私有原始日志定位。
不要自行填写 hidden score，不要公开原始供应商回复、key、user ID 或 oracle。
维护者交回规范 result、可分享的证据摘要及本次评分身份，供矩阵和图表使用。
