# 联合开发计划

更新：2026-10-14。本页是后续任务清单，尚未分配负责人；不声称这些交付或新实验已经完成。
先读 [贡献指南](../CONTRIBUTING.md) 和 [论文来源边界](../paper/iscas2027/README.md)。

日常改动在 `main` 的 feature 分支开发。`paper-source-20261013` 与 `paper/iscas2027/`
保持冻结；十二题 draft preview 及候选锁保留现有身份。工具、文档、公共回归和新增开发辅助脚本
可在快照外演进。公开发布仍缺完整 evaluator 和 runtime closure，不能据此声称整套历史实验可重放。

| 优先级 / 工作包 | 交付物 | 验收证据与边界 |
|---|---|---|
| P0 · 公共输入投影 | 在快照外实现依赖 intake/projection 工具，读取固定 source lock、归档哈希和 allowlist；列出尚不可获取的依赖 | 公共或合成 fixture 上验证固定版本、哈希错配拒绝、越界路径拒绝、输出成员精确匹配、保留 notices。G01/G02 不注入参考 RTL；不得将整个上游 checkout 作为默认输入。网络获取另行执行并保留真实 source receipt |
| P0 · runner 依赖闭合清单 | 按 controller、task source、toolchain、OCI、adapter 分类记录获取方式、版本和缺失项；新建公开可运行 smoke 的说明与 fixtures | 清单区分可公开获取、需授权、缺失；一个 digest 不算构建配方。仅在真实环境验证后记录该 smoke 的命令、源码身份、依赖和输出，不能扩大成历史 E1/E3/R1 重放结论 |
| P1 · 中立 adapter 合约 | 快照外提供 adapter 接口与合成任务回归：输入装载、预算、启动、停止、usage、提交物封存 | 同一公共合约验证停止后提交物不可变、scope 拒绝、真实 usage 或 `null`、INFRA 与语义失败分离。先用合成/公共 fixtures；不得装入 hidden evaluator、参考答案、题目专属提示，或因启动成功宣称工作流完成 |
| P1 · 隔离和结果证据交接 | 定义 workflow 与 trusted grader 的边界、receipt schema 和脱敏导出；在公开合成 fixture 上验证 | workflow 仅获得公共输入和批准的 source projection，停止后独立 grader 读取封存提交物；验证越权读取被拒绝。保存执行源码哈希和原始日志，缺失 trust/resource 保持 `not_available` / `null`；公共合成检查不冒充真实 hidden 校准 |
| P2 · 协作回归与文档 | 按实际工具行为完善单测、离线检查和入门说明，登记尚未覆盖的行为 | 本地和 CI 报告实际命令、状态及未执行项；冻结快照检查通过，分发变更经审查后显式重锁，合并前 verify 与单测通过；不自动生成新锁，不运行模型或 EDA 来充当文档检查 |

每个 issue 只领取一个可审查的交付物，写明允许修改的路径、依赖和排除项。
使用 [开发任务模板](../.github/ISSUE_TEMPLATE/development-task.md) 建立讨论，并通过
[PR 模板](../.github/PULL_REQUEST_TEMPLATE.md) 交回证据。以上优先级不授予 evaluator 访问权限，
也不授权启动付费模型、整批实验或修改他人 workspace。

公共工具、合成 fixture 的检查可先独立完成；真实 source intake、runner smoke 和评分校准必须在
对应依赖、工具和权限实际具备后进行。缺少条件时登记具体缺口，保留 BLOCK/未执行状态。
涉及题目、预算、评分、runtime 或实验条件变化时，按贡献指南创建新身份，不混算历史结果。
