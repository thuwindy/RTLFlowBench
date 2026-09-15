# 协作开发：先理解试卷，再修改程序

欢迎参与 RTLFlowBench。目标是比较不同 **RTL 工作流** 的能力，而不是帮助某个工作流做对题。
本仓库仍是 research preview；可以读题、改进公共工具、做可见测试开发，但不能据此宣称完整判分或正式排名。

## 第一次上手

先读 [题目介绍](docs/BENCHMARKS.md)、[五个工作流](docs/WORKFLOWS.md) 和 [待办](docs/STATUS.md)，
不需要从聊天历史中寻找任务。

```sh
git clone https://github.com/thuwindy/RTLFlowBench.git
cd RTLFlowBench
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python rtlflowbench.py verify
.venv/bin/python rtlflowbench.py list
.venv/bin/python rtlflowbench.py describe --task G01-common-fifo-spec
.venv/bin/python -m unittest discover -s tests -v
```

`verify` 检查分发内容和 schema，测试检查工具行为；两者都不启动模型或 EDA，也不证明 RTL 正确。
`describe` 直接展示已声明的输入文件、输出范围、预算、oracle 类别和原始指标，不补猜接口或评分规则。
具体命令是否已在当前 GitHub 版本发布，以该版本 README/CLI 为准。

第一小时建议：读 README 的十二题表 → 选 G01 看三份 spec → 看 `external_task.json`
和 `EVALUATION_POLICY.md` → 用 describe 对照 → 导出 public packet 到仓库外的新目录。
不需要一开始阅读全部 ChipFlow 源码，也不需要先充值。

## 文件导航

| 想了解或修改什么 | 文件位置 | 注意事项 |
|---|---|---|
| 题目要做什么 | `candidate/tasks/<ID>/public/spec/` | 规格必须独立、明确，不包含答案 |
| 输入、输出和预算 | 同题的 `external_task.json`、`allowed_scope.json`、`budget.json`、`repo.lock` | 这些文件必须一致；不能只改其中一处 |
| 可见反馈 | 同题的 `public/visible/` | 可见测试不是完整评分器 |
| 统一评分政策 | `candidate/policy.json` 和各题 `EVALUATION_POLICY.md` | 原始指标与主结果矩阵分开，缺失值不是零 |
| 外部系统格式 | `schemas/`、`tools/package_submission.py` | adapter 只能搬运格式和启动协议，不能提供解法 |
| 公共工具和回归 | `rtlflowbench.py`、`tests/` | 先增加能复现问题的测试，再修实现 |
| 内容身份 | `candidate/candidate-lock.json`、`public-release-lock.json` | 前者锁题，后者锁分发；都不是运行器 RELEASE |
| 私有判分器、校准、真实日志 | 不在公共仓库中，由维护者授权提供 | 不上传公共 issue，不进入被测工作流输入 |

仓库型任务需要经过核验的 source projection；`export-public` 不下载它。
不能拿整个上游仓库（含历史、答案、全部测试）替代受控输入。

## 能做哪些优化？

优先修复可独立证明的问题：接口歧义、约束冲突、缺失依赖、错误判定、漏记真实 usage、工具崩溃分类和可复现性问题。
不要因为 ChipFlow 或某个工作流低分就降低阈值、删掉失败测试、补专属提示或挑选其擅长的题。

一次修改建议只解决一个问题：

1. 记录 task ID、基准版本/commit、原命令、预期行为和实际行为。
2. 用最小公共复现材料说明矛盾；涉及 hidden oracle 时走私有审查渠道。
3. 新建自己的分支/工作目录，保留原始实验和日志。共享服务器不要修改他人的 checkout。
4. 先加入失败回归，再修 Python/配置/文档。涉及 RTL/TB 时遵守所属开发环境的 Judge/Safe Executor 规则。
5. 按下面的变更分类提交说明；执行回归、校准和隔离检查，不以 exit code 单独认定 PASS。
6. 由维护者审核纳入清单并生成新内容锁。不要为了让 verify 变绿而手工抹掉哈希差异。

## 什么修改需要重跑？

| 变更 | 必须保留的证据及后续动作 |
|---|---|
| 文档或不影响执行的展示 | 说明为什么不改变输入/执行；更新分发版本，保留旧哈希 |
| 题目、预算、hidden oracle、runner 或评分语义 | 新 benchmark/实验身份；相关校准；所有可比系统从零跑新版本 |
| 某个 workflow 的 runtime/adapter 实现 | 新 runtime 身份和同题同预算的新比较；旧结果不静默覆盖、不混算 |
| 供应商、模型、seed 或运行预算 | 新实验 cohort；不能当作原实验续跑 |

某个文件位于 `docs/` 不代表它一定不影响执行；若它进入模型输入或哈希闭包，也要按实际用途处理。
历史 receipt 的执行时哈希永远保留。展示投影变化必须有明确的 post-run 变更记录。

## 判分器维护者的额外检查

维护者需要受控的 evaluator 源码快照、依赖/环境锁和校准输入，而不只是这份公共 clone。
访问权限由项目负责人按本人账号提供；不共享 SSH 私钥或 API key。人类维护者可以审查 oracle，
但不能把答案或针对特定题的知识写入 workflow adapter。

校准按题目语义选择 reference、结构不同的 alternate、blank/no-op、negative、mutants。
对 DV 题，需要验证正确 DUT 不被误报、错误 DUT 被检测；对 QoR 题，功能通过不等于性能优化成功；
对 Trust 题，符合合同的 BLOCK 是预期行为。不要把一个子套件通过写成整题 reference 通过。

交付给实验运行者前，按 [实验清单](docs/EXPERIMENTS.md) 完成新输入和 native runtime 检查。
独立审查、作者审查、AI 审查必须按真实身份披露，不代签。

## 交回改动

在自己的 clone/fork 创建独立分支，一次 PR 解决一个问题。写清任务 ID/版本、复现、原因、
diff、真实测试和版本影响。公共问题可使用 benchmark-defect issue 模板；私有 oracle 走受控渠道。
不公开服务器私有路径、原始日志或凭证。改动后旧分发锁失配是保护机制；
由维护者审计并重锁，不删除校验来恢复绿色状态。
