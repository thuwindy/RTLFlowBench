# 协作开发：先理解试卷，再修改程序

欢迎参与 RTLFlowBench。目标是比较不同 **RTL 工作流** 的能力，而不是帮助某个工作流做对题。
本仓库仍是 research preview；可以读题、改进公共工具、做可见测试开发，但不能据此宣称完整判分或正式排名。

## 冻结快照与日常开发

`paper-source-20261013` tag 和 [`paper/iscas2027/`](paper/iscas2027/README.md)
是论文来源快照。日常协作从 `main` 开始，在新分支修改公共预览工具、测试、文档和开发辅助脚本；
不要修改、移动或重建论文快照，也不要移动 tag。历史源码缺陷可登记 issue，
在快照外提供明确标识的新实现或勘误，并保留原始来源和哈希。

`candidate/` 是早期十二题 draft public preview，与论文输入不是同一版本。
既有 task ID、packet 内容和 `candidate/candidate-lock.json` 在普通工具/文档 PR 中保持不变。
题目变更须单独评审新版本及身份，不能覆盖旧题后沿用旧成绩。
近期工作从 [开发计划](docs/DEVELOPMENT_PLAN.md) 选择一项；其中均为待交付工作，不代表已完成结果。

## 第一次上手

先读 [题目介绍](docs/BENCHMARKS.md)、[五个工作流](docs/WORKFLOWS.md) 和 [待办](docs/STATUS.md)，
不需要从聊天历史中寻找任务。

```sh
git clone https://github.com/thuwindy/RTLFlowBench.git
cd RTLFlowBench
git switch -c feature/public-preview-fix
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python rtlflowbench.py verify
.venv/bin/python rtlflowbench.py list
.venv/bin/python rtlflowbench.py describe --task G01-common-fifo-spec
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python paper/iscas2027/verify.py
.venv/bin/python scripts/check_paper_snapshot.py
```

创建环境和安装依赖是准备步骤，可能需要网络；依赖安装后，上述 Python 检查均可离线执行。
`verify` 检查分发内容和 schema，测试检查工具行为；不启动模型或 EDA，也不证明 RTL 正确。
`paper/iscas2027/verify.py` 校验声明的论文源码；`scripts/check_paper_snapshot.py`
额外核对完整论文目录相对冻结 tag 的字节和成员身份。保留该 tag，不用浅克隆遗漏它。
分发锁失配会使 `verify`、`list`、`describe`、导出及部分单测失败；提交修改后这是待处理证据，
不是跳过检查的理由。维护者完成审查并显式更新分发锁后，合并版本必须重新通过这些检查。
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

有写权限时，在上面的 feature 分支提交并推送到自己的远端分支；无写权限时先在 GitHub fork，
将 clone URL 换为自己的 fork，并把 `thuwindy/RTLFlowBench` 配为 `upstream`。
从最新 `main` 创建分支，避免把实验输出或其他人的工作混入一次 PR。示例只列明确的文件，
按自己的修改替换文件名：

```sh
git diff --check
git diff -- docs/DEVELOPMENT_PLAN.md
git add docs/DEVELOPMENT_PLAN.md
git commit -m "docs: clarify development work package"
git push -u origin feature/public-preview-fix
```

然后在 GitHub 打开指向 `thuwindy/RTLFlowBench:main` 的 PR，填写
[PR 模板](.github/PULL_REQUEST_TEMPLATE.md)。公共缺陷使用
[benchmark-defect](.github/ISSUE_TEMPLATE/benchmark-defect.md)，协作任务使用
[development-task](.github/ISSUE_TEMPLATE/development-task.md)。写明实际执行的命令、结果、
尚未执行的检查与原因。不要把计划检查写成已经通过。

检查日志放仓库外，保留源码 commit/hash、命令、工具版本和原始结果；PR 只附可公开的摘要与脱敏证据。
原始受控实验日志保留在其授权存储，不公开私有路径、provider 原始对话或凭证。
维护者审查 diff 后才能显式重新生成 `public-release-lock.json`，记录被替代锁的身份和变更原因；
不得自动重锁、删除校验或修改候选锁来恢复绿色。既有 receipt 的执行哈希保留不变，
仅展示变化按 `post_run_source_changes` 记录执行哈希、当前哈希及不影响执行语义的分类。
