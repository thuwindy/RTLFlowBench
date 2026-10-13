# RTLFlowBench 协作约束

本仓库用于 G12-RTL/RTLFlowBench 的公共研究预览与论文来源分发。先读
[CONTRIBUTING.md](CONTRIBUTING.md)、[开发计划](docs/DEVELOPMENT_PLAN.md) 和
[论文来源说明](paper/iscas2027/README.md)。本文件不放宽用户或所属开发环境的安全规则。

## 可修改范围

- `paper-source-20261013` tag 与 `paper/iscas2027/` 是冻结来源；不得修改、重写或移动。
  新实现和勘误置于快照外，标明新身份，保留旧来源与哈希。
- 日常 PR 修改公共工具、测试、文档和开发辅助脚本。普通 PR 保持 `candidate/` 的 task ID、
  packet 与 `candidate/candidate-lock.json` 不变；题目语义变化必须单独评审新版本。
- `public-release-lock.json` 绑定整个分发。变更后失配应显式报告；仅在审查后有意识地重建并记录
  被替代锁身份。不得通过自动重锁、绕过校验或修改候选锁消除报错。
- 保留上游许可证、版权和 notices；现有 helper 授权不能推及全部导入语料。

## 证据和隔离

- 不编造仿真 PASS、benchmark、PPA、工具可用性、性能或重放结果。哈希/单测通过只证明对应检查。
  不以退出码独自认定 RTL 正确，`Time Out` 不是 `TEST_PASS`。
- 仅公共 packet 与经批准的 source projection 可进入 workflow。hidden evaluator、参考解、校准池、
  私有测试和题目专属答案不能进入 adapter、workflow 输入或公开 issue/CI。
- 公共 clone 不具备完整评分闭合；不得把 fail-closed 的 `evaluate` 改成虚构评分或成功。
- 保留 task/version/runtime 身份、执行时源码哈希及受控原始日志；不同 cohort 不混算。
  仅展示变化使用显式 `post_run_source_changes`，记录原执行哈希、当前哈希和语义分类。
  缺失 machine-gate、trust、resource 数据保持 `not_available` / `null`，不填 0。
- 不提交 `.env`、`config.yaml`、`outputs/`、波形、归档、凭证、私有机器路径、原始 provider
  对话、推理过程、专有文档或受控执行日志；只发布经审查的脱敏摘要。
- 涉及 ChipFlow RTL/TB 实施时，Judge 必须先 ACCEPT，且只能走匹配的 Safe Executor；
  缺接口语义、匹配 executor 或真实证据时 BLOCK。公共 benchmark 工具不能绕过这些条件。

## 工作方式与检查

从最新 `main` 创建范围明确的 feature 分支；共享服务器只操作自己的账号/workspace。
子代理显式使用最小历史范围，优先 `fork_turns="none"`，最多并行 3 个；大日志落盘，仅传路径和摘要。
父任务超过 100 MiB 或多次压缩时先形成简短交接，不再批量派生；任务结束收束子代理。

依赖准备后，从仓库根目录执行以下离线检查，报告真实结果与未执行原因：

```sh
python3 rtlflowbench.py verify
python3 -m unittest discover -s tests -v
python3 paper/iscas2027/verify.py
python3 scripts/check_paper_snapshot.py
python3 -m unittest discover -s tests/collaboration -v
git diff --check
```

使用已安装 `requirements.txt` 的 Python 环境。文档改动也会影响分发锁，并使部分单测失败；
审查前保留失配证据，审查后显式更新分发锁并重跑。CI 不自动更新锁、不读取 secrets、不启动模型或 EDA。
提交说明必须区分公共离线检查、合成 fixture、真实实验和缺失条件。
