# G12-RTL · RTLFlowBench

G12-RTL examines whether local RTL repair success translates into complete design
acceptance. It separates target repair, preserved behavior, task-level acceptance
and resource cost, so an improvement on one check is not counted as a complete
solution. The repository name `RTLFlowBench` is retained for existing users.

## ISCAS 2027 paper source

**Start here: [paper source and provenance](paper/iscas2027/README.md).**
This directory accompanies *CriticRTL: RTL Repair with Independent Review and
Acceptance Diagnostics*, by Jinhan Fu, Haonan Sun and Hu He. It adds the
paper-associated benchmark/controller and baseline-adapter source distribution,
with exact version mappings and explicit publication transformations where needed.

CriticRTL studies independent diagnosis for target repair; G12-RTL tests complete
acceptance and explains the gap between the two. The paper evaluates/calibrates
G01–G07; G08–G12 are not evaluated in the paper. Baseline adapters and source
snapshots must be interpreted under the common experiment protocol, not as an
unmodified upstream leaderboard.

- [Paper source layout, checks and distribution boundaries](paper/iscas2027/README.md).
- [CriticRTL framework repository](https://github.com/thuwindy/Chipflow) (currently private; access required).
- [Third-party notices and licensing scope](NOTICE.md).

The paper source directory and the older draft packets below are distinct
versions. Do not substitute the draft packets for historical paper inputs or
interpret a file-integrity check as an RTL acceptance result. Hidden evaluator
assets are kept separate from workflow-visible inputs; this source update does
not publish a turnkey scored benchmark service or assert a fresh experiment replay.

## Joint development / 协作开发

开发者从 [CONTRIBUTING.md](CONTRIBUTING.md) 和
[开发任务清单](docs/DEVELOPMENT_PLAN.md) 开始。可在独立分支改进公共工具、
输入契约和后续版本的执行接入；通过 PR 记录复现、验证和版本影响。
`paper/iscas2027/` 固定在 `paper-source-20261013` 标签，作为论文引用基线。

```sh
git switch -c codex/my-topic
python3 scripts/check_paper_snapshot.py
python3 paper/iscas2027/verify.py
python3 -m unittest discover -s tests/collaboration -v
```

协作 CI 同时检查论文快照、公开分发锁和公共工具测试。修改后锁不匹配时，
维护者应审阅差异并记录新的分发身份；不要关闭校验或改写历史执行哈希。
下面的预览工具安装步骤仍适用，所有上述检查均无需模型额度或 EDA。

## Public task preview

The original twelve draft public packets, neutral submission schemas and offline
packaging tools remain available. Their task contents and candidate hashes are
unchanged. See the [full preview guide](README.preview-20260915.md) for task
summaries, upstream source locks, scope rules and usage.

```sh
git clone https://github.com/thuwindy/RTLFlowBench.git
cd RTLFlowBench
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python rtlflowbench.py verify
.venv/bin/python rtlflowbench.py list
.venv/bin/python -m unittest discover -s tests -v
```

`verify` checks distribution hashes and draft schemas; it does not run RTL or
award benchmark scores. See the paper directory for its separate source-integrity
check. Missing measurements remain unknown rather than zero. Failures,
capability blocks and infrastructure errors remain distinct.

The repository remains **public**. Existing preview licenses and upstream notices
are retained; no blanket relicensing of the imported corpus is implied.
