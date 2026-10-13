## 修改解决什么问题

说明触发条件、修改后的行为，以及相关 issue / 开发计划工作包。

## 范围与身份

- 允许修改的路径：
- 涉及 task ID / benchmark、runtime 或 source 版本（无则写不适用）：
- 输入、执行、评分或预算语义是否变化；如变化，新身份与后续验证安排：

## 验证证据

填写实际命令与结果；未执行时说明缺失条件，不把计划写成通过。

| 检查 | 实际结果 / 未执行原因 |
|---|---|
| `python3 rtlflowbench.py verify` | |
| `python3 -m unittest discover -s tests -v` | |
| `python3 paper/iscas2027/verify.py` | |
| `python3 scripts/check_paper_snapshot.py` | |
| `git diff --check` | |
| 与本次修改直接相关的公共/合成回归 | |

源码 commit/hash、日志存储与可公开脱敏摘要：

## 合并前确认

- [ ] `paper/iscas2027/` 和 `paper-source-20261013` 保持原身份；无历史执行哈希替换。
- [ ] 普通工具/文档改动未改 candidate packet、task ID 或候选锁；其他变更已说明新版本。
- [ ] 无 hidden evaluator、参考解、凭证、私有路径、原始对话或受控原始日志泄露。
- [ ] 未将完整上游仓库或评分资料引入 workflow/adapter 输入；保留许可与 notices。
- [ ] 分发锁差异已报告；只在审查后显式重建并记录旧锁身份，合并前重跑 verify 与单测。
- [ ] 结果范围准确；未知数据仍为 `null` / `not_available`，无新增未经证据支持的实验声明。

仅文档/展示投影变化：说明不影响执行语义的理由；如关联历史 receipt，给出
`post_run_source_changes` 记录位置（不得覆盖执行时哈希）。
