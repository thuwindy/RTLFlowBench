# Golden-12：十二道题的输入、意义和评估

RTL 描述数字电路的周期行为。工作流不仅要会写模块，还要能接接口、修仓库、验证、优化并安全拒绝。
Golden-12 是六类能力的紧凑审计，不代表穷尽所有芯片设计问题。

## 六个上游项目加工成十二题

背景来自 common_cells、verilog-axis、wb2axip、PicoRV32、Ibex、SERV，出处和许可见 [NOTICE](../NOTICE.md)。
开源项目本身不是 benchmark：还需要固定输入、允许修改范围、预算、隔离判分器、校准和统一结果格式。
题目目录在 [`candidate/tasks`](../candidate/tasks)，下表不替代各题 spec、`external_task.json` 和评分政策。

| 题目 | 输入 → 输出 | RTL 意义与选取理由 | 主要评估维度 |
|---|---|---|---|
| G01 FIFO | 参数/接口/行为规格 → 独立 RTL | 像排队缓存，检查文字到时序逻辑的转换 | 顺序、满空边界、同时进出、复位、参数 |
| G02 仲裁器 | 请求/授权/锁定规格 → 独立 RTL | 多请求者争用资源，检查谁先用、会不会饿死 | 授权安全、锁定、状态更新、有界公平性 |
| G03 AXI-Stream 集成 | 受控 FIFO IP 与合同 → wrapper | 模块正确不等于连接正确，尤其下游暂停时 | ready/valid、背压、帧边界、数据保持 |
| G04 总线桥集成 | 桥接 IP 与 AXI-Lite/Wishbone 合同 → 集成实现 | 协议翻译必须保存每笔事务归属 | 请求响应对应、通道、停顿、事务隔离 |
| G05 PicoRV32 修复 | 固定 CPU 基线与中断缺陷合同 → 限定修复 | 读懂并修复现有 CPU，而非重写 | F2P、P2P、形式/仿真证据、范围 |
| G06 Ibex 修复 | 基线与 CSR/debug 异常合同 → 限定修复 | 异常发生时正确保存上下文 | 目标异常、上下文保存、回归保持 |
| G07 Ibex 修复 | 基线与 PMP 更新合同 → 序列化修复 | 权限变化后执行必须遵守新规则 | 保护更新生效、时序和回归 |
| G08 FIFO DV | 只读 DUT 与验证合同 → TB/属性 | 不只写设计，还会设计能抓错的测试 | 正确 DUT 不误报、mutation kill、formal/仿真 |
| G09 AXI FIFO DV | 只读 DUT 与验证合同 → cocotb 测试 | 测试能否发现协议缺陷 | mutation kill、false-positive、协议场景 |
| G10 SERV QoR | CPU 与 QoR 约束 → 优化 RTL | 电路变小的同时不能牺牲正确性 | 功能、物理面积、时序条件、重复测量 |
| G11 PicoRV32 QoR | CPU 与工作负载/QoR 合同 → 优化 RTL | 避免电路更小却执行更慢 | 面积、时序、周期分别记录，功能/范围门槛 |
| G12 CDC Trust | 明确不充分的跨时钟契约 → 拒绝产物 | 信息不足时不擅自修改电路 | 合同 BLOCK、无未授权操作、可信证据 |

G07 保留历史目录名 `G07-ibex-ifetch-error-timing`，当前题意为 PMP 更新，以锁定规格为准。
G12 明示拒绝类别，测的是遵守合同，不夸大为自行发现隐含风险。
G01/G02 不给参考 RTL；仓库题只给允许的 source projection，不是整个上游历史、答案和全部测试。

## 评分原则

- F2P：原失败行为修复为通过；P2P：原通过行为不被破坏。
- DV：正确设计是否误报、错误 mutants 是否检测出来，而非只数生成测试条数。
- QoR：先保功能，再看真实物理数据；逻辑综合代理不冒充物理 PPA。
- Trust：合同规定的安全 BLOCK 可以是预期成功，但 INFRA 不是安全能力。
- 各题同时记录范围/可信事件、耗时、token/cache、LLM/EDA 调用、人工干预、成功率及方差。

仅对实际适用、实际测得的指标赋值。覆盖率、功耗等缺失时保留 `null/not_available`。
当前没有任意的“六十分”或加权总分，主结果是完整能力矩阵与原始指标，
规则见 [`candidate/policy.json`](../candidate/policy.json)。
PASS 需要 evaluator 证据；FAIL 保留功能/协议/DV/QoR 子类；BLOCK 与 INFRA 分开。
exit code=0、工作流自报成功、visible tests 通过都不等于完整 PASS。

## 如何证明试卷合理？

先用保留基准/人类 reference、结构不同的 alternate、blank/no-op、negative、mutants 校准。
检查该过的过、该失败的失败；缺少某种证据就列出缺口，不能用子测试通过代替整题通过。
随后跨工作流 pilot 检查可靠性、区分度和方差，不因 ChipFlow 低分就降低难度。
修改输入、判分或评分语义后生成新版本，对所有可比系统统一重跑。
本仓库仍是研究预览，参见 [STATUS](STATUS.md)。
