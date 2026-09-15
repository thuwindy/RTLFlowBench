// RTLFlowBench public lint shim. Functional coverage remains evaluator-private.
`ifndef RTLflowbench_G07_DV_FCOV_SHIM
`define RTLflowbench_G07_DV_FCOV_SHIM
`define DV_FCOV_SIGNAL(TYPE_, NAME_, EXPR_)
`define DV_FCOV_SIGNAL_GEN_IF(TYPE_, NAME_, EXPR_, GEN_COND_, DEFAULT_ = '0)
`endif
