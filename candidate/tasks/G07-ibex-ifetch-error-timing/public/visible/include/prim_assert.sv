// RTLFlowBench public lint shim. Assertions are evaluated only by the private
// verification environment; this visible syntax gate does not claim proof.
`ifndef RTLflowbench_G07_PRIM_ASSERT_SHIM
`define RTLflowbench_G07_PRIM_ASSERT_SHIM
`define ASSERT(__name, __prop, __clk = clk_i, __rst = !rst_ni)
`define ASSERT_IF(__name, __prop, __enable, __clk = clk_i, __rst = !rst_ni)
`define ASSERT_KNOWN(__name, __sig, __clk = clk_i, __rst = !rst_ni)
`define ASSERT_KNOWN_IF(__name, __sig, __enable, __clk = clk_i, __rst = !rst_ni)
`define ASSERT_INIT(__name, __prop)
`endif
