// Public G06 positive-preservation smoke. This is not the hidden defect oracle.
module g06_visible_tb;
  import ibex_pkg::*;

  localparam logic [31:0] NORMAL_PC   = 32'h0000_0100;
  localparam logic [31:0] NORMAL_TVAL = 32'hdead_beef;
  localparam logic [31:0] DEBUG_PC    = 32'h0000_0300;

  logic clk_i = 1'b0;
  logic rst_ni = 1'b0;
  always #5 clk_i = ~clk_i;

  logic fetch_enable_i;
  logic illegal_insn_i;
  logic ecall_insn_i;
  logic mret_insn_i;
  logic dret_insn_i;
  logic wfi_insn_i;
  logic ebrk_insn_i;
  logic csr_pipe_flush_i;
  logic instr_valid_i;
  logic [31:0] instr_i;
  logic [15:0] instr_compressed_i;
  logic instr_is_compressed_i;
  logic instr_fetch_err_i;
  logic [31:0] pc_id_i;
  logic [31:0] pc_if_i;
  logic [31:0] lsu_addr_last_i;
  logic load_err_i;
  logic store_err_i;
  logic branch_set_i;
  logic jump_set_i;
  logic irq_nm_i;
  logic debug_req_i;
  logic stall_lsu_i;
  logic stall_multdiv_i;
  logic stall_jump_i;
  logic stall_branch_i;

  logic ctrl_busy_o;
  logic instr_valid_clear_o;
  logic id_in_ready_o;
  logic instr_req_o;
  logic pc_set_o;
  pc_sel_e pc_mux_o;
  exc_pc_sel_e exc_pc_mux_o;
  exc_cause_e exc_cause_o;
  dbg_cause_e debug_cause_o;
  logic debug_csr_save_o;
  logic debug_mode_o;
  logic csr_save_if_o;
  logic csr_save_id_o;
  logic csr_restore_mret_id_o;
  logic csr_restore_dret_id_o;
  logic csr_save_cause_o;
  logic [31:0] csr_mtval_o;
  logic perf_jump_o;
  logic perf_tbranch_o;

  priv_lvl_e priv_mode_id_o;
  logic csr_mstatus_tw_o;
  logic [31:0] csr_mtvec_o;
  logic [31:0] csr_rdata_o;
  logic irq_pending_o;
  logic csr_msip_o;
  logic csr_mtip_o;
  logic csr_meip_o;
  logic [14:0] csr_mfip_o;
  logic csr_mstatus_mie_o;
  logic [31:0] csr_mepc_o;
  logic [31:0] csr_depc_o;
  logic debug_single_step_o;
  logic debug_ebreakm_o;
  logic debug_ebreaku_o;
  logic illegal_csr_insn_o;

  logic csr_access_i;
  csr_num_e csr_addr_i;
  logic [31:0] csr_wdata_i;
  csr_op_e csr_op_i;

  ibex_controller u_controller (
    .clk_i,
    .rst_ni,
    .fetch_enable_i,
    .ctrl_busy_o,
    .illegal_insn_i,
    .ecall_insn_i,
    .mret_insn_i,
    .dret_insn_i,
    .wfi_insn_i,
    .ebrk_insn_i,
    .csr_pipe_flush_i,
    .instr_valid_i,
    .instr_i,
    .instr_compressed_i,
    .instr_is_compressed_i,
    .instr_fetch_err_i,
    .pc_id_i,
    .instr_valid_clear_o,
    .id_in_ready_o,
    .instr_req_o,
    .pc_set_o,
    .pc_mux_o,
    .exc_pc_mux_o,
    .exc_cause_o,
    .lsu_addr_last_i,
    .load_err_i,
    .store_err_i,
    .branch_set_i,
    .jump_set_i,
    .csr_mstatus_mie_i(csr_mstatus_mie_o),
    .csr_msip_i(csr_msip_o),
    .csr_mtip_i(csr_mtip_o),
    .csr_meip_i(csr_meip_o),
    .csr_mfip_i(csr_mfip_o),
    .irq_pending_i(irq_pending_o),
    .irq_nm_i,
    .debug_req_i,
    .debug_cause_o,
    .debug_csr_save_o,
    .debug_mode_o,
    .debug_single_step_i(debug_single_step_o),
    .debug_ebreakm_i(debug_ebreakm_o),
    .debug_ebreaku_i(debug_ebreaku_o),
    .csr_save_if_o,
    .csr_save_id_o,
    .csr_restore_mret_id_o,
    .csr_restore_dret_id_o,
    .csr_save_cause_o,
    .csr_mtval_o,
    .priv_mode_i(priv_mode_id_o),
    .csr_mstatus_tw_i(csr_mstatus_tw_o),
    .stall_lsu_i,
    .stall_multdiv_i,
    .stall_jump_i,
    .stall_branch_i,
    .perf_jump_o,
    .perf_tbranch_o
  );

  ibex_cs_registers #(
    .MHPMCounterNum(8),
    .MHPMCounterWidth(40),
    .PMPEnable(1'b0),
    .PMPGranularity(0),
    .PMPNumRegions(4),
    .RV32E(1'b0),
    .RV32M(1'b0)
  ) u_cs_registers (
    .clk_i,
    .rst_ni,
    .hart_id_i(32'h0),
    .priv_mode_id_o,
    .priv_mode_if_o(),
    .priv_mode_lsu_o(),
    .csr_mstatus_tw_o,
    .csr_mtvec_o,
    .csr_mtvec_init_i(1'b0),
    .boot_addr_i(32'h0),
    .csr_access_i,
    .csr_addr_i,
    .csr_wdata_i,
    .csr_op_i,
    .csr_rdata_o,
    .irq_software_i(1'b0),
    .irq_timer_i(1'b0),
    .irq_external_i(1'b0),
    .irq_fast_i(15'h0),
    .irq_pending_o,
    .csr_msip_o,
    .csr_mtip_o,
    .csr_meip_o,
    .csr_mfip_o,
    .csr_mstatus_mie_o,
    .csr_mepc_o,
    .csr_pmp_cfg_o(),
    .csr_pmp_addr_o(),
    .debug_mode_i(debug_mode_o),
    .debug_cause_i(debug_cause_o),
    .debug_csr_save_i(debug_csr_save_o),
    .csr_depc_o,
    .debug_single_step_o,
    .debug_ebreakm_o,
    .debug_ebreaku_o,
    .pc_if_i,
    .pc_id_i,
    .csr_save_if_i(csr_save_if_o),
    .csr_save_id_i(csr_save_id_o),
    .csr_restore_mret_i(csr_restore_mret_id_o),
    .csr_restore_dret_i(csr_restore_dret_id_o),
    .csr_save_cause_i(csr_save_cause_o),
    .csr_mcause_i(exc_cause_o),
    .csr_mtval_i(csr_mtval_o),
    .illegal_csr_insn_o,
    .instr_new_id_i(1'b0),
    .instr_ret_i(1'b0),
    .instr_ret_compressed_i(1'b0),
    .imiss_i(1'b0),
    .pc_set_i(pc_set_o),
    .jump_i(1'b0),
    .branch_i(1'b0),
    .branch_taken_i(1'b0),
    .mem_load_i(1'b0),
    .mem_store_i(1'b0),
    .lsu_busy_i(1'b0)
  );

  task automatic tick;
    @(posedge clk_i);
    #1;
  endtask

  task automatic fail_value(
    input string case_id,
    input logic [31:0] expected,
    input logic [31:0] observed
  );
    $display("GOLDEN12_G06_VISIBLE_CASE_FAIL_B19F72C460AE35D8 case=%s expected=%08x observed=%08x",
             case_id, expected, observed);
    $fatal(1, "GOLDEN12_G06_VISIBLE_FUNCTIONAL_FAIL_B19F72C460AE35D8");
  endtask

  task automatic expect_value(
    input string case_id,
    input logic [31:0] expected,
    input logic [31:0] observed
  );
    if (observed !== expected) fail_value(case_id, expected, observed);
  endtask

  task automatic read_csr(input csr_num_e address, output logic [31:0] value);
    csr_access_i = 1'b1;
    csr_addr_i = address;
    csr_op_i = CSR_OP_READ;
    #1;
    value = csr_rdata_o;
    csr_access_i = 1'b0;
    #1;
  endtask

  task automatic take_normal_illegal_exception;
    pc_id_i = NORMAL_PC;
    instr_i = NORMAL_TVAL;
    instr_valid_i = 1'b1;
    illegal_insn_i = 1'b1;
    tick();
    instr_valid_i = 1'b0;
    illegal_insn_i = 1'b0;
    tick();
  endtask

  logic [31:0] observed_mcause;
  logic [31:0] observed_mtval;

  initial begin
    fetch_enable_i = 1'b0;
    illegal_insn_i = 1'b0;
    ecall_insn_i = 1'b0;
    mret_insn_i = 1'b0;
    dret_insn_i = 1'b0;
    wfi_insn_i = 1'b0;
    ebrk_insn_i = 1'b0;
    csr_pipe_flush_i = 1'b0;
    instr_valid_i = 1'b0;
    instr_i = '0;
    instr_compressed_i = '0;
    instr_is_compressed_i = 1'b0;
    instr_fetch_err_i = 1'b0;
    pc_id_i = '0;
    pc_if_i = DEBUG_PC;
    lsu_addr_last_i = '0;
    load_err_i = 1'b0;
    store_err_i = 1'b0;
    branch_set_i = 1'b0;
    jump_set_i = 1'b0;
    irq_nm_i = 1'b0;
    debug_req_i = 1'b0;
    stall_lsu_i = 1'b0;
    stall_multdiv_i = 1'b0;
    stall_jump_i = 1'b0;
    stall_branch_i = 1'b0;
    csr_access_i = 1'b0;
    csr_addr_i = CSR_MSTATUS;
    csr_wdata_i = '0;
    csr_op_i = CSR_OP_READ;

    repeat (2) tick();
    expect_value("reset_mepc", 32'h0, csr_mepc_o);
    expect_value("reset_depc", 32'h0, csr_depc_o);
    expect_value("reset_debug_mode", 32'h0, {31'b0, debug_mode_o});
    $display("GOLDEN12_G06_VISIBLE_CASE_PASS_B19F72C460AE35D8 case=reset_state");

    rst_ni = 1'b1;
    fetch_enable_i = 1'b1;
    repeat (3) tick();

    take_normal_illegal_exception();
    expect_value("normal_exception_mepc", NORMAL_PC, csr_mepc_o);
    read_csr(CSR_MCAUSE, observed_mcause);
    expect_value("normal_exception_mcause", 32'h0000_0002, observed_mcause);
    read_csr(CSR_MTVAL, observed_mtval);
    expect_value("normal_exception_mtval", NORMAL_TVAL, observed_mtval);
    $display("GOLDEN12_G06_VISIBLE_CASE_PASS_B19F72C460AE35D8 case=normal_exception_save");

    debug_req_i = 1'b1;
    tick();
    tick();
    debug_req_i = 1'b0;
    expect_value("fresh_debug_mode", 32'h1, {31'b0, debug_mode_o});
    expect_value("fresh_debug_dpc", DEBUG_PC, csr_depc_o);
    expect_value("fresh_debug_mepc", NORMAL_PC, csr_mepc_o);
    read_csr(CSR_MCAUSE, observed_mcause);
    expect_value("fresh_debug_mcause", 32'h0000_0002, observed_mcause);
    read_csr(CSR_MTVAL, observed_mtval);
    expect_value("fresh_debug_mtval", NORMAL_TVAL, observed_mtval);
    $display("GOLDEN12_G06_VISIBLE_CASE_PASS_B19F72C460AE35D8 case=fresh_debug_entry_preserves_machine_csrs");

    $display("GOLDEN12_G06_VISIBLE_SUITE_PASS_B19F72C460AE35D8");
    $finish;
  end
endmodule
