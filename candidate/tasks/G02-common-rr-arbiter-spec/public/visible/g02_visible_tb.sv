`timescale 1ns/1ps

module g02_visible_tb;
  localparam int unsigned N = 4;
  localparam int unsigned IW = 2;

  logic clk_i = 1'b0;
  logic rst_ni = 1'b0;
  logic [N-1:0] req_i = '0;
  logic grant_accept_i = 1'b0;
  logic lock_i = 1'b0;
  logic [N-1:0] grant_o;
  logic grant_valid_o;
  logic [IW-1:0] grant_index_o;
  integer failures = 0;

  golden12_rr_arbiter #(.NUM_REQUESTERS(N)) dut (
    .clk_i(clk_i),
    .rst_ni(rst_ni),
    .req_i(req_i),
    .grant_accept_i(grant_accept_i),
    .lock_i(lock_i),
    .grant_o(grant_o),
    .grant_valid_o(grant_valid_o),
    .grant_index_o(grant_index_o)
  );

  always #5 clk_i = ~clk_i;

  task automatic check_grant(
    input logic [N-1:0] expected_grant,
    input integer expected_index,
    input string label
  );
    logic expected_valid;
    begin
      #1;
      expected_valid = |expected_grant;
      if (grant_o !== expected_grant ||
          grant_valid_o !== expected_valid ||
          (expected_valid && grant_index_o !== expected_index[IW-1:0]) ||
          (!expected_valid && grant_index_o !== '0) ||
          (^grant_o === 1'bx) ||
          (grant_valid_o === 1'bx) ||
          (^grant_index_o === 1'bx)) begin
        $display("G02_VISIBLE_FAIL label=%s grant=%b valid=%b index=%0d", label, grant_o, grant_valid_o, grant_index_o);
        failures = failures + 1;
      end
    end
  endtask

  task automatic accept_edge;
    begin
      grant_accept_i = 1'b1;
      @(posedge clk_i);
      #1;
      grant_accept_i = 1'b0;
    end
  endtask

  task automatic reset_dut;
    begin
      req_i = '1;
      lock_i = 1'b1;
      grant_accept_i = 1'b1;
      rst_ni = 1'b0;
      #2;
      check_grant('0, 0, "async_reset");
      @(negedge clk_i);
      req_i = '0;
      lock_i = 1'b0;
      grant_accept_i = 1'b0;
      rst_ni = 1'b1;
      #1;
    end
  endtask

  initial begin
    reset_dut();

    req_i = 4'b1111;
    check_grant(4'b0001, 0, "reset_priority");
    accept_edge(); check_grant(4'b0010, 1, "rotate_1");
    accept_edge(); check_grant(4'b0100, 2, "rotate_2");
    accept_edge(); check_grant(4'b1000, 3, "rotate_3");
    accept_edge(); check_grant(4'b0001, 0, "wrap_0");

    req_i = 4'b1010;
    check_grant(4'b0010, 1, "stall_initial");
    repeat (2) @(posedge clk_i);
    check_grant(4'b0010, 1, "stall_stable");

    accept_edge();
    req_i = '0;
    check_grant('0, 0, "no_request");
    repeat (2) @(posedge clk_i);
    req_i = 4'b1010;
    check_grant(4'b1000, 3, "no_request_keeps_priority");

    reset_dut();
    req_i = 4'b0010;
    check_grant(4'b0010, 1, "lock_candidate");
    lock_i = 1'b1;
    @(posedge clk_i);
    #1;
    req_i = 4'b1111;
    check_grant(4'b0010, 1, "lock_non_preempt");
    accept_edge();
    check_grant(4'b0010, 1, "lock_suppresses_accept");
    req_i = 4'b1101;
    check_grant(4'b0001, 0, "lock_owner_drop_reselect");
    @(posedge clk_i);
    check_grant(4'b0001, 0, "lock_new_owner_held");
    lock_i = 1'b0;
    accept_edge();
    check_grant(4'b0100, 2, "unlock_rotates");

    rst_ni = 1'b0;
    #1;
    check_grant('0, 0, "final_async_reset");

    if (failures != 0) begin
      $display("G02_VISIBLE_FAIL failures=%0d", failures);
      $fatal(1);
    end
    $display("GOLDEN12_VISIBLE_PASS task=G02-common-rr-arbiter-spec requesters=4");
    $finish;
  end
endmodule

module g02_compile_probe;
  logic clk_i, rst_ni, grant_accept_i, lock_i;
  logic [2:0] req3, grant3;
  logic [1:0] index3;
  logic valid3;
  logic [4:0] req5, grant5;
  logic [2:0] index5;
  logic valid5;

  golden12_rr_arbiter #(.NUM_REQUESTERS(3)) dut3 (
    .clk_i(clk_i), .rst_ni(rst_ni), .req_i(req3),
    .grant_accept_i(grant_accept_i), .lock_i(lock_i), .grant_o(grant3),
    .grant_valid_o(valid3), .grant_index_o(index3)
  );
  golden12_rr_arbiter #(.NUM_REQUESTERS(5)) dut5 (
    .clk_i(clk_i), .rst_ni(rst_ni), .req_i(req5),
    .grant_accept_i(grant_accept_i), .lock_i(lock_i), .grant_o(grant5),
    .grant_valid_o(valid5), .grant_index_o(index5)
  );
endmodule
