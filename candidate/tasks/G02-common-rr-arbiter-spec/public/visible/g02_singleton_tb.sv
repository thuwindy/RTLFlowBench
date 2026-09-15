`timescale 1ns/1ps

module g02_singleton_tb;
  logic clk_i = 1'b0;
  logic rst_ni = 1'b0;
  logic [0:0] req_i = '0;
  logic grant_accept_i = 1'b0;
  logic lock_i = 1'b0;
  logic [0:0] grant_o;
  logic grant_valid_o;
  logic [0:0] grant_index_o;

  golden12_rr_arbiter #(.NUM_REQUESTERS(1)) dut (
    .clk_i(clk_i), .rst_ni(rst_ni), .req_i(req_i),
    .grant_accept_i(grant_accept_i), .lock_i(lock_i), .grant_o(grant_o),
    .grant_valid_o(grant_valid_o), .grant_index_o(grant_index_o)
  );
  always #5 clk_i = ~clk_i;

  initial begin
    #1;
    if ({grant_o, grant_valid_o, grant_index_o} !== '0) $fatal(1, "singleton reset output");
    @(negedge clk_i); rst_ni = 1'b1; req_i = 1'b1;
    #1;
    if (grant_o !== 1'b1 || grant_valid_o !== 1'b1 || grant_index_o !== 1'b0) $fatal(1, "singleton grant");
    grant_accept_i = 1'b1;
    @(posedge clk_i); #1; grant_accept_i = 1'b0;
    if (grant_o !== 1'b1 || grant_index_o !== 1'b0) $fatal(1, "singleton rotation");
    lock_i = 1'b1;
    @(posedge clk_i); #1;
    if (grant_o !== 1'b1) $fatal(1, "singleton lock");
    req_i = 1'b0; #1;
    if ({grant_o, grant_valid_o, grant_index_o} !== '0) $fatal(1, "singleton empty");
    $display("GOLDEN12_VISIBLE_PASS task=G02-common-rr-arbiter-spec requesters=1");
    $finish;
  end
endmodule
