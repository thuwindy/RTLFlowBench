module g02_invalid_parameter_probe;
  logic clk_i, rst_ni, grant_accept_i, lock_i;
  logic [0:0] req_i, grant_o;
  logic grant_valid_o;
  logic [0:0] grant_index_o;

  golden12_rr_arbiter #(.NUM_REQUESTERS(0)) dut (
    .clk_i(clk_i), .rst_ni(rst_ni), .req_i(req_i),
    .grant_accept_i(grant_accept_i), .lock_i(lock_i), .grant_o(grant_o),
    .grant_valid_o(grant_valid_o), .grant_index_o(grant_index_o)
  );
  initial begin
    #1;
    $display("G02_INVALID_PARAMETER_NOT_REJECTED");
    $finish;
  end
endmodule
