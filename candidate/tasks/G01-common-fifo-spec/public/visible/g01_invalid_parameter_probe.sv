`timescale 1ns/1ps

module g01_invalid_parameter_probe #(
  parameter integer DATA_WIDTH = 0,
  parameter integer DEPTH = 4
);
  localparam integer SAFE_DATA_WIDTH = DATA_WIDTH > 0 ? DATA_WIDTH : 1;
  localparam integer SAFE_FILL_WIDTH = DEPTH > 0 ? $clog2(DEPTH + 1) : 1;

  reg clk_i;
  reg rst_ni;
  reg in_valid_i;
  wire in_ready_o;
  reg [SAFE_DATA_WIDTH-1:0] in_data_i;
  wire out_valid_o;
  reg out_ready_i;
  wire [SAFE_DATA_WIDTH-1:0] out_data_o;
  wire empty_o;
  wire full_o;
  wire [SAFE_FILL_WIDTH-1:0] fill_level_o;

  golden12_fifo #(
    .DATA_WIDTH(DATA_WIDTH),
    .DEPTH(DEPTH)
  ) dut (
    .clk_i(clk_i),
    .rst_ni(rst_ni),
    .in_valid_i(in_valid_i),
    .in_ready_o(in_ready_o),
    .in_data_i(in_data_i),
    .out_valid_o(out_valid_o),
    .out_ready_i(out_ready_i),
    .out_data_o(out_data_o),
    .empty_o(empty_o),
    .full_o(full_o),
    .fill_level_o(fill_level_o)
  );

  initial begin
    clk_i = 1'b0;
    rst_ni = 1'b0;
    in_valid_i = 1'b0;
    in_data_i = {SAFE_DATA_WIDTH{1'b0}};
    out_ready_i = 1'b0;
    #1;
    $display(
      "GOLDEN12_INVALID_PARAMETER_ACCEPTED width=%0d depth=%0d",
      DATA_WIDTH,
      DEPTH
    );
    $finish;
  end
endmodule
