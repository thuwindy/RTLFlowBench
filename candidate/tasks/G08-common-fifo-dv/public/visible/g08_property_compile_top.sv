module g08_property_compile_top #(
  parameter bit FALL_THROUGH = 1'b0,
  parameter int unsigned DATA_WIDTH = 8,
  parameter int unsigned DEPTH = 5,
  parameter int unsigned ADDR_DEPTH = (DEPTH > 1) ? $clog2(DEPTH) : 1
);
  logic clk_i;
  logic rst_ni;
  logic flush_i;
  logic testmode_i;
  logic full_o;
  logic empty_o;
  logic [ADDR_DEPTH-1:0] usage_o;
  logic [DATA_WIDTH-1:0] data_i;
  logic push_i;
  logic [DATA_WIDTH-1:0] data_o;
  logic pop_i;

  fifo_v3 #(
    .FALL_THROUGH(FALL_THROUGH),
    .DATA_WIDTH(DATA_WIDTH),
    .DEPTH(DEPTH)
  ) dut (.*);

  g08_fifo_properties #(
    .FALL_THROUGH(FALL_THROUGH),
    .DATA_WIDTH(DATA_WIDTH),
    .DEPTH(DEPTH),
    .ADDR_DEPTH(ADDR_DEPTH)
  ) properties (.*);
endmodule
