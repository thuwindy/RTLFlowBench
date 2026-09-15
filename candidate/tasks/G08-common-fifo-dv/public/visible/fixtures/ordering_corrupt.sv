module fifo_v3 #(
  parameter bit FALL_THROUGH = 1'b0,
  parameter int unsigned DATA_WIDTH = 32,
  parameter int unsigned DEPTH = 8,
  parameter type dtype = logic [DATA_WIDTH-1:0],
  parameter int unsigned ADDR_DEPTH = (DEPTH > 1) ? $clog2(DEPTH) : 1
) (
  input logic clk_i,
  input logic rst_ni,
  input logic flush_i,
  input logic testmode_i,
  output logic full_o,
  output logic empty_o,
  output logic [ADDR_DEPTH-1:0] usage_o,
  input dtype data_i,
  input logic push_i,
  output dtype data_o,
  input logic pop_i
);
  dtype mem [0:DEPTH-1];
  integer count;
  integer read_pointer;
  integer write_pointer;
  integer newest_pointer;
  logic unused_testmode;

  assign unused_testmode = testmode_i;
  assign full_o = count == DEPTH;
  assign empty_o = (count == 0) && !(FALL_THROUGH && push_i);
  assign usage_o = count[ADDR_DEPTH-1:0];
  assign newest_pointer = write_pointer == 0 ? DEPTH - 1 : write_pointer - 1;
  assign data_o = (FALL_THROUGH && count == 0 && push_i)
      ? data_i : mem[newest_pointer];

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni || flush_i) begin
      count <= 0;
      read_pointer <= 0;
      write_pointer <= 0;
    end else begin
      if (push_i && !full_o) begin
        mem[write_pointer] <= data_i;
        write_pointer <= (write_pointer + 1) % DEPTH;
        count <= count + 1;
      end
      if (pop_i && !empty_o) begin
        read_pointer <= (read_pointer + 1) % DEPTH;
        count <= count - 1;
      end
      if (push_i && pop_i && !full_o && !empty_o) count <= count;
      if (FALL_THROUGH && count == 0 && push_i && pop_i) count <= 0;
    end
  end
endmodule
