`timescale 1ns/1ps

module g01_visible_tb #(
  parameter integer DATA_WIDTH = 32,
  parameter integer DEPTH = 4
);
  localparam integer FILL_WIDTH = $clog2(DEPTH + 1);

  reg clk_i;
  reg rst_ni;
  reg in_valid_i;
  wire in_ready_o;
  reg [DATA_WIDTH-1:0] in_data_i;
  wire out_valid_o;
  reg out_ready_i;
  wire [DATA_WIDTH-1:0] out_data_o;
  wire empty_o;
  wire full_o;
  wire [FILL_WIDTH-1:0] fill_level_o;

  reg [DATA_WIDTH-1:0] model_mem [0:DEPTH-1];
  integer model_head;
  integer model_tail;
  integer model_count;
  integer sequence_id;
  integer round_id;

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

  always #5 clk_i = ~clk_i;

  function automatic [DATA_WIDTH-1:0] word_for;
    input integer value;
    begin
      word_for = (value * 37) ^ (value >> 1) ^ 32'h5a5aa5a5;
    end
  endfunction

  task automatic visible_fail;
    input [8*160-1:0] message;
    begin
      $display("GOLDEN12_VISIBLE_FAIL %0s", message);
      $fatal(1);
    end
  endtask

  task automatic check_state;
    begin
      if (empty_o !== (model_count == 0))
        visible_fail("empty_o does not match modeled occupancy");
      if (full_o !== (model_count == DEPTH))
        visible_fail("full_o does not match modeled occupancy");
      if (fill_level_o !== model_count)
        visible_fail("fill_level_o does not match modeled occupancy");
      if (out_valid_o !== (model_count > 0))
        visible_fail("out_valid_o does not match modeled occupancy");
      if (model_count > 0 && out_data_o !== model_mem[model_head])
        visible_fail("out_data_o does not match the modeled FIFO head");
    end
  endtask

  task automatic drive_cycle;
    input req_in_valid;
    input [DATA_WIDTH-1:0] req_in_data;
    input req_out_ready;
    integer accepted_enqueue;
    integer accepted_dequeue;
    integer expected_ready;
    begin
      @(negedge clk_i);
      in_valid_i = req_in_valid;
      in_data_i = req_in_data;
      out_ready_i = req_out_ready;
      #1;

      check_state();
      expected_ready = (model_count < DEPTH) ||
                       ((model_count > 0) && req_out_ready);
      if (in_ready_o !== expected_ready)
        visible_fail("in_ready_o violates the full-throughput contract");

      accepted_enqueue = in_valid_i && in_ready_o;
      accepted_dequeue = out_valid_o && out_ready_i;
      @(posedge clk_i);
      #1;

      if (accepted_dequeue) begin
        if (model_head == DEPTH - 1)
          model_head = 0;
        else
          model_head = model_head + 1;
        model_count = model_count - 1;
      end
      if (accepted_enqueue) begin
        model_mem[model_tail] = req_in_data;
        if (model_tail == DEPTH - 1)
          model_tail = 0;
        else
          model_tail = model_tail + 1;
        model_count = model_count + 1;
      end
      check_state();
    end
  endtask

  initial begin
    clk_i = 1'b0;
    rst_ni = 1'b0;
    in_valid_i = 1'b0;
    in_data_i = {DATA_WIDTH{1'b0}};
    out_ready_i = 1'b0;
    model_head = 0;
    model_tail = 0;
    model_count = 0;
    sequence_id = 1;

    repeat (2) begin
      @(posedge clk_i);
      #1;
      check_state();
    end
    @(negedge clk_i);
    rst_ni = 1'b1;

    // Empty simultaneous request: enqueue is accepted, dequeue is not.
    drive_cycle(1'b1, word_for(sequence_id), 1'b1);
    sequence_id = sequence_id + 1;

    // A stalled valid output remains stable.
    drive_cycle(1'b0, {DATA_WIDTH{1'b0}}, 1'b0);
    drive_cycle(1'b0, {DATA_WIDTH{1'b0}}, 1'b0);
    drive_cycle(1'b0, {DATA_WIDTH{1'b0}}, 1'b1);

    // Empty underflow attempt has no state effect.
    drive_cycle(1'b0, {DATA_WIDTH{1'b0}}, 1'b1);

    // With exactly one queued word, a simultaneous dequeue/enqueue replaces
    // the head.  The replacement must be the next visible word; returning a
    // stale memory value would violate ordering even though occupancy stays 1.
    drive_cycle(1'b1, word_for(sequence_id), 1'b0);
    sequence_id = sequence_id + 1;
    drive_cycle(1'b1, word_for(sequence_id), 1'b1);
    sequence_id = sequence_id + 1;
    drive_cycle(1'b0, {DATA_WIDTH{1'b0}}, 1'b1);

    // Fill to capacity, reject overflow, then sustain one word/cycle at full.
    while (model_count < DEPTH) begin
      drive_cycle(1'b1, word_for(sequence_id), 1'b0);
      sequence_id = sequence_id + 1;
    end
    drive_cycle(1'b1, word_for(sequence_id), 1'b0);
    drive_cycle(1'b1, word_for(sequence_id), 1'b1);
    sequence_id = sequence_id + 1;
    while (model_count > 0)
      drive_cycle(1'b0, {DATA_WIDTH{1'b0}}, 1'b1);

    // Repeated complete fills and drains exercise non-power-of-two wraparound.
    for (round_id = 0; round_id < 3; round_id = round_id + 1) begin
      while (model_count < DEPTH) begin
        drive_cycle(1'b1, word_for(sequence_id), 1'b0);
        sequence_id = sequence_id + 1;
      end
      while (model_count > 0)
        drive_cycle(1'b0, {DATA_WIDTH{1'b0}}, 1'b1);
    end

    // Synchronous reset must not change state before the next rising edge.
    drive_cycle(1'b1, word_for(sequence_id), 1'b0);
    @(negedge clk_i);
    rst_ni = 1'b0;
    in_valid_i = 1'b1;
    out_ready_i = 1'b1;
    #2;
    check_state();
    @(posedge clk_i);
    #1;
    model_head = 0;
    model_tail = 0;
    model_count = 0;
    check_state();

    $display(
      "GOLDEN12_VISIBLE_PASS task=G01-common-fifo-spec width=%0d depth=%0d",
      DATA_WIDTH,
      DEPTH
    );
    $finish;
  end
endmodule
