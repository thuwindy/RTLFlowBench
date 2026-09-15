`default_nettype none

// Public, independently written SERV smoke.  The program executes:
//   addi x1, x0, 5
//   addi x2, x1, 7
//   sw   x2, 64(x0)
//   jal  x0, 0
// A pass requires the exact observable word-store transaction below.
module g10_visible_software_smoke_tb;
  localparam integer MAX_CYCLES = 4096;

  reg clk;
  reg i_rst;
  reg i_timer_irq;
  reg [1:0] rf_mem [0:1023];
  reg [1:0] rf_read_data;
  reg rf_read_is_x0;
  integer index;
  integer cycle_count;

  wire [31:0] o_ibus_adr;
  wire o_ibus_cyc;
  reg [31:0] i_ibus_rdt;
  wire i_ibus_ack;
  wire [31:0] o_dbus_adr;
  wire [31:0] o_dbus_dat;
  wire [3:0] o_dbus_sel;
  wire o_dbus_we;
  wire o_dbus_cyc;
  wire [31:0] i_dbus_rdt;
  wire i_dbus_ack;
  wire [9:0] o_waddr;
  wire [1:0] o_wdata;
  wire o_wen;
  wire [9:0] o_raddr;
  wire [1:0] i_rdata;

  always #5 clk = ~clk;

  assign i_ibus_ack = o_ibus_cyc;
  assign i_dbus_ack = o_dbus_cyc;
  assign i_dbus_rdt = 32'h00000000;
  assign i_rdata = rf_read_data & {2{~rf_read_is_x0}};

  always @* begin
    case (o_ibus_adr)
      32'h00000000: i_ibus_rdt = 32'h00500093;
      32'h00000004: i_ibus_rdt = 32'h00708113;
      32'h00000008: i_ibus_rdt = 32'h04202023;
      32'h0000000c: i_ibus_rdt = 32'h0000006f;
      default:      i_ibus_rdt = 32'h00000013;
    endcase
  end

  always @(posedge clk) begin
    if (o_wen && (|o_waddr[9:4]))
      rf_mem[o_waddr] <= o_wdata;
    rf_read_data <= rf_mem[o_raddr];
    rf_read_is_x0 <= !(|o_raddr[9:4]);
  end

  serv_synth_wrapper #(
    .PRE_REGISTER(1),
    .RESET_STRATEGY("MINI"),
    .WITH_CSR(1),
    .RF_WIDTH(2),
    .RF_L2D(10)
  ) dut (
    .clk(clk),
    .i_rst(i_rst),
    .i_timer_irq(i_timer_irq),
    .o_ibus_adr(o_ibus_adr),
    .o_ibus_cyc(o_ibus_cyc),
    .i_ibus_rdt(i_ibus_rdt),
    .i_ibus_ack(i_ibus_ack),
    .o_dbus_adr(o_dbus_adr),
    .o_dbus_dat(o_dbus_dat),
    .o_dbus_sel(o_dbus_sel),
    .o_dbus_we(o_dbus_we),
    .o_dbus_cyc(o_dbus_cyc),
    .i_dbus_rdt(i_dbus_rdt),
    .i_dbus_ack(i_dbus_ack),
    .o_waddr(o_waddr),
    .o_wdata(o_wdata),
    .o_wen(o_wen),
    .o_raddr(o_raddr),
    .i_rdata(i_rdata)
  );

  initial begin
    clk = 1'b0;
    i_rst = 1'b1;
    i_timer_irq = 1'b0;
    rf_read_data = 2'b00;
    rf_read_is_x0 = 1'b1;
    cycle_count = 0;
    for (index = 0; index < 1024; index = index + 1)
      rf_mem[index] = 2'b00;

    repeat (6) @(posedge clk);
    @(negedge clk);
    i_rst = 1'b0;

    while (cycle_count < MAX_CYCLES) begin
      @(posedge clk);
      #1;
      cycle_count = cycle_count + 1;
      if (o_dbus_cyc && o_dbus_we && i_dbus_ack) begin
        if (
          (o_dbus_adr === 32'h00000040) &&
          (o_dbus_dat === 32'h0000000c) &&
          (o_dbus_sel === 4'b1111)
        ) begin
          $display("GOLDEN12_G10_VISIBLE_SMOKE_PASS");
          $finish;
        end
        $display(
          "GOLDEN12_G10_VISIBLE_SMOKE_FAIL address=%08x data=%08x sel=%x",
          o_dbus_adr,
          o_dbus_dat,
          o_dbus_sel
        );
        $fatal(1, "unexpected data-bus write");
      end
    end

    $display("GOLDEN12_G10_VISIBLE_SMOKE_FAIL timeout_cycles=%0d", MAX_CYCLES);
    $fatal(1, "expected word store was not observed");
  end
endmodule

`default_nettype wire
