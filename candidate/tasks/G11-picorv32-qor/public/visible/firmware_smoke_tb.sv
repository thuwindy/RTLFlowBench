`timescale 1 ns / 1 ps

module g11_visible_firmware_smoke_tb;
    localparam integer MAX_CYCLES = 2048;

    reg clk = 0;
    reg resetn = 0;
    wire trap;
    wire mem_valid;
    wire mem_instr;
    reg mem_ready = 0;
    wire [31:0] mem_addr;
    wire [31:0] mem_wdata;
    wire [3:0] mem_wstrb;
    reg [31:0] mem_rdata = 0;
    wire mem_la_read;
    wire mem_la_write;
    wire [31:0] mem_la_addr;
    wire [31:0] mem_la_wdata;
    wire [3:0] mem_la_wstrb;
    wire pcpi_valid;
    wire [31:0] pcpi_insn;
    wire [31:0] pcpi_rs1;
    wire [31:0] pcpi_rs2;
    reg pcpi_wr = 0;
    reg [31:0] pcpi_rd = 0;
    reg pcpi_wait = 0;
    reg pcpi_ready = 0;
    reg [31:0] irq = 0;
    wire [31:0] eoi;
    wire trace_valid;
    wire [35:0] trace_data;
    reg observed_store = 0;
    integer cycles = 0;

    always #5 clk = !clk;

    picorv32 #(
        .ENABLE_COUNTERS(1),
        .ENABLE_COUNTERS64(1),
        .ENABLE_REGS_16_31(1),
        .ENABLE_REGS_DUALPORT(1),
        .LATCHED_MEM_RDATA(0),
        .TWO_STAGE_SHIFT(1),
        .BARREL_SHIFTER(1),
        .TWO_CYCLE_COMPARE(0),
        .TWO_CYCLE_ALU(0),
        .COMPRESSED_ISA(1),
        .CATCH_MISALIGN(1),
        .CATCH_ILLINSN(1),
        .ENABLE_PCPI(1),
        .ENABLE_MUL(1),
        .ENABLE_FAST_MUL(0),
        .ENABLE_DIV(0),
        .ENABLE_IRQ(1),
        .ENABLE_IRQ_QREGS(1),
        .ENABLE_IRQ_TIMER(1),
        .ENABLE_TRACE(0),
        .REGS_INIT_ZERO(0),
        .MASKED_IRQ(32'h0000_0000),
        .LATCHED_IRQ(32'hffff_ffff),
        .PROGADDR_RESET(32'h0000_0000),
        .PROGADDR_IRQ(32'h0000_0010),
        .STACKADDR(32'hffff_ffff)
    ) dut (
        .clk(clk), .resetn(resetn), .trap(trap),
        .mem_valid(mem_valid), .mem_instr(mem_instr), .mem_ready(mem_ready),
        .mem_addr(mem_addr), .mem_wdata(mem_wdata), .mem_wstrb(mem_wstrb),
        .mem_rdata(mem_rdata),
        .mem_la_read(mem_la_read), .mem_la_write(mem_la_write),
        .mem_la_addr(mem_la_addr), .mem_la_wdata(mem_la_wdata),
        .mem_la_wstrb(mem_la_wstrb),
        .pcpi_valid(pcpi_valid), .pcpi_insn(pcpi_insn),
        .pcpi_rs1(pcpi_rs1), .pcpi_rs2(pcpi_rs2),
        .pcpi_wr(pcpi_wr), .pcpi_rd(pcpi_rd), .pcpi_wait(pcpi_wait),
        .pcpi_ready(pcpi_ready), .irq(irq), .eoi(eoi),
        .trace_valid(trace_valid), .trace_data(trace_data)
    );

    always @(posedge clk) begin
        mem_ready <= 0;
        if (mem_valid && !mem_ready) begin
            mem_ready <= 1;
            case (mem_addr)
                32'h0000_0000: mem_rdata <= 32'h0050_0093; // addi x1, x0, 5
                32'h0000_0004: mem_rdata <= 32'h0070_8113; // addi x2, x1, 7
                32'h0000_0008: mem_rdata <= 32'h0420_2023; // sw x2, 64(x0)
                32'h0000_000c: mem_rdata <= 32'h0000_006f; // jal x0, 0
                default: mem_rdata <= 32'h0000_006f;
            endcase
        end
        if (mem_valid && mem_ready && |mem_wstrb) begin
            if (mem_addr == 32'h0000_0040 && mem_wstrb == 4'b1111 && mem_wdata == 32'd12)
                observed_store <= 1;
            else begin
                $display("GOLDEN12_G11_VISIBLE_SMOKE_FAIL unexpected_store addr=%08x data=%08x strb=%x", mem_addr, mem_wdata, mem_wstrb);
                $finish_and_return(1);
            end
        end
    end

    initial begin
        repeat (4) @(posedge clk);
        resetn <= 1;
        while (cycles < MAX_CYCLES && !observed_store) begin
            @(posedge clk);
            cycles = cycles + 1;
            if (trap) begin
                $display("GOLDEN12_G11_VISIBLE_SMOKE_FAIL trap");
                $finish_and_return(1);
            end
        end
        if (!observed_store) begin
            $display("GOLDEN12_G11_VISIBLE_SMOKE_FAIL timeout");
            $finish_and_return(1);
        end
        $display("GOLDEN12_G11_VISIBLE_SMOKE_PASS");
        $finish;
    end
endmodule
