`timescale 1ns/1ps
`default_nettype none

module g04_visible_tb;
    localparam integer C_AXI_DATA_WIDTH = 32;
    localparam integer C_AXI_ADDR_WIDTH = 16;
    localparam integer BYTE_LANES = C_AXI_DATA_WIDTH/8;
    localparam integer WB_ADDR_WIDTH = C_AXI_ADDR_WIDTH-$clog2(BYTE_LANES);

    reg i_clk = 1'b0;
    reg i_axi_reset_n = 1'b0;
    reg i_axi_awvalid = 1'b0;
    wire o_axi_awready;
    reg [C_AXI_ADDR_WIDTH-1:0] i_axi_awaddr = 0;
    reg [2:0] i_axi_awprot = 0;
    reg i_axi_wvalid = 1'b0;
    wire o_axi_wready;
    reg [C_AXI_DATA_WIDTH-1:0] i_axi_wdata = 0;
    reg [BYTE_LANES-1:0] i_axi_wstrb = 0;
    wire o_axi_bvalid;
    reg i_axi_bready = 1'b1;
    wire [1:0] o_axi_bresp;
    reg i_axi_arvalid = 1'b0;
    wire o_axi_arready;
    reg [C_AXI_ADDR_WIDTH-1:0] i_axi_araddr = 0;
    reg [2:0] i_axi_arprot = 0;
    wire o_axi_rvalid;
    reg i_axi_rready = 1'b1;
    wire [C_AXI_DATA_WIDTH-1:0] o_axi_rdata;
    wire [1:0] o_axi_rresp;
    wire o_reset;
    wire o_wb_cyc, o_wb_stb, o_wb_we;
    wire [WB_ADDR_WIDTH-1:0] o_wb_addr;
    wire [C_AXI_DATA_WIDTH-1:0] o_wb_data;
    wire [BYTE_LANES-1:0] o_wb_sel;
    reg i_wb_stall = 1'b0;
    reg i_wb_ack = 1'b0;
    reg [C_AXI_DATA_WIDTH-1:0] i_wb_data = 0;
    reg i_wb_err = 1'b0;

    always #5 i_clk = ~i_clk;

    golden12_axil_wb_split_bridge #(
        .C_AXI_DATA_WIDTH(C_AXI_DATA_WIDTH),
        .C_AXI_ADDR_WIDTH(C_AXI_ADDR_WIDTH),
        .LGFIFO(2)
    ) dut (.*);

    task automatic fail(input [8*128-1:0] reason);
        begin
            $display("GOLDEN12_VISIBLE_FAIL %0s", reason);
            $fatal(1);
        end
    endtask

    task automatic apply_reset;
        begin
            @(negedge i_clk);
            i_axi_reset_n = 1'b0;
            repeat (3) begin
                @(posedge i_clk);
                if (!o_reset) fail("o_reset not asserted");
                if (o_wb_cyc || o_wb_stb) fail("Wishbone active during reset");
            end
            @(negedge i_clk);
            i_axi_reset_n = 1'b1;
            if (o_reset) fail("o_reset not deasserted");
        end
    endtask

    task automatic send_ar(input [C_AXI_ADDR_WIDTH-1:0] addr);
        integer cycles;
        begin
            @(negedge i_clk);
            i_axi_araddr = addr;
            i_axi_arvalid = 1'b1;
            cycles = 0;
            do begin
                @(posedge i_clk);
                cycles = cycles + 1;
                if (cycles > 40) fail("AR handshake timeout");
            end while (!o_axi_arready);
            @(negedge i_clk);
            i_axi_arvalid = 1'b0;
        end
    endtask

    task automatic send_aw(input [C_AXI_ADDR_WIDTH-1:0] addr);
        integer cycles;
        begin
            @(negedge i_clk);
            i_axi_awaddr = addr;
            i_axi_awvalid = 1'b1;
            cycles = 0;
            do begin
                @(posedge i_clk);
                cycles = cycles + 1;
                if (cycles > 40) fail("AW handshake timeout");
            end while (!o_axi_awready);
            @(negedge i_clk);
            i_axi_awvalid = 1'b0;
        end
    endtask

    task automatic send_w(
        input [C_AXI_DATA_WIDTH-1:0] data,
        input [BYTE_LANES-1:0] sel
    );
        integer cycles;
        begin
            @(negedge i_clk);
            i_axi_wdata = data;
            i_axi_wstrb = sel;
            i_axi_wvalid = 1'b1;
            cycles = 0;
            do begin
                @(posedge i_clk);
                cycles = cycles + 1;
                if (cycles > 40) fail("W handshake timeout");
            end while (!o_axi_wready);
            @(negedge i_clk);
            i_axi_wvalid = 1'b0;
        end
    endtask

    task automatic expect_wb(
        input expected_we,
        input [WB_ADDR_WIDTH-1:0] expected_addr,
        input [C_AXI_DATA_WIDTH-1:0] expected_data,
        input [BYTE_LANES-1:0] expected_sel
    );
        integer cycles;
        reg [WB_ADDR_WIDTH-1:0] held_addr;
        reg [C_AXI_DATA_WIDTH-1:0] held_data;
        reg [BYTE_LANES-1:0] held_sel;
        reg held_we;
        begin
            cycles = 0;
            while (!(o_wb_cyc && o_wb_stb)) begin
                @(posedge i_clk);
                cycles = cycles + 1;
                if (cycles > 60) fail("Wishbone request timeout");
            end
            @(negedge i_clk);
            if (o_wb_we !== expected_we) fail("Wishbone WE mismatch");
            if (o_wb_addr !== expected_addr) fail("Wishbone address mismatch");
            if (o_wb_data !== expected_data) fail("Wishbone data mismatch");
            if (o_wb_sel !== expected_sel) fail("Wishbone select mismatch");
            held_we = o_wb_we;
            held_addr = o_wb_addr;
            held_data = o_wb_data;
            held_sel = o_wb_sel;
            if (i_wb_stall) begin
                repeat (3) begin
                    @(posedge i_clk);
                    if (!o_wb_cyc || !o_wb_stb) fail("stalled request withdrawn");
                    if (o_wb_we !== held_we || o_wb_addr !== held_addr ||
                        o_wb_data !== held_data || o_wb_sel !== held_sel)
                        fail("stalled Wishbone fields changed");
                end
            end
        end
    endtask

    task automatic ack_current(input [C_AXI_DATA_WIDTH-1:0] data);
        begin
            @(negedge i_clk);
            i_wb_stall = 1'b0;
            @(posedge i_clk);
            @(negedge i_clk);
            i_wb_data = data;
            i_wb_ack = 1'b1;
            @(posedge i_clk);
            @(negedge i_clk);
            i_wb_ack = 1'b0;
        end
    endtask

    task automatic err_current;
        begin
            @(negedge i_clk);
            i_wb_stall = 1'b0;
            @(posedge i_clk);
            @(negedge i_clk);
            i_wb_err = 1'b1;
            @(posedge i_clk);
            @(negedge i_clk);
            i_wb_err = 1'b0;
        end
    endtask

    task automatic expect_r(
        input [C_AXI_DATA_WIDTH-1:0] data,
        input [1:0] resp
    );
        integer cycles;
        begin
            cycles = 0;
            while (!o_axi_rvalid) begin
                @(posedge i_clk);
                cycles = cycles + 1;
                if (cycles > 60) fail("R response timeout");
            end
            if (o_axi_rdata !== data) fail("R data mismatch");
            if (o_axi_rresp !== resp) fail("R response mismatch");
            @(negedge i_clk);
        end
    endtask

    task automatic expect_b(input [1:0] resp);
        integer cycles;
        begin
            cycles = 0;
            while (!o_axi_bvalid) begin
                @(posedge i_clk);
                cycles = cycles + 1;
                if (cycles > 60) fail("B response timeout");
            end
            if (o_axi_bresp !== resp) fail("B response mismatch");
            @(negedge i_clk);
        end
    endtask

    initial begin
        apply_reset();

        // Stray completion inputs while idle must not create AXI responses.
        @(negedge i_clk); i_wb_ack = 1'b1;
        @(posedge i_clk);
        @(negedge i_clk); i_wb_ack = 1'b0;
        repeat (3) begin
            @(posedge i_clk);
            if (o_axi_rvalid || o_axi_bvalid) fail("idle ACK created response");
        end

        // Read through external backpressure, including stalled-field stability.
        i_wb_stall = 1'b1;
        send_ar(16'h0124);
        expect_wb(1'b0, 14'h0049, 32'h00000000, 4'hf);
        ack_current(32'h13579bdf);
        expect_r(32'h13579bdf, 2'b00);

        // AW-before-W write.
        send_aw(16'h0208);
        repeat (2) @(posedge i_clk);
        send_w(32'hdeadbeef, 4'b1011);
        expect_wb(1'b1, 14'h0082, 32'hdeadbeef, 4'b1011);
        ack_current(32'h00000000);
        expect_b(2'b00);

        // W-before-AW write.
        send_w(32'hc001d00d, 4'b0111);
        repeat (2) @(posedge i_clk);
        send_aw(16'h030c);
        expect_wb(1'b1, 14'h00c3, 32'hc001d00d, 4'b0111);
        ack_current(32'h00000000);
        expect_b(2'b00);

        // Reset restores read preference when read and write become ready together.
        apply_reset();
        fork
            send_ar(16'h0400);
            begin
                fork
                    send_aw(16'h0500);
                    send_w(32'h55aa33cc, 4'hf);
                join
            end
        join
        expect_wb(1'b0, 14'h0100, 32'h00000000, 4'hf);
        ack_current(32'h2468ace0);
        expect_r(32'h2468ace0, 2'b00);
        expect_wb(1'b1, 14'h0140, 32'h55aa33cc, 4'hf);
        ack_current(32'h00000000);
        expect_b(2'b00);

        // Read and write errors map only to the matching AXI channel.
        send_ar(16'h0600);
        expect_wb(1'b0, 14'h0180, 32'h00000000, 4'hf);
        err_current();
        expect_r(32'h00000000, 2'b10);
        if (o_axi_bvalid) fail("read error leaked to B channel");

        send_aw(16'h0700);
        send_w(32'h11223344, 4'hf);
        expect_wb(1'b1, 14'h01c0, 32'h11223344, 4'hf);
        err_current();
        expect_b(2'b10);
        if (o_axi_rvalid) fail("write error leaked to R channel");

        $display("GOLDEN12_VISIBLE_PASS task=G04-wb2axip-split-bridge data_width=32 addr_width=16");
        $finish;
    end

    initial begin
        #30000;
        fail("global timeout");
    end
endmodule

`default_nettype wire
