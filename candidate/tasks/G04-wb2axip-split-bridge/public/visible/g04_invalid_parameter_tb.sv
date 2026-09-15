`timescale 1ns/1ps

module g04_visible_invalid_parameter_tb;
    localparam integer C_AXI_DATA_WIDTH = 24;
    localparam integer C_AXI_ADDR_WIDTH = 16;
    localparam integer WB_ADDR_WIDTH = C_AXI_ADDR_WIDTH-$clog2(C_AXI_DATA_WIDTH/8);

    reg i_clk = 1'b0;
    reg i_axi_reset_n = 1'b0;
    wire o_axi_awready, o_axi_wready, o_axi_bvalid;
    wire [1:0] o_axi_bresp;
    wire o_axi_arready, o_axi_rvalid;
    wire [C_AXI_DATA_WIDTH-1:0] o_axi_rdata;
    wire [1:0] o_axi_rresp;
    wire o_reset, o_wb_cyc, o_wb_stb, o_wb_we;
    wire [WB_ADDR_WIDTH-1:0] o_wb_addr;
    wire [C_AXI_DATA_WIDTH-1:0] o_wb_data;
    wire [C_AXI_DATA_WIDTH/8-1:0] o_wb_sel;

    golden12_axil_wb_split_bridge #(
        .C_AXI_DATA_WIDTH(C_AXI_DATA_WIDTH),
        .C_AXI_ADDR_WIDTH(C_AXI_ADDR_WIDTH),
        .LGFIFO(2)
    ) dut (
        .i_clk(i_clk), .i_axi_reset_n(i_axi_reset_n),
        .i_axi_awvalid(1'b0), .o_axi_awready(o_axi_awready),
        .i_axi_awaddr({C_AXI_ADDR_WIDTH{1'b0}}), .i_axi_awprot(3'b000),
        .i_axi_wvalid(1'b0), .o_axi_wready(o_axi_wready),
        .i_axi_wdata({C_AXI_DATA_WIDTH{1'b0}}), .i_axi_wstrb({C_AXI_DATA_WIDTH/8{1'b0}}),
        .o_axi_bvalid(o_axi_bvalid), .i_axi_bready(1'b0), .o_axi_bresp(o_axi_bresp),
        .i_axi_arvalid(1'b0), .o_axi_arready(o_axi_arready),
        .i_axi_araddr({C_AXI_ADDR_WIDTH{1'b0}}), .i_axi_arprot(3'b000),
        .o_axi_rvalid(o_axi_rvalid), .i_axi_rready(1'b0),
        .o_axi_rdata(o_axi_rdata), .o_axi_rresp(o_axi_rresp),
        .o_reset(o_reset), .o_wb_cyc(o_wb_cyc), .o_wb_stb(o_wb_stb),
        .o_wb_we(o_wb_we), .o_wb_addr(o_wb_addr), .o_wb_data(o_wb_data),
        .o_wb_sel(o_wb_sel), .i_wb_stall(1'b0), .i_wb_ack(1'b0),
        .i_wb_data({C_AXI_DATA_WIDTH{1'b0}}), .i_wb_err(1'b0)
    );

    always #5 i_clk = ~i_clk;
    initial begin
        #2;
        $display("GOLDEN12_G04_VISIBLE_INVALID_PARAMETER_FAIL data_width=24");
        $finish;
    end
endmodule
