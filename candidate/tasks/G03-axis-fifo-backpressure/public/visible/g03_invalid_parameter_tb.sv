`timescale 1ns/1ps

module g03_visible_invalid_parameter_probe #(
    parameter integer DATA_WIDTH = 12,
    parameter integer DEPTH_BYTES = 24
) ();
    reg                         clk;
    reg                         rst;
    reg  [DATA_WIDTH-1:0]       s_axis_tdata;
    reg  [DATA_WIDTH/8-1:0]     s_axis_tkeep;
    reg                         s_axis_tvalid;
    wire                        s_axis_tready;
    reg                         s_axis_tlast;
    wire [DATA_WIDTH-1:0]       m_axis_tdata;
    wire [DATA_WIDTH/8-1:0]     m_axis_tkeep;
    wire                        m_axis_tvalid;
    reg                         m_axis_tready;
    wire                        m_axis_tlast;
    wire                        status_overflow;
    wire                        status_good_frame;

    golden12_axis_fifo #(
        .DATA_WIDTH(DATA_WIDTH),
        .DEPTH_BYTES(DEPTH_BYTES)
    ) dut (
        .clk(clk),
        .rst(rst),
        .s_axis_tdata(s_axis_tdata),
        .s_axis_tkeep(s_axis_tkeep),
        .s_axis_tvalid(s_axis_tvalid),
        .s_axis_tready(s_axis_tready),
        .s_axis_tlast(s_axis_tlast),
        .m_axis_tdata(m_axis_tdata),
        .m_axis_tkeep(m_axis_tkeep),
        .m_axis_tvalid(m_axis_tvalid),
        .m_axis_tready(m_axis_tready),
        .m_axis_tlast(m_axis_tlast),
        .status_overflow(status_overflow),
        .status_good_frame(status_good_frame)
    );

    initial begin
        clk = 1'b0;
        rst = 1'b0;
        s_axis_tdata = {DATA_WIDTH{1'b0}};
        s_axis_tkeep = {DATA_WIDTH/8{1'b0}};
        s_axis_tvalid = 1'b0;
        s_axis_tlast = 1'b0;
        m_axis_tready = 1'b0;
        #1;
        $display(
            "GOLDEN12_G03_VISIBLE_INVALID_PARAMETER_FAIL width=%0d depth_bytes=%0d",
            DATA_WIDTH,
            DEPTH_BYTES
        );
        $finish;
    end

    always #5 clk = ~clk;
endmodule


module g03_visible_invalid_parameter_tb;
    g03_visible_invalid_parameter_probe #(
        .DATA_WIDTH(12),
        .DEPTH_BYTES(24)
    ) probe ();
endmodule


module g03_visible_nonintegral_capacity_tb;
    g03_visible_invalid_parameter_probe #(
        .DATA_WIDTH(32),
        .DEPTH_BYTES(10)
    ) probe ();
endmodule


module g03_visible_nonpower_capacity_tb;
    g03_visible_invalid_parameter_probe #(
        .DATA_WIDTH(16),
        .DEPTH_BYTES(12)
    ) probe ();
endmodule
