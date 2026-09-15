`timescale 1ns/1ps
`default_nettype none

module g03_visible_tb;
    localparam integer DATA_WIDTH = 32;
    localparam integer DEPTH_BYTES = 64;
    localparam integer KEEP_WIDTH = DATA_WIDTH/8;

    reg clk = 1'b0;
    reg rst = 1'b0;
    reg [DATA_WIDTH-1:0] s_axis_tdata = 0;
    reg [KEEP_WIDTH-1:0] s_axis_tkeep = 0;
    reg s_axis_tvalid = 1'b0;
    wire s_axis_tready;
    reg s_axis_tlast = 1'b0;
    wire [DATA_WIDTH-1:0] m_axis_tdata;
    wire [KEEP_WIDTH-1:0] m_axis_tkeep;
    wire m_axis_tvalid;
    reg m_axis_tready = 1'b0;
    wire m_axis_tlast;
    wire status_overflow;
    wire status_good_frame;

    reg [DATA_WIDTH-1:0] stalled_data;
    reg [KEEP_WIDTH-1:0] stalled_keep;
    reg stalled_last;
    reg stalled_active = 1'b0;
    integer good_pulses = 0;
    integer overflow_pulses = 0;

    always #5 clk = ~clk;

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

    task automatic fail(input [8*96-1:0] reason);
        begin
            $display("GOLDEN12_VISIBLE_FAIL %0s", reason);
            $fatal(1);
        end
    endtask

    task automatic send_beat(
        input [DATA_WIDTH-1:0] data,
        input [KEEP_WIDTH-1:0] keep,
        input last
    );
        begin
            @(negedge clk);
            s_axis_tdata = data;
            s_axis_tkeep = keep;
            s_axis_tlast = last;
            s_axis_tvalid = 1'b1;
            do @(posedge clk); while (!s_axis_tready);
            @(negedge clk);
            s_axis_tvalid = 1'b0;
            s_axis_tlast = 1'b0;
        end
    endtask

    task automatic expect_beat(
        input [DATA_WIDTH-1:0] data,
        input [KEEP_WIDTH-1:0] keep,
        input last
    );
        integer cycles;
        begin
            cycles = 0;
            while (!(m_axis_tvalid && m_axis_tready)) begin
                @(posedge clk);
                cycles = cycles + 1;
                if (cycles > 40) fail("output timeout");
            end
            if (m_axis_tdata !== data) fail("output data mismatch");
            if (m_axis_tkeep !== keep) fail("output keep mismatch");
            if (m_axis_tlast !== last) fail("output last mismatch");
            @(negedge clk);
        end
    endtask

    always @(posedge clk) begin
        if (status_good_frame) good_pulses <= good_pulses + 1;
        if (status_overflow) overflow_pulses <= overflow_pulses + 1;
        if (rst) begin
            stalled_active <= 1'b0;
        end else if (m_axis_tvalid && !m_axis_tready) begin
            if (stalled_active) begin
                if (m_axis_tdata !== stalled_data)
                    fail("stalled data changed");
                if (m_axis_tkeep !== stalled_keep)
                    fail("stalled keep changed");
                if (m_axis_tlast !== stalled_last)
                    fail("stalled last changed");
            end
            stalled_data <= m_axis_tdata;
            stalled_keep <= m_axis_tkeep;
            stalled_last <= m_axis_tlast;
            stalled_active <= 1'b1;
        end else begin
            stalled_active <= 1'b0;
        end
    end

    initial begin
        rst = 1'b1;
        repeat (3) @(posedge clk);
        @(negedge clk);
        rst = 1'b0;

        // A partial frame must not become output-visible.
        send_beat(32'h11223344, 4'b1111, 1'b0);
        repeat (5) begin
            @(posedge clk);
            if (m_axis_tvalid) fail("partial frame became visible");
        end
        send_beat(32'h55667788, 4'b0011, 1'b1);

        // Hold the completed frame under backpressure and check stability.
        m_axis_tready = 1'b0;
        wait (m_axis_tvalid);
        repeat (4) @(posedge clk);
        @(negedge clk);
        m_axis_tready = 1'b1;
        expect_beat(32'h11223344, 4'b1111, 1'b0);
        expect_beat(32'h55667788, 4'b0011, 1'b1);

        // A second frame verifies ordering across frame boundaries.
        send_beat(32'hdeadbeef, 4'b1111, 1'b1);
        expect_beat(32'hdeadbeef, 4'b1111, 1'b1);
        if (good_pulses != 2) fail("good frame pulse count mismatch");
        if (overflow_pulses != 0) fail("unexpected overflow pulse");

        // Reset must flush an accepted partial frame.
        m_axis_tready = 1'b0;
        send_beat(32'ha5a5a5a5, 4'b1111, 1'b0);
        @(negedge clk);
        rst = 1'b1;
        repeat (2) @(posedge clk);
        @(negedge clk);
        rst = 1'b0;
        m_axis_tready = 1'b1;
        repeat (12) begin
            @(posedge clk);
            if (m_axis_tvalid) fail("pre-reset partial frame survived");
        end

        $display("GOLDEN12_VISIBLE_PASS task=G03-axis-fifo-backpressure width=32 depth_bytes=64");
        $finish;
    end

    initial begin
        #10000;
        fail("global timeout");
    end
endmodule

`default_nettype wire
