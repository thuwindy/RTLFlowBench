`timescale 1 ns / 1 ps

module g05_visible_tb;
	reg clk = 0;
	reg resetn = 0;
	reg [31:0] irq = 0;
	wire [31:0] eoi;
	wire trap;

	always #5 clk = ~clk;

	picorv32 #(
		.ENABLE_IRQ(1),
		.ENABLE_IRQ_TIMER(1),
		.MASKED_IRQ(32'h0000_0000),
		.LATCHED_IRQ(32'hffff_ffff)
	) dut (
		.clk(clk),
		.resetn(resetn),
		.irq(irq),
		.eoi(eoi),
		.trap(trap)
	);

	task fail;
		input [255:0] reason;
		begin
			$display("GOLDEN12_VISIBLE_FAIL %0s", reason);
			$finish(1);
		end
	endtask

	initial begin
		repeat (3) @(posedge clk);
		@(negedge clk);
		resetn = 1;

		@(negedge clk);
		irq[3] = 1;
		@(posedge clk);
		#1;
		if (dut.irq_pending[3] !== 1'b1)
			fail("external_irq_not_pending");
		@(negedge clk);
		irq[3] = 0;
		@(posedge clk);
		#1;
		if (dut.irq_pending[3] !== 1'b1)
			fail("latched_external_irq_not_retained");

		@(negedge clk);
		force dut.timer = 32'd1;
		@(posedge clk);
		#1;
		release dut.timer;
		if (dut.irq_pending[0] !== 1'b1)
			fail("timer_irq_not_pending");

		// Public F2P smoke derived from G05-A04/A05: a newly sampled
		// external source and timer expiry must survive the same edge that
		// acknowledges a different already-pending source.
		@(negedge clk);
		irq = 0;
		dut.cpu_state = 8'b01000000;
		dut.irq_state = 2'b10;
		dut.irq_mask = 0;
		dut.irq_pending = 32'h0000_0008;
		dut.timer = 32'd1;
		irq[4] = 1;
		@(posedge clk);
		#1;
		if (eoi !== 32'h0000_0008)
			fail("service_edge_eoi_changed");
		if (dut.irq_pending[3] !== 1'b0)
			fail("serviced_irq_not_cleared");
		if (dut.irq_pending[4] !== 1'b1)
			fail("service_edge_external_irq_lost");
		if (dut.irq_pending[0] !== 1'b1)
			fail("service_edge_timer_irq_lost");

		@(negedge clk);
		irq = 0;
		resetn = 0;
		@(posedge clk);
		#1;
		if (dut.irq_pending !== 32'd0 || eoi !== 32'd0)
			fail("reset_did_not_clear_irq_state");

		$display("GOLDEN12_VISIBLE_PASS task=G05-picorv32-missing-irq external_irq=1 timer_irq=1 service_edge_merge=1 reset=1");
		$finish;
	end
endmodule
