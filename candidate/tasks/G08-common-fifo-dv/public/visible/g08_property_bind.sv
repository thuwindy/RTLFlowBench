bind fifo_v3 g08_fifo_properties #(
  .FALL_THROUGH(FALL_THROUGH),
  .DATA_WIDTH(DATA_WIDTH),
  .DEPTH(DEPTH),
  .ADDR_DEPTH(ADDR_DEPTH)
) g08_public_bound_properties (.*);
