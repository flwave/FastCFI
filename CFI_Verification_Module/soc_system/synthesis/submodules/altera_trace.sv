// (C) 2001-2017 Intel Corporation. All rights reserved.
// Your use of Intel Corporation's design tools, logic functions and other 
// software and tools, and its AMPP partner logic functions, and any output 
// files from any of the foregoing (including device programming or simulation 
// files), and any associated documentation or information are expressly subject 
// to the terms and conditions of the Intel Program License Subscription 
// Agreement, Intel FPGA IP License Agreement, or other applicable 
// license agreement, including, without limitation, that your use is for the 
// sole purpose of programming logic devices manufactured by Intel and sold by 
// Intel or its authorized distributors.  Please refer to the applicable 
// agreement for further details.


// Copyright (C) 1991-2014 Altera Corporation
// Your use of Altera Corporation's design tools, logic functions 
// and other software and tools, and its AMPP partner logic 
// functions, and any output files from any of the foregoing 
// (including device programming or simulation files), and any 
// associated documentation or information are expressly subject 
// to the terms and conditions of the Altera Program License 
// Subscription Agreement, Altera MegaCore Function License 
// Agreement, or other applicable license agreement, including, 
// without limitation, that your use is for the sole purpose of 
// programming logic devices manufactured by Altera and sold by 
// Altera or its authorized distributors.  Please refer to the 
// applicable agreement for further details.
`timescale 1 ps / 1 ps
module altera_trace #(
	parameter IN_DWIDTH = 32,
	parameter OUT_DWIDTH = 32,
	parameter NUM_PIPELINE_REG = 1,
	parameter ADD_FEATURE = 1
)(
	h2f_tpiu_data,
	h2f_tpiu_clock_out,
	h2f_tpiu_reset_n,
	data_gpio,
	clk_gpio,
	reset_gpio,
	trace_clkin,
	trace_clk_ctl,
	trace_clkout,
	trace_dataout,
	f2h_tpiu_clock_out_ctl,
	f2h_tpiu_clock_out
);

input	[IN_DWIDTH-1:0]			h2f_tpiu_data;
input							h2f_tpiu_clock_out;
input							h2f_tpiu_reset_n;
input							trace_clkin;
input							trace_clk_ctl;
output							trace_clkout;
output	[(OUT_DWIDTH*2)-1:0]	data_gpio;
output							clk_gpio;
output							reset_gpio;
output	[OUT_DWIDTH-1:0]		trace_dataout;
output							f2h_tpiu_clock_out_ctl;
output							f2h_tpiu_clock_out;

wire [OUT_DWIDTH-1:0] 	tdata_in_l_gpio, tdata_in_h_gpio;
wire [OUT_DWIDTH-1:0] 	tdata_out_l_gpio, tdata_out_h_gpio;
reg  [OUT_DWIDTH-1:0] 	tdata_out_l_reg[NUM_PIPELINE_REG-1:0];
reg  [OUT_DWIDTH-1:0] 	tdata_out_h_reg[NUM_PIPELINE_REG-1:0];

genvar i, j;

assign f2h_tpiu_clock_out_ctl = trace_clk_ctl;
assign f2h_tpiu_clock_out = trace_clkin;
assign trace_clkout  = h2f_tpiu_clock_out;

// assign the last pipeline register output to the DDIO input
assign tdata_out_h_gpio = tdata_out_h_reg[NUM_PIPELINE_REG-1];
assign tdata_out_l_gpio = tdata_out_l_reg[NUM_PIPELINE_REG-1];

generate
if (ADD_FEATURE) begin
	reg  [OUT_DWIDTH-1:0] td1_reg, td2_reg, td3_reg;
	
	assign tdata_in_l_gpio = td3_reg;
	assign tdata_in_h_gpio = td2_reg;
	
	// DDR to SDR conv block
	always @(posedge h2f_tpiu_clock_out or negedge h2f_tpiu_reset_n) begin
		if (~h2f_tpiu_reset_n) begin
			td2_reg <= {OUT_DWIDTH{1'b0}};
			td3_reg <= {OUT_DWIDTH{1'b0}};
		end
		else begin
			td2_reg <= h2f_tpiu_data;	
			td3_reg <= td1_reg;	
		end
	end
	
	always @(negedge h2f_tpiu_clock_out or negedge h2f_tpiu_reset_n) begin
		if (~h2f_tpiu_reset_n) begin
			td1_reg <= {OUT_DWIDTH{1'b0}};
		end
		else begin
			td1_reg <= h2f_tpiu_data;	
		end
	end
end
else begin
	assign tdata_in_l_gpio = h2f_tpiu_data[(IN_DWIDTH/2)-1 : 0];
	assign tdata_in_h_gpio = h2f_tpiu_data[IN_DWIDTH-1 : (IN_DWIDTH/2)];
end 

for (i=0; i< NUM_PIPELINE_REG; i=i+1) begin : pipeline_loopblk2
	if (i == 0) begin : pipeline_ifblk1		
		// assign the first pipeline register input to the trace data output
		always @(posedge h2f_tpiu_clock_out or negedge h2f_tpiu_reset_n) begin
			if (~h2f_tpiu_reset_n) begin
				tdata_out_l_reg[i] <= {OUT_DWIDTH{1'b0}};
				tdata_out_h_reg[i] <= {OUT_DWIDTH{1'b0}};
			end
			else begin
				tdata_out_l_reg[i] <= tdata_in_l_gpio;	
				tdata_out_h_reg[i] <= tdata_in_h_gpio;
			end
		end
	end
	else begin
		always @(posedge h2f_tpiu_clock_out or negedge h2f_tpiu_reset_n) begin
			if (~h2f_tpiu_reset_n) begin
				tdata_out_l_reg[i] <= {OUT_DWIDTH{1'b0}};
				tdata_out_h_reg[i] <= {OUT_DWIDTH{1'b0}};
			end
			else begin
				tdata_out_l_reg[i] <= tdata_out_l_reg[i-1];	
				tdata_out_h_reg[i] <= tdata_out_h_reg[i-1];
			end
		end
	end
end

if (ADD_FEATURE) begin
	assign data_gpio 	= {(OUT_DWIDTH*2){1'b0}};
	assign clk_gpio 	= 1'b0;
	assign reset_gpio 	= 1'b0;
	
	// DDIO for Cyclone V/Arria V
	altddio #(
		.DWIDTH		(OUT_DWIDTH)
	) altddio_inst (
		.aclr		(~h2f_tpiu_reset_n),
		.datain_h	(tdata_out_l_gpio),
		.datain_l	(tdata_out_h_gpio),
		.outclock	(h2f_tpiu_clock_out),
		.dataout	(trace_dataout)
	);
end
else begin
	assign data_gpio		= {tdata_out_h_gpio, tdata_out_l_gpio};
	assign clk_gpio 		= h2f_tpiu_clock_out;
	assign reset_gpio 		= ~h2f_tpiu_reset_n;
	assign trace_dataout 	= {OUT_DWIDTH{1'b0}};
end
endgenerate

endmodule
