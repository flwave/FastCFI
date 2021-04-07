// ============================================================================
// Copyright (c) 2013 by Terasic Technologies Inc.
// ============================================================================
//
// Permission:
//
//   Terasic grants permission to use and modify this code for use
//   in synthesis for all Terasic Development Boards and Altera Development 
//   Kits made by Terasic.  Other use of this code, including the selling 
//   ,duplication, or modification of any portion is strictly prohibited.
//
// Disclaimer:
//
//   This VHDL/Verilog or C/C++ source code is intended as a design reference
//   which illustrates how these types of functions can be implemented.
//   It is the user's responsibility to verify their design for
//   consistency and functionality through the use of formal
//   verification methods.  Terasic provides no warranty regarding the use 
//   or functionality of this code.
//
// ============================================================================
//           
//  Terasic Technologies Inc
//  9F., No.176, Sec.2, Gongdao 5th Rd, East Dist, Hsinchu City, 30070. Taiwan
//  
//  
//                     web: http://www.terasic.com/  
//                     email: support@terasic.com
//
// ============================================================================
//Date:  Mon Jun 17 20:35:29 2013
// ============================================================================

`define ENABLE_HPS

module ghrd_top(
      
      ///////// ADC /////////
      inout              ADC_CS_N,
      output             ADC_DIN,
      input              ADC_DOUT,
      output             ADC_SCLK,

      ///////// AUD /////////
      input              AUD_ADCDAT,
      inout              AUD_ADCLRCK,
      inout              AUD_BCLK,
      output             AUD_DACDAT,
      inout              AUD_DACLRCK,
      output             AUD_XCK,

      ///////// CLOCK2 /////////
      input              CLOCK2_50,

      ///////// CLOCK3 /////////
      input              CLOCK3_50,

      ///////// CLOCK4 /////////
      input              CLOCK4_50,

      ///////// CLOCK /////////
      input              CLOCK_50,

      ///////// DRAM /////////
      output      [12:0] DRAM_ADDR,
      output      [1:0]  DRAM_BA,
      output             DRAM_CAS_N,
      output             DRAM_CKE,
      output             DRAM_CLK,
      output             DRAM_CS_N,
      inout       [15:0] DRAM_DQ,
      output             DRAM_LDQM,
      output             DRAM_RAS_N,
      output             DRAM_UDQM,
      output             DRAM_WE_N,

      ///////// FAN /////////
      output             FAN_CTRL,

      ///////// FPGA /////////
      output             FPGA_I2C_SCLK,
      inout              FPGA_I2C_SDAT,

      ///////// GPIO /////////
      inout     [35:0]         GPIO_0,
      inout     [35:0]         GPIO_1,
 

      ///////// HEX0 /////////
      output      [6:0]  HEX0,

      ///////// HEX1 /////////
      output      [6:0]  HEX1,

      ///////// HEX2 /////////
      output      [6:0]  HEX2,

      ///////// HEX3 /////////
      output      [6:0]  HEX3,

      ///////// HEX4 /////////
      output      [6:0]  HEX4,

      ///////// HEX5 /////////
      output      [6:0]  HEX5,

`ifdef ENABLE_HPS
      ///////// HPS /////////
      inout              HPS_CONV_USB_N,
      output      [14:0] HPS_DDR3_ADDR,
      output      [2:0]  HPS_DDR3_BA,
      output             HPS_DDR3_CAS_N,
      output             HPS_DDR3_CKE,
      output             HPS_DDR3_CK_N,
      output             HPS_DDR3_CK_P,
      output             HPS_DDR3_CS_N,
      output      [3:0]  HPS_DDR3_DM,
      inout       [31:0] HPS_DDR3_DQ,
      inout       [3:0]  HPS_DDR3_DQS_N,
      inout       [3:0]  HPS_DDR3_DQS_P,
      output             HPS_DDR3_ODT,
      output             HPS_DDR3_RAS_N,
      output             HPS_DDR3_RESET_N,
      input              HPS_DDR3_RZQ,
      output             HPS_DDR3_WE_N,
      output             HPS_ENET_GTX_CLK,
      inout              HPS_ENET_INT_N,
      output             HPS_ENET_MDC,
      inout              HPS_ENET_MDIO,
      input              HPS_ENET_RX_CLK,
      input       [3:0]  HPS_ENET_RX_DATA,
      input              HPS_ENET_RX_DV,
      output      [3:0]  HPS_ENET_TX_DATA,
      output             HPS_ENET_TX_EN,
      inout       [3:0]  HPS_FLASH_DATA,
      output             HPS_FLASH_DCLK,
      output             HPS_FLASH_NCSO,
      inout              HPS_GSENSOR_INT,
      inout              HPS_I2C1_SCLK,
      inout              HPS_I2C1_SDAT,
      inout              HPS_I2C2_SCLK,
      inout              HPS_I2C2_SDAT,
      inout              HPS_I2C_CONTROL,
      inout              HPS_KEY,
      inout              HPS_LED,
      inout              HPS_LTC_GPIO,
      output             HPS_SD_CLK,
      inout              HPS_SD_CMD,
      inout       [3:0]  HPS_SD_DATA,
      output             HPS_SPIM_CLK,
      input              HPS_SPIM_MISO,
      output             HPS_SPIM_MOSI,
      inout              HPS_SPIM_SS,
      input              HPS_UART_RX,
      output             HPS_UART_TX,
      input              HPS_USB_CLKOUT,
      inout       [7:0]  HPS_USB_DATA,
      input              HPS_USB_DIR,
      input              HPS_USB_NXT,
      output             HPS_USB_STP,
`endif /*ENABLE_HPS*/

      ///////// IRDA /////////
      input              IRDA_RXD,
      output             IRDA_TXD,

      ///////// KEY /////////
      input       [3:0]  KEY,

      ///////// LEDR /////////
      output  reg    [9:0]  LEDR,

      ///////// PS2 /////////
      inout              PS2_CLK,
      inout              PS2_CLK2,
      inout              PS2_DAT,
      inout              PS2_DAT2,

      ///////// SW /////////
      input       [9:0]  SW,

      ///////// TD /////////
      input              TD_CLK27,
      input      [7:0]  TD_DATA,
      input             TD_HS,
      output             TD_RESET_N,
      input             TD_VS,


      ///////// VGA /////////
      output      [7:0]  VGA_B,
      output             VGA_BLANK_N,
      output             VGA_CLK,
      output      [7:0]  VGA_G,
      output             VGA_HS,
      output      [7:0]  VGA_R,
      output             VGA_SYNC_N,
      output             VGA_VS
);



// internal wires and registers declaration
  wire [3:0]  fpga_debounced_buttons;
  wire [9:0]  fpga_led_internal;
  wire        hps_fpga_reset_n;
  wire [2:0]  hps_reset_req;
  wire        hps_cold_reset;
  wire        hps_warm_reset;
  wire        hps_debug_reset;
  wire [27:0] stm_hw_events;

// connection of internal logics
  assign stm_hw_events    = {{3{1'b0}},SW, fpga_led_internal, fpga_debounced_buttons};

wire [31:0] trace_out;
wire trace_clk_out;

    soc_system u0 (
        .memory_mem_a                          ( HPS_DDR3_ADDR),                          //          memory.mem_a
        .memory_mem_ba                         ( HPS_DDR3_BA),                         //                .mem_ba
        .memory_mem_ck                         ( HPS_DDR3_CK_P),                         //                .mem_ck
        .memory_mem_ck_n                       ( HPS_DDR3_CK_N),                       //                .mem_ck_n
        .memory_mem_cke                        ( HPS_DDR3_CKE),                        //                .mem_cke
        .memory_mem_cs_n                       ( HPS_DDR3_CS_N),                       //                .mem_cs_n
        .memory_mem_ras_n                      ( HPS_DDR3_RAS_N),                      //                .mem_ras_n
        .memory_mem_cas_n                      ( HPS_DDR3_CAS_N),                      //                .mem_cas_n
        .memory_mem_we_n                       ( HPS_DDR3_WE_N),                       //                .mem_we_n
        .memory_mem_reset_n                    ( HPS_DDR3_RESET_N),                    //                .mem_reset_n
        .memory_mem_dq                         ( HPS_DDR3_DQ),                         //                .mem_dq
        .memory_mem_dqs                        ( HPS_DDR3_DQS_P),                        //                .mem_dqs
        .memory_mem_dqs_n                      ( HPS_DDR3_DQS_N),                      //                .mem_dqs_n
        .memory_mem_odt                        ( HPS_DDR3_ODT),                        //                .mem_odt
        .memory_mem_dm                         ( HPS_DDR3_DM),                         //                .mem_dm
        .memory_oct_rzqin                      ( HPS_DDR3_RZQ),                      //                .oct_rzqin
       		
	    .hps_0_hps_io_hps_io_emac1_inst_TX_CLK ( HPS_ENET_GTX_CLK), //                   hps_0_hps_io.hps_io_emac1_inst_TX_CLK
        .hps_0_hps_io_hps_io_emac1_inst_TXD0   ( HPS_ENET_TX_DATA[0] ),   //                               .hps_io_emac1_inst_TXD0
        .hps_0_hps_io_hps_io_emac1_inst_TXD1   ( HPS_ENET_TX_DATA[1] ),   //                               .hps_io_emac1_inst_TXD1
        .hps_0_hps_io_hps_io_emac1_inst_TXD2   ( HPS_ENET_TX_DATA[2] ),   //                               .hps_io_emac1_inst_TXD2
        .hps_0_hps_io_hps_io_emac1_inst_TXD3   ( HPS_ENET_TX_DATA[3] ),   //                               .hps_io_emac1_inst_TXD3
        .hps_0_hps_io_hps_io_emac1_inst_RXD0   ( HPS_ENET_RX_DATA[0] ),   //                               .hps_io_emac1_inst_RXD0
        .hps_0_hps_io_hps_io_emac1_inst_MDIO   ( HPS_ENET_MDIO ),   //                               .hps_io_emac1_inst_MDIO
        .hps_0_hps_io_hps_io_emac1_inst_MDC    ( HPS_ENET_MDC  ),    //                               .hps_io_emac1_inst_MDC
        .hps_0_hps_io_hps_io_emac1_inst_RX_CTL ( HPS_ENET_RX_DV), //                               .hps_io_emac1_inst_RX_CTL
        .hps_0_hps_io_hps_io_emac1_inst_TX_CTL ( HPS_ENET_TX_EN), //                               .hps_io_emac1_inst_TX_CTL
        .hps_0_hps_io_hps_io_emac1_inst_RX_CLK ( HPS_ENET_RX_CLK), //                               .hps_io_emac1_inst_RX_CLK
        .hps_0_hps_io_hps_io_emac1_inst_RXD1   ( HPS_ENET_RX_DATA[1] ),   //                               .hps_io_emac1_inst_RXD1
        .hps_0_hps_io_hps_io_emac1_inst_RXD2   ( HPS_ENET_RX_DATA[2] ),   //                               .hps_io_emac1_inst_RXD2
        .hps_0_hps_io_hps_io_emac1_inst_RXD3   ( HPS_ENET_RX_DATA[3] ),   //                               .hps_io_emac1_inst_RXD3
        
        		  
		  .hps_0_hps_io_hps_io_usb1_inst_D0      ( HPS_USB_DATA[0]    ),      //                               .hps_io_usb1_inst_D0
        .hps_0_hps_io_hps_io_usb1_inst_D1      ( HPS_USB_DATA[1]    ),      //                               .hps_io_usb1_inst_D1
        .hps_0_hps_io_hps_io_usb1_inst_D2      ( HPS_USB_DATA[2]    ),      //                               .hps_io_usb1_inst_D2
        .hps_0_hps_io_hps_io_usb1_inst_D3      ( HPS_USB_DATA[3]    ),      //                               .hps_io_usb1_inst_D3
        .hps_0_hps_io_hps_io_usb1_inst_D4      ( HPS_USB_DATA[4]    ),      //                               .hps_io_usb1_inst_D4
        .hps_0_hps_io_hps_io_usb1_inst_D5      ( HPS_USB_DATA[5]    ),      //                               .hps_io_usb1_inst_D5
        .hps_0_hps_io_hps_io_usb1_inst_D6      ( HPS_USB_DATA[6]    ),      //                               .hps_io_usb1_inst_D6
        .hps_0_hps_io_hps_io_usb1_inst_D7      ( HPS_USB_DATA[7]    ),      //                               .hps_io_usb1_inst_D7
        .hps_0_hps_io_hps_io_usb1_inst_CLK     ( HPS_USB_CLKOUT    ),     //                               .hps_io_usb1_inst_CLK
        .hps_0_hps_io_hps_io_usb1_inst_STP     ( HPS_USB_STP    ),     //                               .hps_io_usb1_inst_STP
        .hps_0_hps_io_hps_io_usb1_inst_DIR     ( HPS_USB_DIR    ),     //                               .hps_io_usb1_inst_DIR
        .hps_0_hps_io_hps_io_usb1_inst_NXT     ( HPS_USB_NXT    ),     //                               .hps_io_usb1_inst_NXT
        		  
		  .hps_0_hps_io_hps_io_spim1_inst_CLK    ( HPS_SPIM_CLK  ),    //                               .hps_io_spim1_inst_CLK
        .hps_0_hps_io_hps_io_spim1_inst_MOSI   ( HPS_SPIM_MOSI ),   //                               .hps_io_spim1_inst_MOSI
        .hps_0_hps_io_hps_io_spim1_inst_MISO   ( HPS_SPIM_MISO ),   //                               .hps_io_spim1_inst_MISO
        .hps_0_hps_io_hps_io_spim1_inst_SS0    ( HPS_SPIM_SS ),    //                               .hps_io_spim1_inst_SS0
        
		  .hps_0_hps_io_hps_io_gpio_inst_GPIO09  ( HPS_CONV_USB_N),  //                               .hps_io_gpio_inst_GPIO09
        .hps_0_hps_io_hps_io_gpio_inst_GPIO35  ( HPS_ENET_INT_N),  //                               .hps_io_gpio_inst_GPIO35
        .hps_0_hps_io_hps_io_gpio_inst_GPIO40  ( HPS_LTC_GPIO),  //                               .hps_io_gpio_inst_GPIO40
        //.hps_0_hps_io_hps_io_gpio_inst_GPIO41  ( HPS_GPIO[1]),  //                               .hps_io_gpio_inst_GPIO41
        .hps_0_hps_io_hps_io_gpio_inst_GPIO48  ( HPS_I2C_CONTROL),  //                               .hps_io_gpio_inst_GPIO48
        .hps_0_hps_io_hps_io_gpio_inst_GPIO53  ( HPS_LED),  //                               .hps_io_gpio_inst_GPIO53
        .hps_0_hps_io_hps_io_gpio_inst_GPIO54  ( HPS_KEY),  //                               .hps_io_gpio_inst_GPIO54
        .hps_0_hps_io_hps_io_gpio_inst_GPIO61  ( HPS_GSENSOR_INT),  //                               .hps_io_gpio_inst_GPIO61
		  .hps_0_f2h_stm_hw_events_stm_hwevents  (stm_hw_events),   //        hps_0_f2h_stm_hw_events.stm_hwevents
        .clk_clk                               (CLOCK_50),                               //                            clk.clk
        .reset_reset_n                         (hps_fpga_reset_n),                         //                          reset.reset_n
		  .hps_0_h2f_reset_reset_n               (hps_fpga_reset_n),               //                hps_0_h2f_reset.reset_n
        .hps_0_f2h_warm_reset_req_reset_n      (~hps_warm_reset),      //       hps_0_f2h_warm_reset_req.reset_n
        .hps_0_f2h_debug_reset_req_reset_n     (~hps_debug_reset),     //      hps_0_f2h_debug_reset_req.reset_n
        .hps_0_f2h_cold_reset_req_reset_n      (~hps_cold_reset),     //       hps_0_f2h_cold_reset_req.reset_n
        //.trace_wrapper_0_trace_data_out_export(trace_out),
        .hps_0_h2f_tpiu_clock_clk(trace_clk_out),
		  .hps_0_h2f_tpiu_clk_ctl(1'b0),
        //.trace_wrapper_0_trace_clk_out_clk(trace_clk_out),
		  .hps_0_h2f_tpiu_data(trace_out)
	 
	 );

reg[23:0] num;
dis7seg_clear disc0(viof,HEX0,HEX1,HEX2,HEX3,HEX4,HEX5);
//dis7seg dis1(num,HEX0,HEX1,HEX2,HEX3,HEX4,HEX5);
wire clk500ms;
lclk l2(CLOCK_50,10_000_000,clk500ms);

wire[127:0] deoutd;//data
wire[15:0] deouth;//header
wire[31:0] deoutc;//context
wire[4:0] deouts;//state
wire vio;
reg[31:0] vio_count;
reg[31:0] vio_record[5:0];
reg[31:0] vio_temp[5:0];

reg[9:0] vios;
reg viof;

wire[127:0] probe_cfi,probe_de;

//decoder d1(CLOCK_50,trace_out,deouth,deoutd,deoutc,deouts,probe_de);
//CFI c1(CLOCK_50,deouth,deoutd,deoutc,deouts,vio,probe_cfi);
decoder_pipe d1(CLOCK_50,trace_out,deouth,deoutd,deoutc,deouts,probe_de);
//CFI_buffer cb0(CLOCK_50,deouth,deoutd,deoutc,deouts,vio,probe_cfi);
CFI_comb cb0(CLOCK_50,deouth,deoutd,deoutc,deouts,vio,probe_cfi);

reg[31:0] temp,temp2;

reg trigger;

reg[7:0] outp,count32;
reg[31:0] count128;

always@(posedge clk500ms)
begin
	LEDR[8]<=vio|viof|trigger;
	LEDR[7]<=temp[count32]|temp2[count32];
	LEDR[6]<=vio_count[count32]|probe_de[count128]|probe_cfi[count128]|vio_record[5][count32]|vio_record[4][count32]|vio_record[3][count32]|vio_record[2][count32]|vio_record[1][count32]|vio_record[0][count32];
	if(count32<31)
	begin
		count32<=count32+1;
	end
	else
	begin
		count32<=0;
	end
	if(count128<127)
	begin
		count128<=count128+1;
	end
	else
	begin
		count128<=0;
	end
	LEDR[0]<=~LEDR[0];
end

reg[23:0] count;

reg found;

reg[31:0] last_data;

parameter addrup1=32'hac00;
parameter addrdown1=32'hacd6;

parameter addrup2=32'haccc;
parameter addrdown2=32'haccc;

parameter addrup3=32'habc0;
parameter addrdown3=32'hac00;

parameter addrup4=32'h9054;
parameter addrdown4=32'h9096;

parameter addrup5=32'h93de;
parameter addrdown5=32'h93de;
/*
parameter addrup=32'h9054;
parameter addrdown=32'h9054;
*/

always@(posedge CLOCK_50)
begin
	/*
	if(deouth[3:0]==2&&deoutd[31:0]>=addrup&&deoutd[31:0]<=addrdown
	||deouth[7:4]==2&&deoutd[63:32]>=addrup&&deoutd[63:32]<=addrdown
	||deouth[11:8]==2&&deoutd[95:64]>=addrup&&deoutd[95:64]<=addrdown
	||deouth[15:12]==2&&deoutd[127:96]>=addrup&&deoutd[127:96]<=addrdown)begin
		trigger=1;
	end
	else begin
		trigger=0;
	end
	*/
	/*
	if(deouth[3:0]==5
	||deouth[7:4]==5
	||deouth[11:8]==5
	||deouth[15:12]==5)begin
		trigger=1;
	end
	else begin
		trigger=0;
	end
	*/
	case(SW[3:0])
	0:begin
	if(vio)begin
		trigger=1;
	end
	else begin
		trigger=0;
	end
	end
	1:begin
	if(deouth[3:0]==2&&deoutd[31:0]>=addrup1&&deoutd[31:0]<=addrdown1
	||deouth[7:4]==2&&deoutd[63:32]>=addrup1&&deoutd[63:32]<=addrdown1
	||deouth[11:8]==2&&deoutd[95:64]>=addrup1&&deoutd[95:64]<=addrdown1
	||deouth[15:12]==2&&deoutd[127:96]>=addrup1&&deoutd[127:96]<=addrdown1)begin
		trigger=1;
	end
	else begin
		trigger=0;
	end
	end
	2:begin
	if(deouth[3:0]==2&&deoutd[31:0]>=addrup2&&deoutd[31:0]<=addrdown2
	||deouth[7:4]==2&&deoutd[63:32]>=addrup2&&deoutd[63:32]<=addrdown2
	||deouth[11:8]==2&&deoutd[95:64]>=addrup2&&deoutd[95:64]<=addrdown2
	||deouth[15:12]==2&&deoutd[127:96]>=addrup2&&deoutd[127:96]<=addrdown2)begin
		trigger=1;
	end
	else begin
		trigger=0;
	end
	end
	3:begin
	if(deouth[3:0]==2&&deoutd[31:0]>=addrup3&&deoutd[31:0]<=addrdown3
	||deouth[7:4]==2&&deoutd[63:32]>=addrup3&&deoutd[63:32]<=addrdown3
	||deouth[11:8]==2&&deoutd[95:64]>=addrup3&&deoutd[95:64]<=addrdown3
	||deouth[15:12]==2&&deoutd[127:96]>=addrup3&&deoutd[127:96]<=addrdown3)begin
		trigger=1;
	end
	else begin
		trigger=0;
	end
	end
	4:begin
	if(deouth[3:0]==2&&deoutd[31:0]>=addrup4&&deoutd[31:0]<=addrdown4
	||deouth[7:4]==2&&deoutd[63:32]>=addrup4&&deoutd[63:32]<=addrdown4
	||deouth[11:8]==2&&deoutd[95:64]>=addrup4&&deoutd[95:64]<=addrdown4
	||deouth[15:12]==2&&deoutd[127:96]>=addrup4&&deoutd[127:96]<=addrdown4)begin
		trigger=1;
	end
	else begin
		trigger=0;
	end
	end
	5:begin
	if(deouth[3:0]==2&&deoutd[31:0]>=addrup5&&deoutd[31:0]<=addrdown5
	||deouth[7:4]==2&&deoutd[63:32]>=addrup5&&deoutd[63:32]<=addrdown5
	||deouth[11:8]==2&&deoutd[95:64]>=addrup5&&deoutd[95:64]<=addrdown5
	||deouth[15:12]==2&&deoutd[127:96]>=addrup5&&deoutd[127:96]<=addrdown5)begin
		trigger=1;
	end
	else begin
		trigger=0;
	end
	end
	6:begin
	if(last_data!=32'h8fd6&&probe_cfi[63:32]==32'h8fd6)begin
		trigger=1;
	end
	else begin
		trigger=0;
	end
	last_data=probe_cfi[63:32];
	end
	7:begin
	if(last_data!=32'haccc&&probe_cfi[95:64]==32'haccc)begin
		trigger=1;
	end
	else begin
		trigger=0;
	end
	last_data=probe_cfi[95:64];
	end
	8:begin
	if(last_data!=32'h9054&&probe_cfi[111:96]==32'h9054)begin
		trigger=1;
	end
	else begin
		trigger=0;
	end
	last_data=probe_cfi[111:96];
	end
	endcase
	/*
	if(deouth[3:0]==2&&deoutd[31:0]>=addrup&&deoutd[31:0]<=addrdown
	||deouth[7:4]==2&&deoutd[63:32]>=addrup&&deoutd[63:32]<=addrdown
	||deouth[11:8]==2&&deoutd[95:64]>=addrup&&deoutd[95:64]<=addrdown
	||deouth[15:12]==2&&deoutd[127:96]>=addrup&&deoutd[127:96]<=addrdown)begin
		trigger=1;
	end
	else if(vio)begin
		trigger=1;
	end
	else begin
		trigger=0;
	end
	*/
	/*
	if(vio)begin
		trigger=1;
	end
	else begin
		trigger=0;
	end
	*/
	/*
	if(trace_out==32'hC0C0C0C0)begin
		if(found==0)begin
			found=1;
			trigger=1;
		end
	end
	else if(trace_out!=32'h1)begin
		found=0;
		trigger=0;
	end
	else begin
		trigger=0;
	end*/
	/*
	if(deouth[3:0]==4||deouth[7:4]==4||deouth[11:8]==4||deouth[15:12]==4)begin
		trigger=1;
	end
	else begin
		trigger=0;
	end
	*/
	if(KEY[3]==0)begin
		viof=0;
	end
	if(vio)begin
		viof=1;
	end
	if (vio)begin
		vio_count=vio_count+1;
	end
	LEDR[9]=SW[9];
	temp=trace_out;
end

always@(negedge CLOCK_50)begin
	temp2=trace_out;
end

// Source/Probe megawizard instance
hps_reset hps_reset_inst (
  .source_clk (CLOCK_50),
  .source     (hps_reset_req)
);

altera_edge_detector pulse_cold_reset (
  .clk       (CLOCK_50),
  .rst_n     (hps_fpga_reset_n),
  .signal_in (hps_reset_req[0]),
  .pulse_out (hps_cold_reset)
);
  defparam pulse_cold_reset.PULSE_EXT = 6;
  defparam pulse_cold_reset.EDGE_TYPE = 1;
  defparam pulse_cold_reset.IGNORE_RST_WHILE_BUSY = 1;

altera_edge_detector pulse_warm_reset (
  .clk       (CLOCK_50),
  .rst_n     (hps_fpga_reset_n),
  .signal_in (hps_reset_req[1]),
  .pulse_out (hps_warm_reset)
);
  defparam pulse_warm_reset.PULSE_EXT = 2;
  defparam pulse_warm_reset.EDGE_TYPE = 1;
  defparam pulse_warm_reset.IGNORE_RST_WHILE_BUSY = 1;
  
altera_edge_detector pulse_debug_reset (
  .clk       (CLOCK_50),
  .rst_n     (hps_fpga_reset_n),
  .signal_in (hps_reset_req[2]),
  .pulse_out (hps_debug_reset)
);
  defparam pulse_debug_reset.PULSE_EXT = 32;
  defparam pulse_debug_reset.EDGE_TYPE = 1;
  defparam pulse_debug_reset.IGNORE_RST_WHILE_BUSY = 1;

endmodule


module dis7seg(num,out0,out1,out2,out3,out4,out5);
input [23:0] num;
output [6:0] out0;
output [6:0] out1;
output [6:0] out2;
output [6:0] out3;
output [6:0] out4;
output [6:0] out5;

wire [6:0] code[15:0];
assign code[0]=7'b1000000;
assign code[1]=7'b1111001;
assign code[2]=7'b0100100;
assign code[3]=7'b0110000;
assign code[4]=7'b0011001;
assign code[5]=7'b0010010;
assign code[6]=7'b0000010;
assign code[7]=7'b1111000;
assign code[8]=7'b0000000;
assign code[9]=7'b0010000;
assign code[10]=7'b0001000;
assign code[11]=7'b0000011;
assign code[12]=7'b1000110;
assign code[13]=7'b0100001;
assign code[14]=7'b0000110;
assign code[15]=7'b0001110;

assign out0=code[num&4'b1111];
assign out1=code[(num>>4)&4'b1111];
assign out2=code[(num>>8)&4'b1111];
assign out3=code[(num>>12)&4'b1111];
assign out4=code[(num>>16)&4'b1111];
assign out5=code[(num>>20)&4'b1111];

endmodule

module dis7seg_clear(error,out0,out1,out2,out3,out4,out5);
input error;
output [6:0] out0;
output [6:0] out1;
output [6:0] out2;
output [6:0] out3;
output [6:0] out4;
output [6:0] out5;

assign out0=error?7'b0101111:7'b0101111;
assign out1=error?7'b0100011:7'b0001000;
assign out2=error?7'b0101111:7'b0000110;
assign out3=error?7'b0101111:7'b1000111;
assign out4=error?7'b0000110:7'b1000110;
assign out5=7'b1111111;

endmodule

module lclk(clkin,times,clkout);
	input clkin;
	input[32:1] times;
	output clkout;
	reg clkout;
	reg [32:1] conter;
	always @(posedge clkin)begin
	if(conter==times)begin
	clkout=1;
	conter=0;
	end
	else
	clkout=0;
	conter=conter+1;
	end
endmodule
