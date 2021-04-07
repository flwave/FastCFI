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


module soc_system_hps_0_hps_io_border(
// memory
  output wire [15 - 1 : 0 ] mem_a
 ,output wire [3 - 1 : 0 ] mem_ba
 ,output wire [1 - 1 : 0 ] mem_ck
 ,output wire [1 - 1 : 0 ] mem_ck_n
 ,output wire [1 - 1 : 0 ] mem_cke
 ,output wire [1 - 1 : 0 ] mem_cs_n
 ,output wire [1 - 1 : 0 ] mem_ras_n
 ,output wire [1 - 1 : 0 ] mem_cas_n
 ,output wire [1 - 1 : 0 ] mem_we_n
 ,output wire [1 - 1 : 0 ] mem_reset_n
 ,inout wire [32 - 1 : 0 ] mem_dq
 ,inout wire [4 - 1 : 0 ] mem_dqs
 ,inout wire [4 - 1 : 0 ] mem_dqs_n
 ,output wire [1 - 1 : 0 ] mem_odt
 ,output wire [4 - 1 : 0 ] mem_dm
 ,input wire [1 - 1 : 0 ] oct_rzqin
// hps_io
 ,output wire [1 - 1 : 0 ] hps_io_emac1_inst_TX_CLK
 ,output wire [1 - 1 : 0 ] hps_io_emac1_inst_TXD0
 ,output wire [1 - 1 : 0 ] hps_io_emac1_inst_TXD1
 ,output wire [1 - 1 : 0 ] hps_io_emac1_inst_TXD2
 ,output wire [1 - 1 : 0 ] hps_io_emac1_inst_TXD3
 ,input wire [1 - 1 : 0 ] hps_io_emac1_inst_RXD0
 ,inout wire [1 - 1 : 0 ] hps_io_emac1_inst_MDIO
 ,output wire [1 - 1 : 0 ] hps_io_emac1_inst_MDC
 ,input wire [1 - 1 : 0 ] hps_io_emac1_inst_RX_CTL
 ,output wire [1 - 1 : 0 ] hps_io_emac1_inst_TX_CTL
 ,input wire [1 - 1 : 0 ] hps_io_emac1_inst_RX_CLK
 ,input wire [1 - 1 : 0 ] hps_io_emac1_inst_RXD1
 ,input wire [1 - 1 : 0 ] hps_io_emac1_inst_RXD2
 ,input wire [1 - 1 : 0 ] hps_io_emac1_inst_RXD3
 ,inout wire [1 - 1 : 0 ] hps_io_usb1_inst_D0
 ,inout wire [1 - 1 : 0 ] hps_io_usb1_inst_D1
 ,inout wire [1 - 1 : 0 ] hps_io_usb1_inst_D2
 ,inout wire [1 - 1 : 0 ] hps_io_usb1_inst_D3
 ,inout wire [1 - 1 : 0 ] hps_io_usb1_inst_D4
 ,inout wire [1 - 1 : 0 ] hps_io_usb1_inst_D5
 ,inout wire [1 - 1 : 0 ] hps_io_usb1_inst_D6
 ,inout wire [1 - 1 : 0 ] hps_io_usb1_inst_D7
 ,input wire [1 - 1 : 0 ] hps_io_usb1_inst_CLK
 ,output wire [1 - 1 : 0 ] hps_io_usb1_inst_STP
 ,input wire [1 - 1 : 0 ] hps_io_usb1_inst_DIR
 ,input wire [1 - 1 : 0 ] hps_io_usb1_inst_NXT
 ,output wire [1 - 1 : 0 ] hps_io_spim1_inst_CLK
 ,output wire [1 - 1 : 0 ] hps_io_spim1_inst_MOSI
 ,input wire [1 - 1 : 0 ] hps_io_spim1_inst_MISO
 ,output wire [1 - 1 : 0 ] hps_io_spim1_inst_SS0
 ,inout wire [1 - 1 : 0 ] hps_io_gpio_inst_GPIO09
 ,inout wire [1 - 1 : 0 ] hps_io_gpio_inst_GPIO35
 ,inout wire [1 - 1 : 0 ] hps_io_gpio_inst_GPIO40
 ,inout wire [1 - 1 : 0 ] hps_io_gpio_inst_GPIO48
 ,inout wire [1 - 1 : 0 ] hps_io_gpio_inst_GPIO53
 ,inout wire [1 - 1 : 0 ] hps_io_gpio_inst_GPIO54
 ,inout wire [1 - 1 : 0 ] hps_io_gpio_inst_GPIO61
);

assign hps_io_emac1_inst_MDIO = intermediate[1] ? intermediate[0] : 'z;
assign hps_io_usb1_inst_D0 = intermediate[3] ? intermediate[2] : 'z;
assign hps_io_usb1_inst_D1 = intermediate[5] ? intermediate[4] : 'z;
assign hps_io_usb1_inst_D2 = intermediate[7] ? intermediate[6] : 'z;
assign hps_io_usb1_inst_D3 = intermediate[9] ? intermediate[8] : 'z;
assign hps_io_usb1_inst_D4 = intermediate[11] ? intermediate[10] : 'z;
assign hps_io_usb1_inst_D5 = intermediate[13] ? intermediate[12] : 'z;
assign hps_io_usb1_inst_D6 = intermediate[15] ? intermediate[14] : 'z;
assign hps_io_usb1_inst_D7 = intermediate[17] ? intermediate[16] : 'z;
assign hps_io_spim1_inst_MOSI = intermediate[19] ? intermediate[18] : 'z;
assign hps_io_gpio_inst_GPIO09 = intermediate[21] ? intermediate[20] : 'z;
assign hps_io_gpio_inst_GPIO35 = intermediate[23] ? intermediate[22] : 'z;
assign hps_io_gpio_inst_GPIO40 = intermediate[25] ? intermediate[24] : 'z;
assign hps_io_gpio_inst_GPIO48 = intermediate[27] ? intermediate[26] : 'z;
assign hps_io_gpio_inst_GPIO53 = intermediate[29] ? intermediate[28] : 'z;
assign hps_io_gpio_inst_GPIO54 = intermediate[31] ? intermediate[30] : 'z;
assign hps_io_gpio_inst_GPIO61 = intermediate[33] ? intermediate[32] : 'z;

wire [34 - 1 : 0] intermediate;

wire [99 - 1 : 0] floating;

cyclonev_hps_peripheral_emac emac1_inst(
 .EMAC_GMII_MDO_I({
    hps_io_emac1_inst_MDIO[0:0] // 0:0
  })
,.EMAC_GMII_MDO_OE({
    intermediate[1:1] // 0:0
  })
,.EMAC_PHY_TXD({
    hps_io_emac1_inst_TXD3[0:0] // 3:3
   ,hps_io_emac1_inst_TXD2[0:0] // 2:2
   ,hps_io_emac1_inst_TXD1[0:0] // 1:1
   ,hps_io_emac1_inst_TXD0[0:0] // 0:0
  })
,.EMAC_CLK_TX({
    hps_io_emac1_inst_TX_CLK[0:0] // 0:0
  })
,.EMAC_PHY_RXDV({
    hps_io_emac1_inst_RX_CTL[0:0] // 0:0
  })
,.EMAC_PHY_RXD({
    hps_io_emac1_inst_RXD3[0:0] // 3:3
   ,hps_io_emac1_inst_RXD2[0:0] // 2:2
   ,hps_io_emac1_inst_RXD1[0:0] // 1:1
   ,hps_io_emac1_inst_RXD0[0:0] // 0:0
  })
,.EMAC_GMII_MDO_O({
    intermediate[0:0] // 0:0
  })
,.EMAC_GMII_MDC({
    hps_io_emac1_inst_MDC[0:0] // 0:0
  })
,.EMAC_PHY_TX_OE({
    hps_io_emac1_inst_TX_CTL[0:0] // 0:0
  })
,.EMAC_CLK_RX({
    hps_io_emac1_inst_RX_CLK[0:0] // 0:0
  })
);


cyclonev_hps_peripheral_usb usb1_inst(
 .USB_ULPI_STP({
    hps_io_usb1_inst_STP[0:0] // 0:0
  })
,.USB_ULPI_DATA_I({
    hps_io_usb1_inst_D7[0:0] // 7:7
   ,hps_io_usb1_inst_D6[0:0] // 6:6
   ,hps_io_usb1_inst_D5[0:0] // 5:5
   ,hps_io_usb1_inst_D4[0:0] // 4:4
   ,hps_io_usb1_inst_D3[0:0] // 3:3
   ,hps_io_usb1_inst_D2[0:0] // 2:2
   ,hps_io_usb1_inst_D1[0:0] // 1:1
   ,hps_io_usb1_inst_D0[0:0] // 0:0
  })
,.USB_ULPI_NXT({
    hps_io_usb1_inst_NXT[0:0] // 0:0
  })
,.USB_ULPI_DIR({
    hps_io_usb1_inst_DIR[0:0] // 0:0
  })
,.USB_ULPI_DATA_O({
    intermediate[16:16] // 7:7
   ,intermediate[14:14] // 6:6
   ,intermediate[12:12] // 5:5
   ,intermediate[10:10] // 4:4
   ,intermediate[8:8] // 3:3
   ,intermediate[6:6] // 2:2
   ,intermediate[4:4] // 1:1
   ,intermediate[2:2] // 0:0
  })
,.USB_ULPI_CLK({
    hps_io_usb1_inst_CLK[0:0] // 0:0
  })
,.USB_ULPI_DATA_OE({
    intermediate[17:17] // 7:7
   ,intermediate[15:15] // 6:6
   ,intermediate[13:13] // 5:5
   ,intermediate[11:11] // 4:4
   ,intermediate[9:9] // 3:3
   ,intermediate[7:7] // 2:2
   ,intermediate[5:5] // 1:1
   ,intermediate[3:3] // 0:0
  })
);


cyclonev_hps_peripheral_spi_master spim1_inst(
 .SPI_MASTER_RXD({
    hps_io_spim1_inst_MISO[0:0] // 0:0
  })
,.SPI_MASTER_TXD({
    intermediate[18:18] // 0:0
  })
,.SPI_MASTER_SSI_OE_N({
    intermediate[19:19] // 0:0
  })
,.SPI_MASTER_SCLK({
    hps_io_spim1_inst_CLK[0:0] // 0:0
  })
,.SPI_MASTER_SS_0_N({
    hps_io_spim1_inst_SS0[0:0] // 0:0
  })
);


cyclonev_hps_peripheral_gpio gpio_inst(
 .GPIO1_PORTA_I({
    hps_io_gpio_inst_GPIO54[0:0] // 25:25
   ,hps_io_gpio_inst_GPIO53[0:0] // 24:24
   ,floating[3:0] // 23:20
   ,hps_io_gpio_inst_GPIO48[0:0] // 19:19
   ,floating[10:4] // 18:12
   ,hps_io_gpio_inst_GPIO40[0:0] // 11:11
   ,floating[14:11] // 10:7
   ,hps_io_gpio_inst_GPIO35[0:0] // 6:6
   ,floating[20:15] // 5:0
  })
,.GPIO1_PORTA_OE({
    intermediate[31:31] // 25:25
   ,intermediate[29:29] // 24:24
   ,floating[24:21] // 23:20
   ,intermediate[27:27] // 19:19
   ,floating[31:25] // 18:12
   ,intermediate[25:25] // 11:11
   ,floating[35:32] // 10:7
   ,intermediate[23:23] // 6:6
   ,floating[41:36] // 5:0
  })
,.GPIO2_PORTA_O({
    intermediate[32:32] // 3:3
   ,floating[44:42] // 2:0
  })
,.GPIO0_PORTA_O({
    intermediate[20:20] // 9:9
   ,floating[53:45] // 8:0
  })
,.GPIO2_PORTA_I({
    hps_io_gpio_inst_GPIO61[0:0] // 3:3
   ,floating[56:54] // 2:0
  })
,.GPIO2_PORTA_OE({
    intermediate[33:33] // 3:3
   ,floating[59:57] // 2:0
  })
,.GPIO0_PORTA_I({
    hps_io_gpio_inst_GPIO09[0:0] // 9:9
   ,floating[68:60] // 8:0
  })
,.GPIO0_PORTA_OE({
    intermediate[21:21] // 9:9
   ,floating[77:69] // 8:0
  })
,.GPIO1_PORTA_O({
    intermediate[30:30] // 25:25
   ,intermediate[28:28] // 24:24
   ,floating[81:78] // 23:20
   ,intermediate[26:26] // 19:19
   ,floating[88:82] // 18:12
   ,intermediate[24:24] // 11:11
   ,floating[92:89] // 10:7
   ,intermediate[22:22] // 6:6
   ,floating[98:93] // 5:0
  })
);


hps_sdram hps_sdram_inst(
 .mem_dq({
    mem_dq[31:0] // 31:0
  })
,.mem_odt({
    mem_odt[0:0] // 0:0
  })
,.mem_ras_n({
    mem_ras_n[0:0] // 0:0
  })
,.mem_dqs_n({
    mem_dqs_n[3:0] // 3:0
  })
,.mem_dqs({
    mem_dqs[3:0] // 3:0
  })
,.mem_dm({
    mem_dm[3:0] // 3:0
  })
,.mem_we_n({
    mem_we_n[0:0] // 0:0
  })
,.mem_cas_n({
    mem_cas_n[0:0] // 0:0
  })
,.mem_ba({
    mem_ba[2:0] // 2:0
  })
,.mem_a({
    mem_a[14:0] // 14:0
  })
,.mem_cs_n({
    mem_cs_n[0:0] // 0:0
  })
,.mem_ck({
    mem_ck[0:0] // 0:0
  })
,.mem_cke({
    mem_cke[0:0] // 0:0
  })
,.oct_rzqin({
    oct_rzqin[0:0] // 0:0
  })
,.mem_reset_n({
    mem_reset_n[0:0] // 0:0
  })
,.mem_ck_n({
    mem_ck_n[0:0] // 0:0
  })
);

endmodule

