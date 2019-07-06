module CFI_kernel(clk,en,init_addr,check_addr,atom,addr,addr_aux,info,probe);
parameter nodes=0;
parameter func_bits=0;
parameter block_bits=0;
input clk/*synthesis keep*/;
input en/*synthesis keep*/;
output reg[31:0] addr;
output reg[func_bits+block_bits+32-1:0] addr_aux;
output reg[4:0] info;
input[31:0] init_addr/*synthesis keep*/;
input[31:0] check_addr/*synthesis keep*/;
input[1:0] atom/*synthesis keep*/;
output reg[127:0] probe;
wire[31:0] addr_p[0:0];
wire[4:0] info_p[0:0];
wire[func_bits+block_bits+32-1:0] addr_aux_p[0:0];
CFI_kernel_part_0 ckp0(en,init_addr,check_addr,atom,addr_p[0],addr_aux_p[0],info_p[0]);
always@(posedge clk)begin
addr=addr_p[0];
info=info_p[0];
addr_aux=addr_aux_p[0];
end
endmodule
module CFI_kernel_part_0(en,addr,check_addr,atom,addr_out,addr_aux,info);
parameter func_bits=0;
parameter block_bits=0;
input[31:0] addr/*synthesis keep*/;
input en/*synthesis keep*/;
output reg[31:0] addr_out;
output reg[func_bits+block_bits+32-1:0] addr_aux;
output reg[4:0] info;
input[31:0] check_addr/*synthesis keep*/;
input[1:0] atom/*synthesis keep*/;
reg[31:0] addr_p[-1:0];
reg[4:0] info_p[-1:0];
reg[func_bits+block_bits+32-1:0] addr_aux_p[-1:0];
always@(en,addr,check_addr,atom)begin
if(en)begin

end
end
endmodule
