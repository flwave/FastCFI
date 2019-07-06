module CFI_comb(clk,deh,ded,dec,des,vio,probe);
	input clk;
	input[127:0] ded;//data
	input[15:0] deh;//header
	input[31:0] dec;//cid
	input[4:0] des;//state
	output vio;
	output reg[127:0] probe;
	
	wire[31:0] wd;//data
	wire[31:0] wc;//cid
	wire ws;//state 
	wire[3:0] wh;//header
	
	wire read,empty,overflow;
	wire[127:0] probe_fe,probe_ve;
	
	//CFI_comb_data_receiver cr0(clk,deh,ded,dec,des,lock,read_c,ready,read_c_max,outd,outc,outs,probe_re);
	CFI_FIFO cf0(clk,read,des,deh,dec,ded,empty,overflow,ws,wh,wc,wd,probe_fe);
	CFI_comb_verification cve0(clk,ws,wh,wc,wd,empty,overflow,read,vio,probe_ve);
	always@(posedge clk)begin
		probe=probe_ve|probe_fe;
	end
	
endmodule

module CFI_comb_verification(clk,ins,inh,inc,ind,empty,overflow,read,vio,probe);
parameter nodes=0;
parameter func_bits=1;
parameter block_bits=1;
	parameter stack_size=16;
	
	input clk;
	input[31:0] ind;//data
	input[31:0] inc;//cid
	input ins;//state 
	input[3:0] inh;//header
	
	output reg[127:0] probe;
	
	input empty,overflow;
	output read;
	
	output reg vio;
	
	parameter IDLE=8'h00;
	parameter INIT=8'h01;
	parameter WORK=8'h02;
	parameter WAIT_SYNC=8'h03;
	parameter OVERFLOW=8'h04;
	parameter READROM=8'h05;
	parameter LAST=8'h06;
	parameter FEED=8'h07;
	parameter WAIT_DATA=8'h08;
	parameter VERIFY=8'h09;
	parameter WAIT_DATA2=8'h0a;
	
	reg last2wait_sync;
	
	reg[7:0] step;
	reg[7:0] process_c;//count how many cycles after starting working
	reg[7:0] outdata_c,indata_c;
	
	reg[3:0] verify_begin;
	reg wait_sync;
	
	reg[31:0] address;
	reg[31:0] cid,target_cid;
	reg state,target_state;
	
	reg pass_verify;
	
	reg en;
	reg[31:0] init_addr;
	reg[31:0] check_addr;
	reg[1:0] atom;
	wire[31:0] addr;
	wire[func_bits+block_bits+32-1:0] addr_aux;
	wire[4:0] info;
	
	reg[31:0] n_addr;
	
	wire[127:0] probe_w;
	
	reg[3:0] deh_last;
	reg init_check;
	
	
	reg[63:0] func_stack[stack_size-1:0];//[high32]:function end; [low32]:function begin
	reg[63:0] last_func;//[high32]:function end; [low32]:function begin
	reg[63:0] return_func_stack[stack_size-1:0];
	reg[31:0] return_stack[stack_size-1:0];//correct return add;
	reg[63:0] addr_bend_buf[1:0];
	reg[31:0] last_2_bend[1:0],last_2_addr[1:0],last_branch;
	reg[2:0] outdata_count/*synthesis noprune*/;//this is for left shift count valid data out
	reg[1:0] last_2_en;
	reg[5:0] last_2_atom;
	reg[5:0] last_2_ret_act;//record the return stack action. 1:overflow,vio,etc; 2:push
	reg ret_verify,ind_verify;
	
	reg[15:0] stack_ptr;
	
	reg[31:0] max_cid;
	
	//CFI_kernel ck0(clk,init_addr,check_addr,atoms,atomson,re,stateful,probe_w);
	CFI_kernel ck0(clk,en,init_addr,check_addr,atom,addr,addr_aux,info,probe_w);
	
	assign read=1;
	
	always@(posedge clk)begin
		vio=0;
		//probe=stack_ptr|(addr<<32)|(info<<64)|(addr_aux[31:0]<<96)|return_stack[stack_ptr-1];
		//probe=(addr<<64)|(addr_aux[31:0]<<96);
		if(overflow)begin
			stack_ptr=0;
			ind_verify=0;
			ret_verify=0;
			addr_bend_buf[1]=0;
			addr_bend_buf[0]=0;
			last_branch=0;
			last_func=0;
			last_2_ret_act=last_2_ret_act<<2;
			last_2_ret_act[1:0]=1;
			step=IDLE;
		end
		else if(step==IDLE)begin
			case(inh)
				2:begin
				last2wait_sync=0;
				
				en=1;
				cid=inc;
				state=ins;
				
				init_addr=ind;
				check_addr=0;
				atom=2'b10;
				//last_branch=ind;
				last_2_atom=6'b101010;
				outdata_count=3'b110;
				outdata_c=0;
				indata_c=0;
				
				if(target_cid==0||target_state==ins)
				step=WAIT_DATA;
				end
				6:begin
					en=1;
					stack_ptr=0;
					ind_verify=0;
					ret_verify=0;
					addr_bend_buf[1]=0;
					addr_bend_buf[0]=0;
					last_branch=0;
					last_func=0;
					last_2_ret_act=last_2_ret_act<<2;
					last_2_ret_act[1:0]=1;
				end
			endcase
		end
		else if(step==WAIT_DATA)begin
			//do nothing
			step=WAIT_DATA2;
		end
		else if(step==WAIT_DATA2)begin
			//do nothing
			step=VERIFY;
		end
		else if(step==VERIFY)begin
			if(outdata_c<10)
			outdata_c=outdata_c+1;
			step=FEED;
			//--------------
			if(target_cid!=0&&inc>0&&target_cid!=inc)begin
				target_cid=0;
				stack_ptr=0;
				ind_verify=0;
				ret_verify=0;
				addr_bend_buf[1]=0;
				addr_bend_buf[0]=0;
				last_branch=0;
				last_func=0;
				//last_2_ret_act=last_2_ret_act<<2;
				//last_2_ret_act[1:0]=1;
				step=IDLE;
			end
			if(target_cid!=0&&inc>0&&target_state!=ins)begin
				step=IDLE;
			end
			//--------------data process-----------------
			if(outdata_c>1)begin
				if(!(last_branch>=addr_aux[31:0]&&last_branch<=addr_aux[31:0]+addr_aux[block_bits+32-1:32]))begin//continued trace
					ind_verify=0;
					last_branch=0;
				end
				addr_bend_buf[1]=addr_bend_buf[0];
				addr_bend_buf[0]=((addr_aux[31:0]+addr_aux[block_bits+32-1:32])<<32)|last_branch;
				last_branch=addr;
				/*if(!(addr_aux[31:0]>=last_func[31:0]&&addr_aux[31:0]<=last_func[63:32]))begin
					last_func=0;
				end*/
				if(info[0]&&last_2_atom[3:2]!=2'b01)begin//if this process begin at a function entry, there is no 'last block end address'.....the reason process_c cannot be 1: 1 is the init part; cannot be 2: 2 is the first one starting work
					//if((stack_ptr==0||(stack_ptr>0&&addr_aux[31:0]!=func_stack[stack_ptr-1][31:0]))&&(addr_bend_buf[1][31:0]!=0&&!(addr_bend_buf[1][31:0]>=addr_aux[31:0]&&addr_bend_buf[1][31:0]<=addr_aux[31:0]+addr_aux[block_bits+32-1:32])))begin
					if(addr_bend_buf[0][31:0]==addr_aux[31:0]&&(addr_bend_buf[1][31:0]==0||!(addr_bend_buf[1][31:0]>=addr_aux[31:0]&&addr_bend_buf[1][31:0]<=addr_aux[31:0]+addr_aux[func_bits+block_bits+32-1:block_bits+32])))begin//the target address of last branch is right at the entry
						func_stack[stack_ptr]=((addr_aux[31:0]+addr_aux[func_bits+block_bits+32-1:block_bits+32])<<32)|addr_aux[31:0];
						return_stack[stack_ptr]=addr_bend_buf[1][63:32];
						if(addr_bend_buf[1][63:32]>=last_func[31:0]&&addr_bend_buf[1][63:32]<=last_func[63:32])begin
							return_func_stack[stack_ptr]=last_func;
						end
						else begin
							return_func_stack[stack_ptr]=0;
						end
						stack_ptr=stack_ptr+1;
						if(stack_ptr>stack_size)begin
							stack_ptr=0;
						end
						last_2_ret_act=last_2_ret_act<<2;
						last_2_ret_act[1:0]=2;
					end
					last_func=((addr_aux[31:0]+addr_aux[func_bits+block_bits+32-1:block_bits+32])<<32)|addr_aux[31:0];
				end
			end
			//probe=probe_w;
			probe=(addr<<64)|(addr_aux[31:0]<<96)|return_stack[stack_ptr-1]|(return_func_stack[stack_ptr-1]<<16)|(func_stack[stack_ptr-1][31:0]<<32)|(func_stack[stack_ptr-1][63:32]<<48);
			//--------------verify-----------------
			if(outdata_c==1)begin//the first output, verify if this is the program we want to check
				if(info[4]&&cid>=max_cid)begin
					max_cid=cid;
					if(target_cid==0)begin
						target_cid=cid;
						target_state=1;
					end
				end
				else begin
					step=IDLE;
				end
			end
			else begin//normally working
				if(!info[4])begin//if this is still in range
					step=IDLE;
				end
				
				if(info[3])begin
					probe[120]=1;
					vio=1;
				end
				
				if(ind_verify)begin
					if(info[0]&&(addr_bend_buf[0][31:0]==addr_aux[31:0]||addr_bend_buf[0][31:0]==0))begin
					end
					else if(!info[4])begin//!!!!!!!!!!!!!!!!!!!not very good. add "&&iofo[4]" means if jump out of range, we don't verify. But this mat allow jump to somewhere in range but there is mal code (originally no code).
					end
					else begin
						probe[119]=1;
						vio=1;
					end
					ind_verify=0;
				end
				
				
				if(info[2])begin//verify indirect branch
					probe[127]=1;
					if(stack_ptr>0&&addr_aux[31:0]>=func_stack[stack_ptr-1][31:0]&&addr_aux[31:0]<=func_stack[stack_ptr-1][63:32])begin//now current address in verification range
						probe[126]=1;
						if(return_stack[stack_ptr-1]==0||addr==return_stack[stack_ptr-1])begin//if this is return
							probe[125]=1;
							stack_ptr=stack_ptr-1;
							//last_2_ret_act=last_2_ret_act<<2;
							//last_2_ret_act[1:0]=2;
						end
						else if(last_2_ret_act[3:2]==1&&stack_ptr==1)begin
							probe[125]=1;
						end
						else if(stack_ptr>1&&(return_stack[stack_ptr-2]==0||addr==return_stack[stack_ptr-2]))begin//if add "stack_ptr==1||", the return check will be relatively weak(because if stack_ptr<=1, we won't check).
							probe[125]=1;
							stack_ptr=stack_ptr-2;
							//last_2_ret_act=last_2_ret_act<<4;
							//last_2_ret_act[3:0]=2'b1010;
						end
						else if(return_func_stack[stack_ptr-1]==0||(addr>=return_func_stack[stack_ptr-1][31:0]&&addr<=return_func_stack[stack_ptr-1][63:32]))begin//if next addr is in the range of last call function(may also regraded as return)
							probe[124]=1;
							stack_ptr=stack_ptr-1;
							//last_2_ret_act=last_2_ret_act<<2;
							//last_2_ret_act[1:0]=2;
						end
						else if(stack_ptr>1&&(return_func_stack[stack_ptr-2]==0||(addr>=return_func_stack[stack_ptr-2][31:0]&&addr<=return_func_stack[stack_ptr-2][63:32])))begin//if next addr is in the range of last call function(may also regraded as return)
							probe[124]=1;
							stack_ptr=stack_ptr-2;
							//last_2_ret_act=last_2_ret_act<<4;
							//last_2_ret_act[3:0]=2'b1010;
						end
						else if(!info[1]) begin//this is not a certain return point we verify if this is call in the next cycle
							
							if(addr>=func_stack[stack_ptr-1][31:0]&&addr<=func_stack[stack_ptr-1][63:32])begin//if next address still in range: OK
								probe[123]=1;
							end
							else begin
								probe[122]=1;
								ind_verify=1;
							end
						end
						else begin//this is a place we must return, but we didn't return to correct place
							probe[121]=1;
							vio=1;
						end
					end
				end
				
			end
			if(vio)begin
				stack_ptr=0;
				target_cid=0;
				ind_verify=0;
				ret_verify=0;
				addr_bend_buf[1]=0;
				addr_bend_buf[0]=0;
				last_branch=0;
				last_func=0;
				//last_2_ret_act=last_2_ret_act<<2;
				//last_2_ret_act[1:0]=1;
				
				step=IDLE;
			end
		end
		else if(step==FEED)begin
			case(inh)
			0: begin
				en=1;
			end
			1: begin
				en=1;
				if(outdata_c>1)
				init_addr=addr;
				check_addr=0;
				atom=ind[0];
				step=WAIT_DATA;
			end
			2:begin
				en=1;
				if(outdata_c>1)
				init_addr=addr;
				check_addr=ind;
				atom=2'b10;
				step=WAIT_DATA;
			end
			3:begin
				en=1;
				step=IDLE;
			end
			4:begin
				en=1;
				step=WAIT_SYNC;
			end
			5:begin
				en=1;
				step=IDLE;
			end
			6:begin
				en=1;
				stack_ptr=0;
				ind_verify=0;
				ret_verify=0;
				addr_bend_buf[1]=0;
				addr_bend_buf[0]=0;
				last_branch=0;
				last_func=0;
				last_2_ret_act=last_2_ret_act<<2;
				last_2_ret_act[1:0]=1;
				step=IDLE;
			end
			endcase
		end
		else if(step==WAIT_SYNC)begin
			if(inh==5)begin
				step=IDLE;
			end
		end
		
	end
	
endmodule


module CFI_FIFO_test(clk,empty,overflow,read,outs,outh,outc,outd);
input clk;

output outs;
output[3:0] outh;
output[31:0] outc;
output[31:0] outd;


output reg read/*synthesis noprune*/;
reg[4:0] ins/*synthesis noprune*/;
reg[15:0] inh/*synthesis noprune*/;
reg[31:0] inc/*synthesis noprune*/;
reg[127:0] ind/*synthesis noprune*/;

output empty,overflow;

CFI_FIFO f1(clk,read,ins,inh,inc,ind,empty,overflow,outs,outh,outc,outd);

reg[7:0] count,data_c;

always@(posedge clk)begin
	if(count==0)begin
		read=1;
		count=count+1;
	end
	else if(count==1)begin
		read=1;
		count=count+1;
	end
	else begin
		read=1;
		count=0;
	end	
	
	case(data_c)
	0:begin
	ins=5'b10000;
	inh=16'h2121;
	inc=32'habab;
	ind=127'h0000abcd000003151234567800000315;
	end
	default:begin
	ins=0;
	inh=0;
	inc=0;
	ind=0;
	end
	endcase
	if(data_c<16)begin
		data_c=data_c+1;
	end
	else begin
		data_c=0;
	end
	
end

endmodule

module CFI_FIFO(clk,read,ins,inh,inc,ind,empty,overflow,outs,outh,outc,outd,probe);

parameter size=64;

input clk;

input[4:0] ins;
input[15:0] inh;
input[31:0] inc;
input[127:0] ind;

input read;

output reg outs;
output reg[3:0] outh;
output reg[31:0] outc;
output reg[31:0] outd;

output reg[127:0] probe;

output reg empty;
output reg overflow;

reg full;
reg[32:0] pin,pout;
reg[7:0] a_c;//atom_count;

reg bufs[size-1:0];
reg[3:0] bufh[size-1:0];
reg[31:0] bufc[size-1:0];
reg[31:0] bufd[size-1:0];

wire[31:0] data[3:0];
wire[3:0] header[3:0];

assign data[0]=ind[31:0];
assign data[1]=ind[63:32];
assign data[2]=ind[95:64];
assign data[3]=ind[127:96];

assign header[0]=inh[3:0];
assign header[1]=inh[7:4];
assign header[2]=inh[11:8];
assign header[3]=inh[15:12];

reg[3:0] data_c;

reg[7:0] self_rst;

reg[2:0] step;

always@(posedge clk)begin
	if(self_rst==8'h45)begin
		
	end
	else begin
		step=0;
		a_c=0;
		pin=0;
		pout=0;
		self_rst=8'h45;
		empty=1;
		overflow=0;
		full=0;
	end
	
	probe=bufd[pout]|(bufh[pout]<<32);
	
	if(overflow)begin
		a_c=0;
		step=0;
	end
	if(step==0)begin
		if(read&&empty==0)begin
			step=3;
			if(bufh[pout]==1)begin
				outs=bufs[pout];
				outh=bufh[pout];
				outc=bufc[pout];
				outd=bufd[pout][a_c];
				if(bufd[pout][a_c+1])begin
					a_c=0;
					full=0;
					pout=pout+1;
					if(pout>=size)begin
						pout=0;
					end
					if(pout==pin)begin
						empty=1;
					end
					else begin
						empty=0;
					end
				end
				else begin
					a_c=a_c+2;
				end
			end
			else begin
				outs=bufs[pout];
				outh=bufh[pout];
				outc=bufc[pout];
				outd=bufd[pout];
				full=0;
				pout=pout+1;
				if(pout>=size)begin
					pout=0;
				end
				if(pout==pin)begin
					empty=1;
				end
				else begin
					empty=0;
				end
			end
		end
		else begin
			outs=0;
			outh=0;
			outc=0;
			outd=0;
		end
	end
	else begin
		step=step-1;
	end
	
	data_c=0;
	overflow=0;
	if(ins[4])begin
		while(data_c<4)begin
			if(header[data_c]>0)begin
				empty=0;
				if(full)begin
					overflow=1;
				end
				bufs[pin]=ins[data_c];
				bufh[pin]=header[data_c];
				bufc[pin]=inc;
				bufd[pin]=data[data_c];
				pin=pin+1;
				if(pin>=size)begin
					pin=0;
				end
				if(pin==pout)begin
					full=1;
				end
				else begin
					full=0;
				end
			end
			data_c=data_c+1;
		end
	end
	
end

endmodule
