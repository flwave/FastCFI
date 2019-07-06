module decoder_pipe(clk,traces,outh,outd,outc,outs,probe);
	input clk;
	input[31:0] traces;
	output[127:0] outd;//data
	output[15:0] outh;//header
	output[31:0] outc;//cid
	output[4:0] outs;//state
	
	output reg[127:0] probe;
	
	wire[31:0] headers,headers_d2c;
	wire[31:0] pac_cs,pac_cs_d2c;
	wire[3:0] finishes,finishes_d2c;
	wire[31:0] traces_h2d,traces_d2c;
	wire[31:0] data_part0,data_part1,data_part2,data_part3;
	wire state_part0,state_part1,state_part2,state_part3;
	wire[31:0] cid_part0,cid_part1,cid_part2,cid_part3;
	
	header_pipe hp0(clk,traces,headers[31:24],pac_cs[31:24],finishes[3],headers,pac_cs,finishes);
	data_pipe regp0(.clk(clk),.traces(traces),.traces_o(traces_h2d));
	decode_byte_pipe dp0(clk,traces_h2d[7:0],headers[7:0],pac_cs[7:0],data_part0,state_part0,cid_part0);
	decode_byte_pipe dp1(clk,traces_h2d[15:8],headers[15:8],pac_cs[15:8],data_part1,state_part1,cid_part1);
	decode_byte_pipe dp2(clk,traces_h2d[23:16],headers[23:16],pac_cs[23:16],data_part2,state_part2,cid_part2);
	decode_byte_pipe dp3(clk,traces_h2d[31:24],headers[31:24],pac_cs[31:24],data_part3,state_part3,cid_part3);
	data_pipe regp1(clk,traces_h2d,headers,pac_cs,finishes,traces_d2c,headers_d2c,pac_cs_d2c,finishes_d2c);
	combine_pipe cp0(clk,traces_d2c,headers_d2c,pac_cs_d2c,finishes_d2c,
		data_part0,data_part1,data_part2,data_part3,
		state_part0,state_part1,state_part2,state_part3,
		cid_part0,cid_part1,cid_part2,cid_part3,
		outd,outh,outc,outs);
		
	always@(posedge clk)begin
		probe=data_part0|(data_part1<<32)|(data_part2<<64)|(data_part3<<96);
	end
	
endmodule

module data_pipe(clk,traces,headers,pac_cs,finishes,traces_o,headers_o,pac_cs_o,finishes_o);
	input clk;
	input[31:0] traces;
	input[31:0] headers;
	input[31:0] pac_cs;
	input[3:0] finishes;
	
	output reg[31:0] traces_o;
	output reg[31:0] headers_o;
	output reg[31:0] pac_cs_o;
	output reg[3:0] finishes_o;
	
	always@(posedge clk)begin
		traces_o<=traces;
		headers_o<=headers;
		pac_cs_o<=pac_cs;
		finishes_o<=finishes;
	end
	
endmodule

module header_pipe(clk,traces,header_last,pac_c_last,finish_last,headers,pac_cs,finishes);
	input clk;
	input[31:0] traces;
	input[7:0] header_last;
	input[7:0] pac_c_last;
	input finish_last;
	output reg[31:0] headers;
	output reg[31:0] pac_cs;
	output reg[3:0] finishes;
	
	parameter NONE=8'h00;
	parameter IDLE=8'h01;
	parameter ASYNC=8'h02;
	parameter ISYNC=8'h03;
	parameter ATOM=8'h04;
	parameter BRANCH=8'h05;
	parameter CONTEXT=8'h06;
	parameter WAYPOINT=8'h07;
	parameter WAITISYNC=8'h08;
	
	wire[7:0] trace[3:0];
	
	assign trace[0]=traces[7:0];
	assign trace[1]=traces[15:8];
	assign trace[2]=traces[23:16];
	assign trace[3]=traces[31:24];
	
	reg[7:0] trace_c;
	reg[7:0] pac_c;
	reg[7:0] header;
	reg finish;
	
	reg[1:0] branch_exception;
	
	reg wait_isync;
	
	always@(posedge clk)begin
		if(traces!=32'h1)begin
		finish=finish_last;
		header=header_last;
		pac_c=pac_c_last;
		trace_c=0;
		headers=0;
		pac_cs=0;
		finishes=0;
		while(trace_c<4)begin
			if(finish)begin//this trace is a new trace
				header=get_header(trace[trace_c],wait_isync);
				pac_c=0;
				if(header==ISYNC)begin
					wait_isync=0;
				end
				if(header==ASYNC||header==ISYNC||header==CONTEXT||header==WAYPOINT)begin
					finish=0;
				end
				else if(header==BRANCH)begin//the first byte won't contain exception indicator
					if(trace[trace_c][7])begin//continue data or exception
						finish=0;
					end
					else begin
						finish=1;
					end
					branch_exception=0;
				end
				else begin
					finish=1;
				end
			end
			else begin//this trace is continued trace
				if(header==ASYNC)begin
					if(trace[trace_c]==0)begin
						finish=0;
					end
					else begin
						if(trace[trace_c]==8'h80)begin
							wait_isync=1;
						end
						finish=1;
					end
				end
				else if(header==ISYNC)begin
					if(pac_c<8)begin
						finish=0;
					end
					else begin
						finish=1;
					end
				end
				else if(header==BRANCH)begin//note, now the data is at pac_c+1, since pac_c will +1 only at the end of this part
					if(branch_exception==2)begin
						pac_c=4;//for easy to process, the first exception byte is at packet 5(set 4, will +1 at the end), no matter if there is byte 1,2,3
						if(trace[trace_c][7])begin
							branch_exception=1;
							finish=0;
						end
						else begin
							finish=1;
						end
					end
					else if(branch_exception==1)begin
						pac_c=5;
						finish=1;
					end
					else if(pac_c<3)begin//now at 1,2,3
						if(trace[trace_c][7]||trace[trace_c][7:6]==2'b01)begin//continue data or exception
							finish=0;
						end
						else begin
							finish=1;
						end
						if(trace[trace_c][7:6]==2'b01)begin
							branch_exception=2;
						end
						else begin
							branch_exception=0;
						end
					end
					else if(pac_c==3)begin//=4
						if(trace[trace_c][6])begin
							finish=0;
							branch_exception=2;
						end
						else begin
							finish=1;
						end
					end
				end
				else if(header==CONTEXT)begin
					if(pac_c<3)begin
						finish=0;
					end
					else begin
						finish=1;
					end
				end
				else if(header==WAYPOINT)begin
					if(pac_c>=8'h05)begin
						finish=1;
					end
					else if(pac_c!=8'h04)begin
						if(trace[trace_c][7])begin
							finish=0;
						end
						else begin
							finish=1;
						end
					end
					else begin
						if(trace[trace_c][6])begin
							finish=0;
						end
						else begin
							finish=1;
						end
					end
				end
				else begin
					finish=1;
				end
				pac_c=pac_c+1;
			end
			headers=headers|(header<<(8*trace_c));
			pac_cs=pac_cs|(pac_c<<(8*trace_c));
			finishes=finishes|(finish<<trace_c);
			trace_c=trace_c+1;
		end
		end
	end
	
	function[7:0]get_header;
		input[7:0] trace;
		input wait_isync;
		begin
			if(wait_isync)begin
				if(trace==8'h08)begin
					get_header=ISYNC;
				end
				else begin
					get_header=IDLE;
				end
			end
			else begin
				if(trace==8'h00)begin
					get_header=ASYNC;
				end
				else if(trace==8'h08)begin
					get_header=ISYNC;
				end
				else if(trace==8'h6e)begin
					get_header=CONTEXT;
				end
				else if(trace[0]==1'b1)begin
					get_header=BRANCH;
				end
				else if(trace[7]==1'b1&&trace[0]==1'b0)begin
					get_header=ATOM;
				end
				else if(trace==8'h72)begin
					get_header=WAYPOINT;
				end
				else begin
					get_header=IDLE;
				end
			end
		end
	endfunction

endmodule

module decode_byte_pipe(clk,trace,header,pac_c,data_part,state_part,cid_part);
	input clk;
	input[7:0] trace;
	input[7:0] header;
	input[7:0] pac_c;
	
	output reg state_part;
	output reg[31:0] cid_part;
	output reg[31:0] data_part;
	
	parameter NONE=8'h00;
	parameter IDLE=8'h01;
	parameter ASYNC=8'h02;
	parameter ISYNC=8'h03;
	parameter ATOM=8'h04;
	parameter BRANCH=8'h05;
	parameter CONTEXT=8'h06;
	parameter WAYPOINT=8'h07;
	parameter WAITISYNC=8'h08;
	
	always@(posedge clk)begin
		state_part=0;
		data_part=0;
		cid_part=0;
		case(header)
		ASYNC:
		begin
			//nothing we should do
		end
		ISYNC:
		begin
			if(pac_c==0)begin
				//do nothing
			end
			else if(pac_c==1)begin
				state_part=trace[0];
				data_part=(trace[7:1]<<1);
			end
			else if(pac_c<=4)begin
				data_part=(trace<<(pac_c*8-8));
			end
			else if(pac_c==5)begin
				//do nothing
				data_part=trace[6:5];
			end
			else begin
				cid_part=(trace<<((pac_c-6)*8));
			end
		end
		ATOM:
		begin
			if(trace[6])begin
				data_part=(1<<9)|(trace[1]<<8)|(trace[2]<<6)|(trace[3]<<4)|(trace[4]<<2)|trace[5];
			end
			else if(trace[5])begin
				data_part=(1<<7)|(trace[1]<<6)|(trace[2]<<4)|(trace[3]<<2)|trace[4];
			end
			else if(trace[4])begin
				data_part=(1<<5)|(trace[1]<<4)|(trace[2]<<2)|trace[3];
			end
			else if(trace[3])begin
				data_part=(1<<3)|(trace[1]<<2)|trace[2];
			end
			else if(trace[2])begin
				data_part=(1<<1)|trace[1];
			end
			else begin
				data_part=0;
			end
			/*
			if(trace[6])begin
				data_part=(1<<5)|(trace[1]<<4)|(trace[2]<<3)|(trace[3]<<2)|(trace[4]<<1)|trace[5];
			end
			else if(trace[5])begin
				data_part=(1<<4)|(trace[1]<<3)|(trace[2]<<2)|(trace[3]<<1)|trace[4];
			end
			else if(trace[4])begin
				data_part=(1<<3)|(trace[1]<<2)|(trace[2]<<1)|trace[3];
			end
			else if(trace[3])begin
				data_part=(1<<2)|(trace[1]<<1)|trace[2];
			end
			else if(trace[2])begin
				data_part=(1<<1)|trace[1];
			end
			else begin
				data_part=1;
			end
			*/
			//data_part=((trace&8'h7f)>>1);
		end
		BRANCH:
		begin
			if(pac_c==0)begin
				data_part=trace[6:1];
			end
			else if(pac_c<=3)begin
				data_part=(trace[6:0]<<(pac_c*7-1));
				if(trace[7])begin
					data_part=data_part|32'h80000000;//add "1" at 31th bit, indicate this is full address, or, not add "1", means the highest address bit is taken by exception indicator
				end
			end
			else if(pac_c==4)begin
				if(trace[5:3]==3'b001)begin
					state_part=0;
					data_part=(trace[2:0]<<27);
				end
				else if(trace[5:4]==2'b01)begin
					state_part=1;
					data_part=(trace[3:0]<<27);
				end
			end
			else begin
				//do nothing
			end
		end
		CONTEXT:
		begin
			if(pac_c==0)begin
				//do nothing
			end
			else begin
				cid_part=(trace<<(pac_c*8-8));
			end
		end
		WAYPOINT:
		begin
			if(pac_c==0)begin
				//do nothing
			end
			else if(pac_c==1)begin
				data_part=trace[6:1];
			end
			else if(pac_c<=4)begin
				data_part=(trace[6:0]<<((pac_c-1)*7-1));
			end
			else if(pac_c==5)begin
				if(trace[5:3]==3'b001)begin
					state_part=0;
					data_part=(trace[2:0]<<27);
				end
				else if(trace[5:4]==2'b01)begin
					state_part=1;
					data_part=(trace[3:0]<<27);
				end
			end
			else begin
				//do nothing
			end
		end
		default:
		begin
			//do nothing
		end
		endcase
	end
	
endmodule

module combine_pipe(clk,traces,headers,pac_cs,finishes,
data_part0,data_part1,data_part2,data_part3,
state_part0,state_part1,state_part2,state_part3,
cid_part0,cid_part1,cid_part2,cid_part3,
outd,outh,outc,outs);
	
	input clk;
	input[31:0] traces;
	input[31:0] headers;
	input[31:0] pac_cs;
	input[3:0] finishes;
	input[31:0] data_part0,data_part1,data_part2,data_part3;
	input state_part0,state_part1,state_part2,state_part3;
	input[31:0] cid_part0,cid_part1,cid_part2,cid_part3;
	output reg[127:0] outd;//data
	output reg[15:0] outh;//header
	output reg[31:0] outc;//cid
	output reg[4:0] outs;//state

	parameter NONE=8'h00;
	parameter IDLE=8'h01;
	parameter ASYNC=8'h02;
	parameter ISYNC=8'h03;
	parameter ATOM=8'h04;
	parameter BRANCH=8'h05;
	parameter CONTEXT=8'h06;
	parameter WAYPOINT=8'h07;
	parameter WAITISYNC=8'h08;
	
	wire[31:0] data_part[3:0];
	wire[31:0] cid_part[3:0];
	wire state_part[3:0];
	wire[7:0] header[3:0];
	wire[7:0] pac_c[3:0];
	
	assign data_part[0]=data_part0;
	assign data_part[1]=data_part1;
	assign data_part[2]=data_part2;
	assign data_part[3]=data_part3;
	
	assign cid_part[0]=cid_part0;
	assign cid_part[1]=cid_part1;
	assign cid_part[2]=cid_part2;
	assign cid_part[3]=cid_part3;
	
	assign state_part[0]=state_part0;
	assign state_part[1]=state_part1;
	assign state_part[2]=state_part2;
	assign state_part[3]=state_part3;
	
	assign header[0]=headers[7:0];
	assign header[1]=headers[15:8];
	assign header[2]=headers[23:16];
	assign header[3]=headers[31:24];
	
	assign pac_c[0]=pac_cs[7:0];
	assign pac_c[1]=pac_cs[15:8];
	assign pac_c[2]=pac_cs[23:16];
	assign pac_c[3]=pac_cs[31:24];
	
	reg[31:0] address;
	reg state;
	reg[31:0] cid;
	
	reg[3:0] isync_buf;
	
	reg[31:0] data_temp;
	reg state_temp;
	reg[31:0] cid_temp;
	
	reg[7:0] data_c;
	reg[7:0] data_l;
	
	always@(posedge clk)begin
		outd=0;
		outh=0;
		outc=0;
		outs=0;
		data_c=0;
		if(traces!=32'h1)begin
		while(data_c<4)begin
			case(header[data_c])
			ASYNC:
			begin
				//nothing we should do
			end
			ISYNC:
			begin
				if(pac_c[data_c]==0)begin
					//do nothing
					//outh=outh|(5<<(data_c*4));
				end
				else if(pac_c[data_c]==1)begin
					state=state_part[data_c];
					data_temp=data_part[data_c];
				end
				else if(pac_c[data_c]<=4)begin
					data_temp=data_temp|data_part[data_c];
				end
				else if(pac_c[data_c]==5)begin
					if(data_part[data_c]==2)begin
						outh=outh|(6<<(data_c*4));//isync because of overflow
						isync_buf=6;
					end
					else begin
						outh=outh|(5<<(data_c*4));
						isync_buf=5;
					end
					address=data_temp;
				end
				else if(pac_c[data_c]==6)begin
					cid_temp=cid_part[data_c];
				end
				else if(pac_c[data_c]<9)begin
					outh=outh|(isync_buf<<(data_c*4));
					cid_temp=cid_temp|cid_part[data_c];
				end
				else begin
					cid=cid_temp|cid_part[data_c];
					outd=outd|(address<<(data_c*32));
					outh=outh|(2<<(data_c*4));
				end
			end
			ATOM:
			begin
				outd=outd|(data_part[data_c]<<(data_c*32));
				outh=outh|(1<<(data_c*4));
			end
			BRANCH:
			begin
				if(pac_c[data_c]==0)begin
					data_l=6;
					data_temp=data_part[data_c][30:0];
				end
				else if(pac_c[data_c]<=3)begin
					data_temp=data_temp|data_part[data_c][30:0];
					if(data_part[data_c][31])begin
						data_l=data_l+7;
					end
					else begin
						data_l=data_l+6;
					end
				end
				else if(pac_c[data_c]==4)begin
					state=state_part[data_c];
					data_temp=data_temp|data_part[data_c];
					if(state==0)begin
						data_l=data_l+3;
					end
					else begin
						data_l=data_l+4;
					end
				end
				else begin
					//do nothing
				end
				if(finishes[data_c])begin
					if(state==0)begin//arm
						address=((address>>(data_l+2))<<(data_l+2))|(data_temp<<2);
					end
					else begin//thumb
						address=((address>>(data_l+1))<<(data_l+1))|(data_temp<<1);
					end
					outd=outd|(address<<(data_c*32));
					if(pac_c[data_c]>4)begin
						outh=outh|(3<<(data_c*4));
					end
					else begin
						outh=outh|(2<<(data_c*4));
					end
				end
			end
			CONTEXT:
			begin
				if(pac_c[data_c]==0)begin
					//do nothing
				end
				else if(pac_c[data_c]==1)begin
					data_temp=data_part[data_c];
				end
				else begin
					data_temp=data_temp|data_part[data_c];
				end
				if(finishes[data_c])begin
					cid=data_temp;
				end
			end
			WAYPOINT:
			begin
				if(pac_c[data_c]==0)begin
					//do nothing
					outh=outh|(4<<(data_c*4));
				end
				else if(pac_c[data_c]==1)begin
					data_temp=data_part[data_c];
				end
				else if(pac_c[data_c]<=4)begin
					data_temp=data_temp|data_part[data_c];
				end
				else if(pac_c[data_c]==5)begin
					state=state_part[data_c];
					data_temp=data_temp|data_part[data_c];
				end
				else begin
					//do nothing
				end
				if(finishes[data_c])begin
					address=data_temp;
				end
			end
			default:
			begin
				//do nothing
			end
			endcase
			outs[data_c]=state;
			data_c=data_c+1;
		end
		outc=cid;
		outs[4]=1;
		end
	end
	
endmodule
