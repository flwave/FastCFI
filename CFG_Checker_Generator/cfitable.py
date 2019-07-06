import sys
import re
import copy
import math
import random

atom_enum=[[[0], [1]], [[0, 0], [1, 0], [0, 1], [1, 1]], [[0, 0, 0], [1, 0, 0], [0, 1, 0], [1, 1, 0], [0, 0, 1], [1, 0, 1], [0, 1, 1], [1, 1, 1]], [[0, 0, 0, 0], [1, 0, 0, 0], [0, 1, 0, 0], [1, 1, 0, 0], [0, 0, 1, 0], [1, 0, 1, 0], [0, 1, 1, 0], [1, 1, 1, 0], [0, 0, 0, 1], [1, 0, 0, 1], [0, 1, 0, 1], [1, 1, 0, 1], [0, 0, 1, 1], [1, 0, 1, 1], [0, 1, 1, 1], [1, 1, 1, 1]], [[0, 0, 0, 0, 0], [1, 0, 0, 0, 0], [0, 1, 0, 0, 0], [1, 1, 0, 0, 0], [0, 0, 1, 0, 0], [1, 0, 1, 0, 0], [0, 1, 1, 0, 0], [1, 1, 1, 0, 0], [0, 0, 0, 1, 0], [1, 0, 0, 1, 0], [0, 1, 0, 1, 0], [1, 1, 0, 1, 0], [0, 0, 1, 1, 0], [1, 0, 1, 1, 0], [0, 1, 1, 1, 0], [1, 1, 1, 1, 0], [0, 0, 0, 0, 1], [1, 0, 0, 0, 1], [0, 1, 0, 0, 1], [1, 1, 0, 0, 1], [0, 0, 1, 0, 1], [1, 0, 1, 0, 1], [0, 1, 1, 0, 1], [1, 1, 1, 0, 1], [0, 0, 0, 1, 1], [1, 0, 0, 1, 1], [0, 1, 0, 1, 1], [1, 1, 0, 1, 1], [0, 0, 1, 1, 1], [1, 0, 1, 1, 1], [0, 1, 1, 1, 1], [1, 1, 1, 1, 1]]]

cond=['EQ','NE','CS','HS','CC','LO','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE']
condexplist=['eq','ne','cs','hs','cc','lo','mi','pl','vs','vc','hi','ls','ge','lt','gt','le']
condexp='eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le'

atom_size=5

def get_info(text):
	#===========extract basic info
	asm=[]
	bsadd=0
	nowsec=''
	for string in text:
		sec=re.findall("Disassembly of section (\S+):",string)
		if len(sec)>0:
			nowsec=sec[0]
		head=re.findall("^([\d+,a-f]+) <(\S+)>",string)
		if len(head)!=0:
			temp={'func':head[0][1],'sec':nowsec,'sadd':int(head[0][0],16),'eadd':int(head[0][0],16),'branch':[],'comment':[]}
			bsadd=int(head[0][0],16)
			asm.append(temp)
		else:
			info=re.findall("([\d+,a-f]+):\s+\S........\s+(nop)()",string)
			if len(info)==0:
				info=re.findall("([\d+,a-f]+):\s+\S........\s+(\S+)\s+([^;]+)",string)
			comment=re.findall(".*;\s*(0x[0-9,a-f]+)",string)
			if len(info)!=0:
				if len(comment)>0:
					asm[-1]['comment'].append(comment[0])
					#comment=int(comment[0][2:],16)
					#print hex(comment)
				if bsadd==[]:
					bsadd=int(info[0][0],16)
				asm[-1]['eadd']=int(info[0][0],16)
				temp=get_branch(info,bsadd)
				if temp!=[]:
					asm[-1]['branch'].append(temp)
					bsadd=[]
	
	#============find out the return address of functions
	"""
	allfunc=[a['func'] for a in asm]
	
	for a in asm:
		for i_b in range(len(a['branch'])):
			b=a['branch'][i_b]
			if len(b['func'])>0:
				func=b['func']
				if '+' in func:
					func=func[:func.index('+')]
				if func==a['func']:
					continue#this is a in function direct jump
				try:
					pos=allfunc.index(func)
				except:
					pos=-1
				if pos>=0:
					if len(asm[pos]['branch'])>0 and asm[pos]['branch'][-1]['ind'] and i_b+1<len(a['branch']):
						if '|' in asm[pos]['branch'][-1]['d']:
							asm[pos]['branch'][-1]['d']+='|'+hex(a['branch'][i_b+1]['bs'])[2:]
						else:
							try:
								verify=int(asm[pos]['branch'][-1]['d'],16)
								asm[pos]['branch'][-1]['d']+='|'+hex(a['branch'][i_b+1]['bs'])[2:]
							except:
								asm[pos]['branch'][-1]['d']=hex(a['branch'][i_b+1]['bs'])[2:]
	"""
	"""
	for i_a in range(min(len(asm),100)):
		print asm[i_a]
		print '==========='
	"""
	return asm

def get_branch(info,bsadd):
	#print info[0]
	temp=[]
	parts=info[0][2].split(' ')
	for i in range(len(parts)):
		parts[i]=parts[i].replace("{","")
		parts[i]=parts[i].replace("}","")
		parts[i]=parts[i].replace("[","")
		parts[i]=parts[i].replace("]","")
		parts[i]=parts[i].replace(",","")
	if info[0][1][0]=='b' and len(re.findall("bfc|bfi|bic|bkpt",info[0][1]))==0:#branch instruction
		temp={'bs':bsadd,'be':int(info[0][0],16),'d':parts[0],'func':[],'ind':0,'fix':0,'remark':'n'}
		if len(re.findall("r",parts[0]))!=0 and parts[0]!="lr":
			temp['d']+="+++++++++++++++++++++"
		func=re.findall("<(\S+)>",parts[-1]);
		if len(func)>0:
			temp['func']=func[0];
		else:
			temp['ind']=1#indirect branch
			#print info[0]
	elif info[0][1]=="cbz" or info[0][1]=="cbnz":
		temp={'bs':bsadd,'be':int(info[0][0],16),'d':parts[1],'func':[],'ind':0,'fix':0,'remark':'n'}
		if len(re.findall("r",parts[1]))!=0 and parts[1]!="lr":
			temp['d']+="+++++++++++++++++++++"
		func=re.findall("<(\S+)>",parts[-1]);
		if len(func)>0:
			temp['func']=func[0];
		else:
			temp['ind']=1#indirect branch
	else:#change pc
		if(len(info[0][1])>=3 and info[0][1][0:3]=='pop'):
			for i in range(len(parts)):
				if len(re.findall("pc",parts[i]))!=0:
					temp={'bs':bsadd,'be':int(info[0][0],16),'d':'??','func':[],'ind':0,'fix':0,'remark':'n'}
					func=re.findall("<(\S+)>",parts[-1]);
					if len(func)>0:
						temp['func']=func[0];
					else:
						temp['ind']=1#indirect branch
					break
		elif((len(info[0][1])>=2 and info[0][1][:2]=="st") or (len(info[0][1])>=3 and info[0][1][:3]=="ldm")):
			for i in range(len(parts)):
				if i>0 and len(re.findall("pc",parts[i]))!=0:
					temp={'bs':bsadd,'be':int(info[0][0],16),'d':'??','func':[],'ind':0,'fix':0,'remark':'n'}
					if len(info[0][1])>=3 and info[0][1][:3]=="ldm":
						temp['remark']='ldm'
					func=re.findall("<(\S+)>",parts[-1]);
					if len(func)>0:
						temp['func']=func[0];
					else:
						temp['ind']=1#indirect branch
					break
		else:
			for i in range(len(parts)):
				if i==0 and len(re.findall("pc",parts[i]))!=0:
					temp={'bs':bsadd,'be':int(info[0][0],16),'d':'??','func':[],'ind':0,'fix':0,'remark':'n'}
					func=re.findall("<(\S+)>",parts[-1]);
					if len(func)>0:
						temp['func']=func[0];
					else:
						temp['ind']=1#indirect branch
					break
	
	head=info[0][1].split('!')[0]
	head=head.split('.')[0]
	
	if not (info[0][1]=="cbz" or info[0][1]=="cbnz") and len(temp)>0 and (head[-2:] not in condexplist):#there is no condition code
		temp['fix']=1
	
	return temp

def out_asm(asm,filename):
	bound=[]
	for a in asm:
		if a['sec']=='.text':
			if bound==[]:
				bound=[a['sadd'],a['eadd']]
			else:
				if a['sadd']<bound[0]:
					bound[0]=a['sadd']
				if a['eadd']>bound[1]:
					bound[1]=a['eadd']
	f=open(filename,'wb')
	f.write('bound: '+hex(bound[0])[2:]+','+hex(bound[1])[2:]+'\n')
	for a in asm:
		f.write('function: '+a['func']+' at section '+a['sec']+'\n')
		f.write('start at '+str(hex(a['sadd']))[2:]+' end at '+str(hex(a['eadd'])[2:])+'\n')
		f.write('comment: ')
		if len(a['comment'])>0:
			for i_c in range(len(a['comment'])-1):
				f.write(a['comment'][i_c])
				f.write('|')
			f.write(a['comment'][-1])
		f.write('\n')
		for b in a['branch']:
			f.write('branch: start '+str(hex(b['bs']))[2:]+' source '+str(hex(b['be']))[2:]+' to '+b['d']+' fix '+str(b['fix'])+' ind '+str(b['ind'])+' remark '+b['remark']+'\n')
	f.close()

def out_funcs(asm,filename):
	f=open(filename,'wb')
	for a in asm:
		f.write(a['func']+'\n')
	f.close()
	
	
def in_asm(filename,funcs,exclude,sysfuncs,exsys):
	f=open(filename,'r')
	text=[]
	for line in f:
		text.append(line[0:-1])
	f.close()
	asm=[]
	start=0
	bound=[]
	func_entry=[]
	for string in text:#finding function entry
		add=re.findall("^start at (\S+) end at (\S+)",string)
		if len(add)!=0:
			func_entry.append(int(add[0][0],16))
	for string in text:
		if bound==[]:
			boundary=re.findall("^bound: (\S+),(\S+)",string)
			bound=[int(boundary[0][0],16),int(boundary[0][1],16)]
		head=re.findall("^function: (\S+) at section (\S+)",string)
		if len(head)!=0:
			sec=head[0][1]
			func=head[0][0]
			if (exsys and sec!='.text') or (exsys and func in sysfuncs):
				start=0
			else:
				if exclude==0:
					if len(funcs)==0 or (func in funcs):
						start=1
						temp={'func':func,'sadd':[],'eadd':[],'branch':[],'comment':[]}
						asm.append(temp)
					else:
						start=0
				else:
					if func not in funcs:
						start=1
						temp={'func':func,'sadd':[],'eadd':[],'branch':[],'comment':[]}
						asm.append(temp)
					else:
						start=0
		elif start:
			add=re.findall("^start at (\S+) end at (\S+)",string)
			if len(add)!=0:
				asm[-1]['sadd']=int(add[0][0],16)
				asm[-1]['eadd']=int(add[0][1],16)
			com=re.findall("^comment: (\S+)",string)
			if len(com)!=0:
				com=com[0].split('|')
				for i_c in range(len(com)):
					com[i_c]=int(com[i_c],16)-1
				asm[-1]['comment']=com
			branch=re.findall("^branch: start (\S+) source (\S+) to (\S+) fix (\S+) ind (\S+)",string)
			if len(branch)!=0:
				temp={'bs':int(branch[0][0],16),'be':int(branch[0][1],16),'d':[],'fix':int(branch[0][3]),'ind':int(branch[0][4])}
				ds=branch[0][2]
				ds=ds.split('|')
				try:
					for ld in range(len(ds)):
						temp['d'].append(int(ds[ld],16))
				except:
					if ds[ld][0]=='r':
						temp['d'].append('NAr')
					else:
						temp['d'].append('NA')
				asm[-1]['branch'].append(temp)
	asm[0]['bound']=bound
	asm[0]['func_entry']=func_entry
	for a in asm:
		target_cand=[]
		for c in a['comment']:
				if c>=asm[0]['bound'][0] and c<=asm[0]['bound'][1] and c in asm[0]['func_entry']:
					target_cand.append(c)
		a['valid_fix_target']=list(set(target_cand))
	
	return asm

def find_addrinblock(addr,branges):
	frange=[0,len(branges)-1]
	while 1:
		this=(frange[0]+frange[1])/2
		b=branges[this]
		if addr>=b[0] and addr<=b[1]:
			return this
		elif frange[0]==frange[1]:
			return -1
		elif frange[0]==frange[1]-1:
			if this==frange[0]:
				frange[0]=frange[1]
			elif this==frange[1]:
				frange[1]=frange[0]
		elif addr<b[0]:
			frange[1]=this
		else:
			frange[0]=this

def asm2blocks(asm,addrrange,auto_fix_ind):	
	if auto_fix_ind:
		for i_a in range(len(asm)):#if we enable auto fixed target detection, we should modify some fix=0 to fix=1 and add the target address
			if len(asm[i_a]['valid_fix_target'])>0:
				for i_b in range(len(asm[i_a]['branch'])):
					if 'NAr' in asm[i_a]['branch'][i_b]['d']:
						asm[i_a]['branch'][i_b]['d'].remove('NAr')
						asm[i_a]['branch'][i_b]['d'].extend(asm[i_a]['valid_fix_target'])
			else:
				for i_b in range(len(asm[i_a]['branch'])):
					for i_d in range(len(asm[i_a]['branch'][i_b]['d'])):
						if asm[i_a]['branch'][i_b]['d'][i_d]=='NAr':
							asm[i_a]['branch'][i_b]['d'][i_d]='NA'
	else:
		for i_a in range(len(asm)):
			for i_b in range(len(asm[i_a]['branch'])):
				for i_d in range(len(asm[i_a]['branch'][i_b]['d'])):
					if asm[i_a]['branch'][i_b]['d'][i_d]=='NAr':
						asm[i_a]['branch'][i_b]['d'][i_d]='NA'
	for i_a in range(len(asm)):#add the branch fail address (not for fixed branch instruction)
		a=asm[i_a]
		for lb in range(len(a['branch'])):
			if a['branch'][lb]['fix']==0:
				if lb==len(a['branch'])-1:#last one, fail will jump to the begin of next func
					a['branch'][lb]['d'].append(asm[i_a+1]['branch'][0]['bs'])
				else:
					a['branch'][lb]['d'].append(a['branch'][lb+1]['bs'])
	#add the begin and end flag, and the the func name
	for a in asm:
		valid=0
		for i_b in range(len(a['branch'])):
			if a['branch'][i_b]['ind']:
				valid=1
				break
		valid=1#disable function validation check
		for i_b in range(len(a['branch'])):
			a['branch'][i_b]['func']=a['func']
			a['branch'][i_b]['fs']=0
			a['branch'][i_b]['fe']=0
			a['branch'][i_b]['fepos']=-1
			if valid:
				if i_b==0:
					a['branch'][i_b]['fs']=1
				if i_b==len(a['branch'])-1:
					a['branch'][i_b]['fe']=1
	print 'END add begin end flag, func name'
	#extract blocks
	blocks=[]
	for a in asm:
		for b in a['branch']:
			blocks.append(b)
	print 'END extract blocks'
	#add function position pointer
	func=''
	for i_b in range(len(blocks)):
		if blocks[i_b]['fs']:
			func=blocks[i_b]['func']
			pos=copy.deepcopy(i_b)
		if blocks[i_b]['func']==func and blocks[i_b]['fe']:
			blocks[pos]['fepos']=i_b
	print 'END add func ptr'
	#delete blocks out of range
	delete=[]
	for i_b in range(len(blocks)):
		if blocks[i_b]['bs']<addrrange[0] or blocks[i_b]['bs']>addrrange[1]:
			delete.append(i_b)
	delete.reverse()
	
	for de in delete:
		del blocks[de]
	print 'END blocks'
	
	#add the pointer of each destination
	branges=[[b['bs'],b['be']] for b in blocks]
	
	count=0
	for b in blocks:
		b['dpos']=[]
		b['spos']=[]
	for i_b in range(len(blocks)):
		#print count
		count+=1
		for i_d in range(len(blocks[i_b]['d'])):
			found=0
			if blocks[i_b]['d'][i_d]!='NA':
				i=find_addrinblock(blocks[i_b]['d'][i_d],branges)
				if i>=0:
					found=1
					blocks[i_b]['dpos'].append(i)
					blocks[i]['spos'].append(i_b)
			if(found==0):
				blocks[i_b]['dpos'].append(-1)
	print 'END add pointer'
	#add the stateful information of each call [source,destination]
	
	funcnames=[b['func'] for b in blocks]
	
	for i_b in range(len(blocks)):
		#print i_b
		blocks[i_b]['stateful']=[]
		for d in blocks[i_b]['d']:
			found=0
			func=''
			if d!='NA':
				i_b2=find_addrinblock(d,branges)
				if blocks[i_b2]['bs']==d and blocks[i_b2]['fs']==1:
					found=1
					func=blocks[i_b2]['func']
					pos=i_b2
			if found==0:
				blocks[i_b]['stateful'].append([])
			else:
				i_b2=blocks[pos]['fepos']
				if i_b2==-1:
					print i_b,'error'
				if i_b+1<len(blocks) and blocks[i_b+1]['func']==blocks[i_b]['func']:
					blocks[i_b]['stateful'].append([i_b2,i_b+1])	
				
	"""
	print "blocks:========"
	for i_b in range(min(len(blocks),100)):
		print i_b,blocks[i_b]
	"""
	return blocks

def find_able_to_ind(blocks):
	flag=[0 for i in range(len(blocks))]
	for i_b in range(len(blocks)):
		if blocks[i_b]['ind']:
			blocks[i_b]['toind']=[i_b]
		else:
			blocks[i_b]['toind']=[]
	for i_b in range(len(blocks)):
		if blocks[i_b]['ind']==0:
			find_ind(i_b,blocks,flag)
			#blocks[i_b]['toind'].extend(ind)

def find_ind(pos,blocks,flag):
	if flag[pos]:#has been processed
		return
	else:
		flag[pos]=1
		if blocks[pos]['ind']:
			return
		for d in blocks[pos]['dpos']:
			if d>=0:
				find_ind(d,blocks,flag)
				#print len(blocks[d]['toind'])
				blocks[pos]['toind'].extend(blocks[d]['toind'])
				blocks[pos]['toind']=list(set(blocks[pos]['toind']))

def get_valid_blocks(pos,indpos,blocks,flag):
	#given a indirect block, find the valid direct block of it
	#valid direct block: only has pathes to this indirect block but not other indirect blocks
	if flag[pos]:
		return
	else:
		flag[pos]=1
		valid=1
		for toind in blocks[pos]['toind']:
			if toind!=indpos:
				valid=0
				break
		if valid==0:
			return
		else:
			blocks[indpos]['optset'].append(pos)
			blocks[indpos]['optset']=list(set(blocks[indpos]['optset']))
		for s in blocks[pos]['spos']:
			get_valid_blocks(s,indpos,blocks,flag)

def out_asm_final(asm,filename):
	f=open(filename,'wb')
	for a in asm:
		f.write('function: '+a['func']+'\n')
		f.write('start at '+str(hex(a['sadd']))[2:]+' end at '+str(hex(a['eadd'])[2:])+'\n')
		for b in a['branch']:
			f.write('branch: start '+str(hex(b['bs']))[2:]+' source '+str(hex(b['be']))[2:]+' to '+str(b['d'])+'\n')
	f.close()

def gen_unit(asm,in_n,filename):
	for a in asm:#add the branch fail address
		for lb in range(len(a['branch'])-1):
			a['branch'][lb]['d'].append(a['branch'][lb+1]['bs'])
	
	#extract blocks
	blocks=[]
	for a in asm:
		for b in a['branch']:
			blocks.append(b)
	#add blocks according to destination addresses
	blocks_add=[]
	for b in blocks:
		for d in b['d']:
			for cb in blocks:
				if d>cb['bs'] and d<=cb['be']:
					temp=copy.deepcopy(cb)
					temp['bs']=d
					blocks_add.append(temp)
					break
	blocks.extend(blocks_add)
	for b in blocks:
		b['dpos']=[]
		b['in_capt']=[0 for i in range(in_n)]
		for i_d in range(len(b['d'])):
			found=0
			for i in range(len(blocks)):
				if blocks[i]['bs']==b['d'][i_d]:
					found=1
					b['dpos'].append(i)
					break
			if(found==0):
				b['dpos'].append(-1)
	
	f=open(filename,'wb')
	for i_b in range(len(blocks)):
		for i_d in range(len(blocks[i_b]['d'])):
			cont_pos=blocks[i_b]['dpos'][i_d]
			if(cont_pos>0):
				cont_in=in_n
				for i_in in range(in_n):
					if(blocks[cont_pos]['in_capt'][i_in]==0):
						cont_in=i_in
						break
				if(cont_in<in_n):
					blocks[cont_pos]['in_capt'][cont_in]=1
					f.write('assign ins['+str(cont_pos)+']['+str(5*cont_in+4)+':'+str(5*cont_in)+']=outs['+str(i_b)+']['+str(5*i_d+4)+':'+str(5*i_d)+'];\n')
				else:
					print "error!!!!!!!"
					return
	for i_b in range(len(blocks)):
		for i_in in range(in_n):
			if(blocks[i_b]['in_capt'][i_in]==0):
				f.write('assign ins['+str(i_b)+']['+str(5*i_in+4)+':'+str(5*i_in)+']=0;\n')
	for i_b in range(len(blocks)):
		f.write('CFI_unit cu'+str(i_b)+'(rst,start['+str(i_b)+'],init_addr,32\'h'+str(hex(blocks[i_b]['bs']))[2:]+',check_addr,atoms,atomson,ins['+str(i_b)+'],outs['+str(i_b)+'],last['+str(i_b)+'],probeu['+str(i_b)+']);\n')
	f.close()
	"""
	f=open(filename,'wb')
	for b in blocks:
		f.write('32\'h'+str(hex(b['bs']))[2:]+':\n')
		f.write('begin\n')
		for i in range(len(b['d'])):
			f.write('	ROMf['+str(32*i+31)+':'+str(32*i)+']=32\'h'+str(hex(b['d'][i]))[2:]+';\n')
		f.write('end\n')
	"""
	for b in blocks:
		print b
	return 0

def find_result_atom(blocks,pos,atoms):
	stack_info=[]
	for atom in atoms:
		if(len(blocks[pos]['dpos'])>=atom+1):
			if(blocks[pos]['d'][atom]=='NA' or blocks[pos]['dpos'][atom]==-1):
				return [-2,stack_info]#valid, but unknown
			else:
				if len(blocks[pos]['stateful'][atom])>0:
					stack_info.append(blocks[pos]['stateful'][atom])
				pos=blocks[pos]['dpos'][atom]
				if(pos<0):
					return [-2,stack_info]
		else:
			return -1#invalid
	return [pos,stack_info]

def atom2str(atom):
	s=''
	for a in atom:
		s+=str(a)
	return s

def gen_comb(blocks,filename,split):
	
	max_func_len=0
	max_block_len=0
	now_func_add_s=-1
	func=''
	for b in blocks:
		if now_func_add_s>=0:
			if b['fs']:
				now_func_add_s=b['bs']
			if b['fe']:
				if b['be']-now_func_add_s>max_func_len:
					max_func_len=b['be']-now_func_add_s
		else:
			if b['fs']:
				now_func_add_s=b['bs']
		
		if b['be']-b['bs']>max_block_len:
			max_block_len=b['be']-b['bs']
	func_bits=0
	block_bits=0
	for i in range(100):
		if 2**i>=max_func_len:
			func_bits=i
			break
	for i in range(100):
		if 2**i>=max_block_len:
			block_bits=i
			break
	
	print max_func_len,max_block_len,func_bits,block_bits
	
	num=math.ceil(float(len(blocks))/split)
	parts=[(i+1)*split for i in range(int(num-1))]
	parts.append(len(blocks))
	
	f=open(filename,'wb')
	
	f.write('module CFI_kernel(clk,en,init_addr,check_addr,atom,addr,addr_aux,info,probe);\n')
	f.write('parameter nodes='+str(len(blocks))+';\n')
	f.write('parameter func_bits='+str(func_bits)+';\n')
	f.write('parameter block_bits='+str(block_bits)+';\n')
	f.write('input clk/*synthesis keep*/;\n')
	f.write('input en/*synthesis keep*/;\n')
	f.write('output reg[31:0] addr;\n')
	f.write('output reg[func_bits+block_bits+32-1:0] addr_aux;\n')
	f.write('output reg[4:0] info;\n')#[0]function begin [1]function end [2]uncertain [3]invalid path [4]in block range(for first time validation)
	f.write('input[31:0] init_addr/*synthesis keep*/;\n')
	f.write('input[31:0] check_addr/*synthesis keep*/;\n')
	f.write('input[1:0] atom/*synthesis keep*/;\n')#[0] atom [1] invalid
	f.write('output reg[127:0] probe;\n')
	
	f.write('wire[31:0] addr_p['+str(len(parts)-1)+':0];\n')
	f.write('wire[4:0] info_p['+str(len(parts)-1)+':0];\n')
	f.write('wire[func_bits+block_bits+32-1:0] addr_aux_p['+str(len(parts)-1)+':0];\n')
	
	for i_p in range(len(parts)):
		f.write('CFI_kernel_part_'+str(i_p)+' ckp'+str(i_p)+'(en,init_addr,check_addr,atom,addr_p['+str(i_p)+'],addr_aux_p['+str(i_p)+'],info_p['+str(i_p)+']);\n')
	
	f.write('always@(posedge clk)begin\n')
	#f.write('if(en)begin\n')
	f.write('addr=')
	for i_p in range(len(parts)):
		f.write('addr_p['+str(i_p)+']')
		if i_p==len(parts)-1:
			f.write(';\n')
		else:
			f.write('|')
	f.write('info=')
	for i_p in range(len(parts)):
		f.write('info_p['+str(i_p)+']')
		if i_p==len(parts)-1:
			f.write(';\n')
		else:
			f.write('|')
	f.write('addr_aux=')
	for i_p in range(len(parts)):
		f.write('addr_aux_p['+str(i_p)+']')
		if i_p==len(parts)-1:
			f.write(';\n')
		else:
			f.write('|')
	#f.write('end\n')#end en
	f.write('end\n')
	f.write('endmodule\n')
	#--------------------------part module---------------------
	
	for i_p in range(len(parts)):
		if i_p==0:
			brange=[0,parts[i_p]]
		else:
			brange=[parts[i_p-1],parts[i_p]]
		blen=brange[1]-brange[0]
		
		f.write('module CFI_kernel_part_'+str(i_p)+'(en,addr,check_addr,atom,addr_out,addr_aux,info);\n')
		f.write('parameter func_bits='+str(func_bits)+';\n')
		f.write('parameter block_bits='+str(block_bits)+';\n')
		f.write('input[31:0] addr/*synthesis keep*/;\n')
		f.write('input en/*synthesis keep*/;\n')
		f.write('output reg[31:0] addr_out;\n')
		f.write('output reg[func_bits+block_bits+32-1:0] addr_aux;\n')
		f.write('output reg[4:0] info;\n')
		#f.write('input[31:0] init_addr/*synthesis keep*/;\n')
		f.write('input[31:0] check_addr/*synthesis keep*/;\n')
		f.write('input[1:0] atom/*synthesis keep*/;\n')
		
		#f.write('reg[31:0] addr;\n')
		
		f.write('reg[31:0] addr_p['+str(blen-1)+':0];\n')
		f.write('reg[4:0] info_p['+str(blen-1)+':0];\n')
		f.write('reg[func_bits+block_bits+32-1:0] addr_aux_p['+str(blen-1)+':0];\n')
		
		f.write('always@(en,addr,check_addr,atom)begin\n')
		f.write('if(en)begin\n')
		#f.write('if(init_addr)\n')
		#f.write('addr=init_addr;\n')
		#f.write('else\n')
		#f.write('addr=addr_in;\n')
		for i_b in range(brange[0],brange[1]):
			
			f.write('if(addr>=32\'h'+hex(blocks[i_b]['bs'])[2:]+'&&addr<=32\'h'+hex(blocks[i_b]['be'])[2:]+')begin\n')
			#blocklen=blocks[i_b]['be']-blocks[i_b]['bs']
			if i_b!=len(blocks)-1 and blocks[i_b]['fe']==0:
				blocklen=blocks[i_b+1]['bs']-blocks[i_b]['bs']
			else:
				blocklen=blocks[i_b]['be']-blocks[i_b]['bs']
			funclen=-1
			until_end=0
			if blocks[i_b]['fs']:
				func=blocks[i_b]['func']
				for i_b2 in range(i_b,len(blocks)):
					if blocks[i_b2]['func']==func:
						if blocks[i_b2]['fe']:
							funclen=blocks[i_b2]['be']-blocks[i_b]['bs']
							break
						elif i_b2==len(blocks)-1:
							until_end=1
					else:
						break
			if until_end:
				funclen=blocks[-1]['be']-blocks[i_b]['bs']
			if funclen>=0:
				f.write('	'+'addr_aux_p['+str(i_b-brange[0])+']=('+str(funclen)+'<<(32+block_bits))|('+str(blocklen)+'<<32)|32\'h'+hex(blocks[i_b]['bs'])[2:]+';\n')
			else:
				f.write('	'+'addr_aux_p['+str(i_b-brange[0])+']=('+str(blocklen)+'<<32)|32\'h'+hex(blocks[i_b]['bs'])[2:]+';\n')
			
			f.write('	'+'info_p['+str(i_b-brange[0])+'][4]=1;\n')
			if blocks[i_b]['fs'] and blocks[i_b]['fe']==0:
				f.write('	'+'info_p['+str(i_b-brange[0])+'][1:0]=1;\n')
			elif blocks[i_b]['fs']==0 and blocks[i_b]['fe']:
				if blocks[i_b]['ind']:
					f.write('	'+'info_p['+str(i_b-brange[0])+'][1:0]=2;\n')
				else:
					f.write('	'+'info_p['+str(i_b-brange[0])+'][1:0]=0;\n')
			elif blocks[i_b]['fs'] and blocks[i_b]['fe']:
				f.write('	'+'info_p['+str(i_b-brange[0])+'][1:0]=3;\n')
			else:
				f.write('	'+'info_p['+str(i_b-brange[0])+'][1:0]=0;\n')
			if blocks[i_b]['ind']==0:#this is a direct branch, only consider atom
				f.write('	'+'if(atom==0)begin\n')
				f.write('	'*2+'addr_p['+str(i_b-brange[0])+']=32\'h'+hex(blocks[i_b]['d'][0])[2:]+';\n')
				f.write('	'*2+'info_p['+str(i_b-brange[0])+'][3:2]=0;\n')
				"""	
				if blocks[i_b]['dpos'][0]>=0:
					npos=blocks[i_b]['dpos'][0]
					f.write('	'*2+'addr_p['+str(i_b-brange[0])+']=32\'h'+hex(blocks[i_b]['d'][0])[2:]+';\n')
					f.write('	'*2+'info_p['+str(i_b-brange[0])+'][3:2]=0;\n')
				else:
					f.write('	'*2+'addr_p['+str(i_b-brange[0])+']=0;\n')
					f.write('	'*2+'info_p['+str(i_b-brange[0])+'][3:2]=1;\n')
				"""
				f.write('	'+'end\n')
				if blocks[i_b]['fix']==0 and len(blocks[i_b]['dpos'])>1:
					f.write('	'+'else if(atom==1)begin\n')
					f.write('	'*2+'addr_p['+str(i_b-brange[0])+']=32\'h'+hex(blocks[i_b]['d'][1])[2:]+';\n')
					f.write('	'*2+'info_p['+str(i_b-brange[0])+'][3:2]=0;\n')
					"""
					if blocks[i_b]['dpos'][1]>=0:
						npos=blocks[i_b]['dpos'][1]
						f.write('	'*2+'addr_p['+str(i_b-brange[0])+']=32\'h'+hex(blocks[i_b]['d'][1])[2:]+';\n')
						f.write('	'*2+'info_p['+str(i_b-brange[0])+'][3:2]=0;\n')
					else:
						f.write('	'*2+'addr_p['+str(i_b-brange[0])+']=0;\n')
						f.write('	'*2+'info_p['+str(i_b-brange[0])+'][3:2]=1;\n')
					"""
					f.write('	'+'end\n')
				f.write('	'+'else begin\n')
				f.write('	'*2+'addr_p['+str(i_b-brange[0])+']=0;\n')
				#f.write('	'*2+'info_p['+str(i_b-brange[0])+'][3:2]=2;\n')
				f.write('	'*2+'info_p['+str(i_b-brange[0])+'][3:2]=0;\n')#direct branch cannot be attacked, if atom input is wrong, it maybe another program. we just ignore
				f.write('	'+'end\n')
			else:#this is an indirect branch, only consider check_addr
				f.write('	'+'addr_p['+str(i_b-brange[0])+']=check_addr;\n')
				once=0
				lend=0
				if blocks[i_b]['fix']:#no condition code
					lend=len(blocks[i_b]['d'])
				else:#may have "1" atom
					lend=len(blocks[i_b]['d'])-1
					f.write('	'+'if(atom==1)begin\n')
					f.write('	'*2+'addr_p['+str(i_b-brange[0])+']=32\'h'+hex(blocks[i_b]['d'][-1])[2:]+';\n')
					f.write('	'*2+'info_p['+str(i_b-brange[0])+'][3:2]=0;\n')
					f.write('	'+'end\n')
					once+=1
				for i_d in range(lend):
					if blocks[i_b]['d'][i_d]!='NA':
						if once>0:
							f.write('	'+'else ')
						else:
							f.write('	')
						f.write('if(check_addr==32\'h'+hex(blocks[i_b]['d'][i_d])[2:]+')begin\n')
						f.write('	'*2+'info_p['+str(i_b-brange[0])+'][3:2]=0;\n')
						"""
						if blocks[i_b]['dpos'][i_d]>=0:
							npos=blocks[i_b]['dpos'][i_d]
							#f.write('	'+'addr_p['+str(i_b-brange[0])+']=32\'h'+hex(blocks[npos]['be'])[2:]+';\n')
							f.write('	'*2+'info_p['+str(i_b-brange[0])+'][3:2]=0;\n')
						else:
							#f.write('	'+'addr_p['+str(i_b-brange[0])+']=0;\n')
							f.write('	'*2+'info_p['+str(i_b-brange[0])+'][3:2]=1;\n')
						"""
						f.write('	'+'end\n')
						once+=1
				if once>0:
					f.write('	'+'else begin\n')
				if 'NA' in blocks[i_b]['d']:
					#f.write('	'*2+'addr_p['+str(i_b-brange[0])+']=32\'h'+hex(blocks[i_b]['be'])[2:]+';\n')
					f.write('	'*2+'info_p['+str(i_b-brange[0])+'][3:2]=1;\n')
				else:
					#f.write('	'*2+'addr_p['+str(i_b-brange[0])+']=32\'h'+hex(blocks[i_b]['be'])[2:]+';\n')
					f.write('	'*2+'info_p['+str(i_b-brange[0])+'][3:2]=2;\n')
				if once>0:
					f.write('	'+'end\n')
				#f.write('	'+'endcase\n')
			f.write('end\n')
			f.write('else begin\n')
			f.write('	'+'addr_p['+str(i_b-brange[0])+']=0;\n')
			f.write('	'+'info_p['+str(i_b-brange[0])+']=0;\n')
			f.write('	'+'addr_aux_p['+str(i_b-brange[0])+']=0;\n')
			f.write('end\n')
		
		f.write('addr_out=')
		for i_b in range(blen):
			f.write('addr_p['+str(i_b)+']')
			if i_b==blen-1:
				f.write(';\n')
			else:
				f.write('|')
		f.write('info=')
		for i_b in range(blen):
			f.write('info_p['+str(i_b)+']')
			if i_b==blen-1:
				f.write(';\n')
			else:
				f.write('|')
		f.write('addr_aux=')
		for i_b in range(blen):
			f.write('addr_aux_p['+str(i_b)+']')
			if i_b==blen-1:
				f.write(';\n')
			else:
				f.write('|')	
		
		f.write('end\n')#end en
		#f.write('else begin\n')
		#f.write('addr_out=addr_out;\n')
		#f.write('info=info;\n')
		#f.write('addr_aux=addr_aux;\n')
		#f.write('end\n')
		f.write('end\n')#end always
		f.write('endmodule\n')
	
	f.close()
	return 0

def enum(length):
	results=[]
	for l in range(length):
		r=[]
		for i in range(2**(l+1)):
			r.append([(i>>j)%2 for j in range(l+1)])
		results.append(r)
	return results


def how_many_ind(asm):
	bound=asm[0]['bound']
	#print bound,len(asm[0]['func_entry'])
	for a in asm:
		print a
		unfix=0
		source=[]
		target_cand=[]
		for b in a['branch']:
			if b['ind']:
				source.append(b['bs'])
				unfix+=1
		is_addr=0
		if unfix>1:
			for c in a['comment']:
				if c>=bound[0] and c<=bound[1] and c in asm[0]['func_entry']:
					is_addr=1
					target_cand.append(c)
		if is_addr:
			print '==============='
			print unfix,a['func'],source,target_cand,a['valid_fix_target']

if __name__=="__main__":
	if(sys.argv[1]=='extract'):
		f=open(sys.argv[2],'r')
		text=[]
		for line in f:
			text.append(line[0:-1])
		f.close()
		asm=get_info(text)
		out_asm(asm,'raw')
		out_funcs(asm,'out_funcs')
	elif(sys.argv[1]=='gencase'):
		f=open(sys.argv[2],'r')
		text=[]
		for line in f:
			text.append(line[0:-1])
		f.close()
		funcs=[]
		
		for string in text:
			temp=re.findall("\S+",string)
			if len(temp)>0:
				funcs.append(temp[0])
		
		f=open('funcs_sys','r')
		text=[]
		for line in f:
			text.append(line[0:-1])
		f.close()
		sysfuncs=[]
		
		for string in text:
			temp=re.findall("\S+",string)
			if len(temp)>0:
				sysfuncs.append(temp[0])
		
		exsys=0
		exclude=0
		addrrange=[0,0xffffffff]
		num_random=0
		name=''
		split=100
		empty=0
		auto_fix_ind=0
		
		argp=[]
		for i in range(3,len(sys.argv)):
			if sys.argv[i][0]=='-':
				argp.append(i)
		
		for i in argp:
			if sys.argv[i]=='-r':
				addrrange=[int(sys.argv[i+1],16),int(sys.argv[i+2],16)]
			elif sys.argv[i]=='-f':
				funcs=funcs[int(sys.argv[i+1]):int(sys.argv[i+2])]
			elif sys.argv[i]=='-e':
				exclude=1
			elif sys.argv[i]=='-a':
				funcs=[]
			elif sys.argv[i]=='-nosys':
				exsys=1
			elif sys.argv[i]=='-random':
				num_random=int(sys.argv[i+1])
				select=range(len(funcs))
				random.shuffle(select)
				select=select[:num_random]
				select.sort()
				funcs=[funcs[n] for n in select]
			elif sys.argv[i]=='-name':
				name=sys.argv[i+1]
			elif sys.argv[i]=='-s':
				split=int(sys.argv[i+1])
			elif sys.argv[i]=='-empty':
				empty=1
			elif sys.argv[i]=='-auto_fixind':
				auto_fix_ind=1
		
		asm=in_asm('raw',funcs,exclude,sysfuncs,exsys)
		print asm[1]
		print 'extract asm complete'
		blocks=asm2blocks(asm,addrrange,auto_fix_ind)
		if empty:
			blocks=blocks[0:1]
		print blocks[0]
		print 'block number:',len(blocks)
		gen_comb(blocks,'CFI_kernel'+name+'.v',split)
	
	
