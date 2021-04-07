import sys
import re
import copy
import math
import random

"""
Needed to be fixed:
Some functions have no regular function return, but just a direct branch to somewhere else at the end of the 
funcion. But this kind of functions will usually not be called.
"""

atom_enum=[[[0], [1]], [[0, 0], [1, 0], [0, 1], [1, 1]], [[0, 0, 0], [1, 0, 0], [0, 1, 0], [1, 1, 0], [0, 0, 1], [1, 0, 1], [0, 1, 1], [1, 1, 1]], [[0, 0, 0, 0], [1, 0, 0, 0], [0, 1, 0, 0], [1, 1, 0, 0], [0, 0, 1, 0], [1, 0, 1, 0], [0, 1, 1, 0], [1, 1, 1, 0], [0, 0, 0, 1], [1, 0, 0, 1], [0, 1, 0, 1], [1, 1, 0, 1], [0, 0, 1, 1], [1, 0, 1, 1], [0, 1, 1, 1], [1, 1, 1, 1]], [[0, 0, 0, 0, 0], [1, 0, 0, 0, 0], [0, 1, 0, 0, 0], [1, 1, 0, 0, 0], [0, 0, 1, 0, 0], [1, 0, 1, 0, 0], [0, 1, 1, 0, 0], [1, 1, 1, 0, 0], [0, 0, 0, 1, 0], [1, 0, 0, 1, 0], [0, 1, 0, 1, 0], [1, 1, 0, 1, 0], [0, 0, 1, 1, 0], [1, 0, 1, 1, 0], [0, 1, 1, 1, 0], [1, 1, 1, 1, 0], [0, 0, 0, 0, 1], [1, 0, 0, 0, 1], [0, 1, 0, 0, 1], [1, 1, 0, 0, 1], [0, 0, 1, 0, 1], [1, 0, 1, 0, 1], [0, 1, 1, 0, 1], [1, 1, 1, 0, 1], [0, 0, 0, 1, 1], [1, 0, 0, 1, 1], [0, 1, 0, 1, 1], [1, 1, 0, 1, 1], [0, 0, 1, 1, 1], [1, 0, 1, 1, 1], [0, 1, 1, 1, 1], [1, 1, 1, 1, 1]]]

cond=['EQ','NE','CS','HS','CC','LO','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE']
condexplist=['eq','ne','cs','hs','cc','lo','mi','pl','vs','vc','hi','ls','ge','lt','gt','le']
condexp='eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le'

atom_size=5

all_inst_count=0
all_dbranch_count=0
all_indbranch_count=0

def get_info(text):
	global all_inst_count
	global all_dbranch_count
	global all_indbranch_count
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
					#print temp
					asm[-1]['branch'].append(temp)
					bsadd=[]
					if temp['ind']:
						all_indbranch_count+=1
					else:
						all_dbranch_count+=1
				all_inst_count+=1
	print 'direct branch ratio:',float(all_dbranch_count)/all_inst_count*100,'%'
	print 'indirect branch ratio:',float(all_indbranch_count)/all_inst_count*100,'%'
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
					print len(asm[i_a+1]['branch'])
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

def find_able_to_ind_fcall(blocks):
	#this function will find which indirect blocks that each block can go to
	#if there is a function call on the path to an indirect block I for one block B (including this function call), B has no "toind" to I
	flag=[0 for i in range(len(blocks))]
	#after this part, all the indirect block will be marked ind=1, and toind=itself. all the function call will be marked fcall=1, and tofs=itself
	for i_b in range(len(blocks)):
		if blocks[i_b]['ind']:
			blocks[i_b]['toind']=[i_b]
		else:
			blocks[i_b]['toind']=[]
		"""
		blocks[i_b]['tofs']=[]#should be called ['tofcall']
		blocks[i_b]['fcall']=0
		for p in blocks[i_b]['dpos']:
			if p>=0 and blocks[p]['fs']:
				blocks[i_b]['fcall']=1
				blocks[i_b]['tofs']=[i_b]
				break
		"""
	for i_b in range(len(blocks)):
		if blocks[i_b]['ind']==0:# and blocks[i_b]['fcall']==0:
			find_ind_fcall(i_b,blocks[i_b]['func'],blocks,flag)
	
	for i_b in range(len(blocks)):
		if -1 in blocks[i_b]['toind']:
			blocks[i_b]['toind']=[]
	#	if -1 in blocks[i_b]['tofs']:
	#		blocks[i_b]['tofs']=[]

def find_ind_fcall(pos,funcname,blocks,flag):
	if flag[pos]:#has been processed
		return
	else:
		flag[pos]=1
		if blocks[pos]['ind']:# or blocks[pos]['fcall']:
			return
		for d in blocks[pos]['dpos']:
			if d>=0:
				if blocks[d]['func']!=funcname:#not in the same function
					blocks[pos]['toind']=[-1]
					break
				else:
					find_ind_fcall(d,funcname,blocks,flag)
					#print len(blocks[d]['toind'])
					blocks[pos]['toind'].extend(blocks[d]['toind'])
					blocks[pos]['toind']=list(set(blocks[pos]['toind']))
					#blocks[pos]['tofs'].extend(blocks[d]['tofs'])
					#blocks[pos]['tofs']=list(set(blocks[pos]['tofs']))
			#else:#if there is uncertain destination, be reservative
			#	blocks[pos]['toind']=[-1]
			#	blocks[pos]['tofs']=[-1]
			#	break
				

def get_opt_blocks(blocks):
	for i_b in range(len(blocks)):
		if blocks[i_b]['ind']:# or blocks[i_b]['fcall']:
			blocks[i_b]['optset']=[i_b]
	count=0
	for i_b in range(len(blocks)):
		if blocks[i_b]['ind']:# or blocks[i_b]['fcall']:
			count+=1
			#print i_b,count
			flag=[0 for i in range(len(blocks))]
			get_valid_blocks(i_b,i_b,blocks,flag)
	#now create new opt blocks
	optblocks=[]
	flag=[0 for i in range(len(blocks))]
	for i_b in range(len(blocks)):
		b=blocks[i_b]
		if b['ind']:# or b['fcall']:
			for opt in b['optset']:
				flag[opt]=1
			optblocks.append({'rootpos':i_b,'oripos':b['optset'],'addrs':[],'d':b['d'],'oridpos':b['dpos'],'fix':b['fix'],'ind':1})
	for i_b in range(len(blocks)):
		if flag[i_b]==0:
			optblocks.append({'rootpos':i_b,'oripos':[i_b],'addrs':[],'d':b['d'],'oridpos':b['dpos'],'fix':b['fix'],'ind':0})
	#merge address
	for ob in optblocks:
		ob['oripos'].sort()
		if len(ob['oripos'])==1:
			ob['addrs'].append([blocks[ob['oripos'][0]]['bs'],blocks[ob['oripos'][0]]['be']])
		else:
			now=ob['oripos'][0]
			nowaddr=[blocks[ob['oripos'][0]]['bs'],blocks[ob['oripos'][0]]['be']]
			addr=[blocks[ob['oripos'][0]]['bs'],blocks[ob['oripos'][0]]['be']]
			for i_ob in range(1,len(ob['oripos'])):
				if ob['oripos'][i_ob]==now+1 and blocks[ob['oripos'][i_ob]]['bs']<=nowaddr[1]+4:
					addr[1]=blocks[ob['oripos'][i_ob]]['be']
				else:
					ob['addrs'].append(addr)
					addr=[blocks[ob['oripos'][i_ob]]['bs'],blocks[ob['oripos'][i_ob]]['be']]
				now=ob['oripos'][i_ob]
				nowaddr=[blocks[ob['oripos'][i_ob]]['bs'],blocks[ob['oripos'][i_ob]]['be']]
			ob['addrs'].append(addr)
	#find function start and function end
	i=0
	for ob in optblocks:
		optblocks[i]['fs']=0
		optblocks[i]['fe']=0
		optblocks[i]['fsoripos']=-1
		optblocks[i]['feoripos']=-1
		counts=0
		counte=0
		for orp in ob['oripos']:
			if blocks[orp]['fs']:
				optblocks[i]['fsoripos']=orp
				counts+=1
			if blocks[orp]['fe']:
				optblocks[i]['feoripos']=orp
				counte+=1
		if counts>1:
			"""
			print '=============='
			for orp in ob['oripos']:
				if blocks[orp]['fs']:
					print blocks[orp]
			"""
			print 'ERROR, more than 1 function entry'
		elif counts==1:
			optblocks[i]['fs']=1
		if counte>1:
			"""
			print '=============='
			for orp in ob['oripos']:
				if blocks[orp]['fe']:
					print blocks[orp]
			"""
			print 'ERROR, more than 1 function end'
		elif counte==1:
			optblocks[i]['fe']=1
		i+=1
	#sanity check
	for ob in optblocks:
		funcname=[]
		for orp in ob['oripos']:
			if funcname==[]:
				funcname=blocks[orp]['func']
			else:
				if funcname!=blocks[orp]['func']:
					print 'ERROR, blocks not from the same function'
		
	return optblocks

def get_valid_blocks(pos,sppos,blocks,flag):
	#given a indirect block, find the valid direct block of it
	#valid direct block: only has pathes to this indirect block but not other indirect blocks
	if flag[pos]:
		return
	else:
		flag[pos]=1
		valid=1
		for toind in blocks[pos]['toind']:
			if toind!=sppos:
				valid=0
				break
		"""
		if valid:
			for tofs in blocks[pos]['tofs']:
				if tofs!=sppos:
					valid=0
					break
		"""
		if len(blocks[pos]['toind'])==0:
			valid=0
		if blocks[pos]['fs']:#function start should be a signal node
			valid=0
		if valid==0:
			return
		else:
			blocks[sppos]['optset'].append(pos)
			blocks[sppos]['optset']=list(set(blocks[sppos]['optset']))
		for s in blocks[pos]['spos']:
			get_valid_blocks(s,sppos,blocks,flag)

def gen_comb_opt(filename,optblocks,blocks,split):
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
	
	for b in optblocks:
		for addr in b['addrs']:
			if addr[1]-addr[0]>max_block_len:
				max_block_len=addr[1]-addr[0]
	
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
	
	num=math.ceil(float(len(optblocks))/split)
	parts=[(i+1)*split for i in range(int(num-1))]
	parts.append(len(optblocks))
	
	f=open(filename,'wb')
	
	f.write('module CFI_kernel(clk,en,init_addr,check_addr,atom,addr,addr_aux,info,probe);\n')
	f.write('parameter nodes='+str(len(optblocks))+';\n')
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
		f.write('input[31:0] check_addr/*synthesis keep*/;\n')
		f.write('input[1:0] atom/*synthesis keep*/;\n')
		
		f.write('reg[31:0] addr_p['+str(blen-1)+':0];\n')
		f.write('reg[4:0] info_p['+str(blen-1)+':0];\n')
		f.write('reg[func_bits+block_bits+32-1:0] addr_aux_p['+str(blen-1)+':0];\n')
		
		f.write('always@(en,addr,check_addr,atom)begin\n')
		f.write('if(en)begin\n')
		for i_b in range(brange[0],brange[1]):
			f.write('if(')
			for i_a in range(len(optblocks[i_b]['addrs'])):
				addr=optblocks[i_b]['addrs'][i_a]
				f.write('addr>=32\'h'+hex(addr[0])[2:]+'&&addr<=32\'h'+hex(addr[1])[2:])
				if i_a==len(optblocks[i_b]['addrs'])-1:
					f.write(')begin\n')
				else:
					f.write('||')
			
			startaddr=-1
			if optblocks[i_b]['fs']:
				startaddr=blocks[optblocks[i_b]['fsoripos']]['bs']
			else:
				startaddr=blocks[optblocks[i_b]['oripos'][0]]['bs']
				for op in optblocks[i_b]['oripos']:
					if blocks[op]['bs']<startaddr:
						startaddr=blocks[op]['bs']
			
			if optblocks[i_b]['rootpos']!=len(blocks)-1 and blocks[optblocks[i_b]['rootpos']]['fe']==0:
				blocklen=blocks[optblocks[i_b]['rootpos']+1]['bs']-startaddr
			else:
				blocklen=blocks[optblocks[i_b]['rootpos']]['be']-startaddr
			
			funclen=-1
			until_end=0
			if optblocks[i_b]['fs']:
				i_fs=optblocks[i_b]['fsoripos']
				func=blocks[i_fs]['func']
				for i_b2 in range(i_fs,len(blocks)):
					if blocks[i_b2]['func']==func:
						if blocks[i_b2]['fe']:
							funclen=blocks[i_b2]['be']-blocks[i_fs]['bs']
							break
						elif i_b2==len(blocks)-1:
							until_end=1
					else:
						break
			if until_end:
				funclen=blocks[-1]['be']-blocks[i_b]['bs']
			if funclen>=0:
				#now[31:0] is the least addr(if not function start)/function start in all original blocks, [blocklen+31:31] is the length from the [31:0] addr to the next block(after root block)'s start
				f.write('	'+'addr_aux_p['+str(i_b-brange[0])+']=('+str(funclen)+'<<(32+block_bits))|('+str(blocklen)+'<<32)|32\'h'+hex(startaddr)[2:]+';\n')
			else:
				f.write('	'+'addr_aux_p['+str(i_b-brange[0])+']=('+str(blocklen)+'<<32)|32\'h'+hex(startaddr)[2:]+';\n')
			
			f.write('	'+'info_p['+str(i_b-brange[0])+'][4]=1;\n')
			if optblocks[i_b]['fs'] and optblocks[i_b]['fe']==0:
				f.write('	'+'info_p['+str(i_b-brange[0])+'][1:0]=1;\n')
			elif optblocks[i_b]['fs']==0 and optblocks[i_b]['fe']:
				if optblocks[i_b]['ind']:
					f.write('	'+'info_p['+str(i_b-brange[0])+'][1:0]=2;\n')
				else:
					f.write('	'+'info_p['+str(i_b-brange[0])+'][1:0]=0;\n')
			elif optblocks[i_b]['fs'] and optblocks[i_b]['fe']:
				f.write('	'+'info_p['+str(i_b-brange[0])+'][1:0]=3;\n')
			else:
				f.write('	'+'info_p['+str(i_b-brange[0])+'][1:0]=0;\n')
			if optblocks[i_b]['ind']==0:#this is a direct branch, only consider atom
				f.write('	'+'if(atom==0)begin\n')
				f.write('	'*2+'addr_p['+str(i_b-brange[0])+']=32\'h'+hex(blocks[optblocks[i_b]['rootpos']]['d'][0])[2:]+';\n')
				f.write('	'*2+'info_p['+str(i_b-brange[0])+'][3:2]=0;\n')
				f.write('	'+'end\n')
				if blocks[optblocks[i_b]['rootpos']]['fix']==0 and len(blocks[optblocks[i_b]['rootpos']]['dpos'])>1:
					f.write('	'+'else if(atom==1)begin\n')
					f.write('	'*2+'addr_p['+str(i_b-brange[0])+']=32\'h'+hex(blocks[optblocks[i_b]['rootpos']]['d'][1])[2:]+';\n')
					f.write('	'*2+'info_p['+str(i_b-brange[0])+'][3:2]=0;\n')
					f.write('	'+'end\n')
				f.write('	'+'else begin\n')
				f.write('	'*2+'addr_p['+str(i_b-brange[0])+']=0;\n')
				f.write('	'*2+'info_p['+str(i_b-brange[0])+'][3:2]=0;\n')#direct branch cannot be attacked, if atom input is wrong, it maybe another program. we just ignore
				#f.write('	'*2+'info_p['+str(i_b-brange[0])+'][3:2]=2;\n')
				f.write('	'+'end\n')
			else:#this is an indirect branch, only consider check_addr
				#f.write('	'+'addr_p['+str(i_b-brange[0])+']=check_addr;\n')
				once=0
				lend=0
				if blocks[optblocks[i_b]['rootpos']]['fix']:#no condition code
					lend=len(blocks[optblocks[i_b]['rootpos']]['d'])
				else:#may have "1" atom
					lend=len(blocks[optblocks[i_b]['rootpos']]['d'])-1
					f.write('	'+'if(atom==1)begin\n')
					f.write('	'*2+'addr_p['+str(i_b-brange[0])+']=32\'h'+hex(blocks[optblocks[i_b]['rootpos']]['d'][-1])[2:]+';\n')
					f.write('	'*2+'info_p['+str(i_b-brange[0])+'][3:2]=0;\n')
					f.write('	'+'end\n')
					once+=1
				if once>0:
					f.write('	'+'else ')
				else:
					f.write('	')
				f.write('if(atom[1]==0)begin\n')
				f.write('	'*2+'addr_p['+str(i_b-brange[0])+']=addr;\n')
				f.write('	'*2+'info_p['+str(i_b-brange[0])+'][3:2]=0;\n')
				f.write('	'+'end\n')
				once+=1
				for i_d in range(lend):
					if blocks[optblocks[i_b]['rootpos']]['d'][i_d]!='NA':
						#if blocks[optblocks[i_b]['rootpos']]['ind']!=1:
						#	print "error"
						#	print blocks[optblocks[i_b]['rootpos']]
						if once>0:
							f.write('	'+'else ')
						else:
							f.write('	')
						f.write('if(check_addr==32\'h'+hex(blocks[optblocks[i_b]['rootpos']]['d'][i_d])[2:]+')begin\n')
						f.write('	'*2+'addr_p['+str(i_b-brange[0])+']=check_addr;\n')
						f.write('	'*2+'info_p['+str(i_b-brange[0])+'][3:2]=0;\n')
						f.write('	'+'end\n')
						once+=1
				if once>0:
					f.write('	'+'else begin\n')
				if 'NA' in blocks[optblocks[i_b]['rootpos']]['d']:
					f.write('	'*2+'addr_p['+str(i_b-brange[0])+']=check_addr;\n')
					f.write('	'*2+'info_p['+str(i_b-brange[0])+'][3:2]=1;\n')
				else:
					f.write('	'*2+'addr_p['+str(i_b-brange[0])+']=check_addr;\n')
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
		f.write('end\n')#end always
		f.write('endmodule\n')
	
	f.close()
	"""
	#=============ORIGIN========================
	
	f.write('module CFI_kernel(clk,init_addr,check_addr,atom,last,out,direct,probe);\n')
	f.write('parameter width=8;\n')
	f.write('parameter nodes='+str(len(optblocks))+';\n')
	f.write('input clk;\n')
	f.write('reg[31:0] start;\n')
	f.write('output reg[31:0] last;\n')
	f.write('output reg out,direct;\n')
	f.write('input[31:0] init_addr;\n')
	f.write('input[31:0] check_addr;\n')
	f.write('always@(posedge clk)begin\n')
	f.write('	'+'if(init_addr==0)begin\n')
	f.write('	'*2+'start=last;\n')
	f.write('	'+'end\n')
	f.write('	'+'else begin\n')
	f.write('	'*2+'start=init_addr;\n')
	f.write('	'+'end\n')
	f.write('	'+'last=0;\n')
	f.write('	'+'out=0;\n')
	f.write('	'+'direct=0;\n')
	for ob in optblocks:
		f.write('	'+'if(')
		for i_a in range(len(ob['addrs'])):
			addr=ob['addrs'][i_a]
			f.write('start>=32\'h'+hex(addr[0])[2:]+'&&start<=32\'h'+hex(addr[1])[2:])
			if i_a==len(ob['addrs'])-1:
				f.write(')begin\n')
			else:
				f.write('||')
		
		if ob['ind']:
			f.write('	'*2+'case(check_addr)\n')
			if ob['fix']==0:
				f.write('	'*2+'0: begin\n')
				f.write('	'*3+'if(atom==1)\n')
				f.write('	'*3+'last=32\'h'+hex(ob['d'][-1])[2:]+'\n')
				f.write('	'*2+'end\n')
			for i_d in range(len(ob['d'])):
				d=ob['d'][i_d]
				if d!='NA':
					f.write('	'*2+'32\'h'+hex(d)[2:]+':\n')
					if ob['oridpos'][i_d]>=0:
						f.write('	'*2+'last=32\'h'+hex(d)[2:]+';\n')
					else:
						f.write('	'*2+'out=1;\n')
			if 'NA' in ob['d']:
				f.write('	'*2+'default:\n')
				f.write('	'*2+'out=1;\n')	
			f.write('	'*2+'endcase\n')
		else:
			f.write('	'*2+'direct=1;\n')
			f.write('	'*2+'case(atom)\n')
			f.write('	'*2+'0:\n')
			if ob['oridpos'][0]>=0:
				f.write('	'*2+'last=32\'h'+hex(ob['d'][0])[2:]+';\n')
			else:
				f.write('	'*2+'out=1;\n')
			if ob['fix']==0:
				f.write('	'*2+'1:\n')
				if ob['oridpos'][1]>=0:
					f.write('	'*2+'last=32\'h'+hex(ob['d'][1])[2:]+';\n')
				else:
					f.write('	'*2+'out=1;\n')
				f.write('	'*2+'endcase\n')
		f.write('	'+'end\n')
			
	f.write('end\n')#always end
	f.close()
	"""
	
def gen_comb_opt_backup(filename,optblocks,blocks):
	f=open(filename,'wb')
	
	f.write('module CFI_kernel(clk,init_addr,check_addr,atom,last,out,direct,probe);\n')
	f.write('parameter width=8;\n')
	f.write('parameter nodes='+str(len(optblocks))+';\n')
	f.write('input clk;\n')
	f.write('reg[31:0] start;\n')
	f.write('output reg[31:0] last;\n')
	f.write('output reg out,direct;\n')
	f.write('input[31:0] init_addr;\n')
	f.write('input[31:0] check_addr;\n')
	f.write('always@(posedge clk)begin\n')
	f.write('	'+'if(init_addr==0)begin\n')
	f.write('	'*2+'start=last;\n')
	f.write('	'+'end\n')
	f.write('	'+'else begin\n')
	f.write('	'*2+'start=init_addr;\n')
	f.write('	'+'end\n')
	f.write('	'+'last=0;\n')
	f.write('	'+'out=0;\n')
	f.write('	'+'direct=0;\n')
	for ob in optblocks:
		f.write('	'+'if(')
		for i_a in range(len(ob['addrs'])):
			addr=ob['addrs'][i_a]
			f.write('start>=32\'h'+hex(addr[0])[2:]+'&&start<=32\'h'+hex(addr[1])[2:])
			if i_a==len(ob['addrs'])-1:
				f.write(')begin\n')
			else:
				f.write('||')
		
		if ob['ind']:
			f.write('	'*2+'case(check_addr)\n')
			if ob['fix']==0:
				f.write('	'*2+'0: begin\n')
				f.write('	'*3+'if(atom==1)\n')
				f.write('	'*3+'last=32\'h'+hex(ob['d'][-1])[2:]+'\n')
				f.write('	'*2+'end\n')
			for i_d in range(len(ob['d'])):
				d=ob['d'][i_d]
				if d!='NA':
					f.write('	'*2+'32\'h'+hex(d)[2:]+':\n')
					if ob['oridpos'][i_d]>=0:
						f.write('	'*2+'last=32\'h'+hex(d)[2:]+';\n')
					else:
						f.write('	'*2+'out=1;\n')
			if 'NA' in ob['d']:
				f.write('	'*2+'default:\n')
				f.write('	'*2+'out=1;\n')	
			f.write('	'*2+'endcase\n')
		else:
			f.write('	'*2+'direct=1;\n')
			f.write('	'*2+'case(atom)\n')
			f.write('	'*2+'0:\n')
			if ob['oridpos'][0]>=0:
				f.write('	'*2+'last=32\'h'+hex(ob['d'][0])[2:]+';\n')
			else:
				f.write('	'*2+'out=1;\n')
			if ob['fix']==0:
				f.write('	'*2+'1:\n')
				if ob['oridpos'][1]>=0:
					f.write('	'*2+'last=32\'h'+hex(ob['d'][1])[2:]+';\n')
				else:
					f.write('	'*2+'out=1;\n')
				f.write('	'*2+'endcase\n')
		f.write('	'+'end\n')
			
	f.write('end\n')#always end
	f.close()

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

def check_opt_block_1fs(blocks,optblocks):
	for ob in optblocks:
		count=0
		for orp in ob['oripos']:
			if blocks[orp]['fs']:
				count+=1
		if count>1:
			print 'ERROR, more than 1 function entry'

def disp_block(block):
	i=0
	for b in block:
		print i,b
		i+=1

if __name__=="__main__":
	if(sys.argv[1]=='extract'):
		f=open(sys.argv[2],'r')
		text=[]
		for line in f:
			text.append(line[0:-1])
		f.close()
		asm=get_info(text)
		"""
		for a in asm:
			print '------'
			print a
		"""
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
		debug=0
		
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
				print 'all funcs mode'
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
			elif sys.argv[i]=='-debug':
				debug=1
		#print funcs,addrrange
		
		asm=in_asm('raw',funcs,exclude,sysfuncs,exsys)
		"""
		print '-----------------extracted asm structure-------------'
		for a in asm:
			print a
		"""
		#print asm[1]
		if debug:
			for a in asm:
				print a
		print 'extract asm complete'
		#how_many_ind(asm)
		blocks=asm2blocks(asm,addrrange,auto_fix_ind)
		if empty:
			blocks=blocks[0:1]
		"""
		print '-----------------basic blocks---------------'
		i=0
		for b in blocks:
			print i,b
			i+=1
		print '-----------------basic blocks end---------------'
		"""
		#print blocks[0]
		print 'block number:',len(blocks)
		gen_comb(blocks,'CFI_kernel'+name+'.v',split)
		
		#disp_block(blocks)
		find_able_to_ind_fcall(blocks)
		"""
		i=0
		for b in blocks:
			print i,b
			i+=1
		exit(0)
		"""
		#disp_block(blocks)
		optblocks=get_opt_blocks(blocks)
		print 'optimal block number:',len(optblocks)
		print 'optimized',float(len(blocks)-len(optblocks))*100/len(blocks),'% blocks'
		#disp_block(optblocks)
		"""
		print '-----------------opt blocks---------------'
		i=0
		for b in optblocks:
			print i,b
			i+=1
		print '-----------------opt blocks end---------------'
		"""
		count=0
		for b in blocks:
			if b['ind']:
				count+=1
		print count,len(blocks)
		
		check_opt_block_1fs(blocks,optblocks)
		
		gen_comb_opt('CFI_kernel_opt'+name+'.v',optblocks,blocks,split)
		
	else:
		print 'no'
	
	
