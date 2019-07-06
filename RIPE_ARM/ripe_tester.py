# Developed by Nick Nikiforakis to assist the automated testing
# using the RIPE evaluation tool
#
# Released under the MIT license (see file named LICENSE)
#
# This program is part the paper titled
# RIPE: Runtime Intrusion Prevention Evaluator 
# Authored by: John Wilander, Nick Nikiforakis, Yves Younan,
#              Mariam Kamkar and Wouter Joosen
# Published in the proceedings of ACSAC 2011, Orlando, Florida
#
# Please cite accordingly.

import os
import sys

code_ptr = ["ret", "baseptr",
 "funcptrstackvar", "funcptrstackparam",
 "funcptrheap", "funcptrbss", "funcptrdata",
"longjmpstackvar", "longjmpstackparam",
"longjmpheap", "longjmpbss", "longjmpdata",  "structfuncptrstack","structfuncptrheap",
                         "structfuncptrdata","structfuncptrbss"] ;

funcs = ["memcpy", "strcpy", "strncpy", "sprintf", "snprintf",
	 "strcat", "strncat", "sscanf", "fscanf", "homebrew"];


locations = ["stack","heap","bss","data"];
attacks = ["createfile", "returnintolibc", "rop"];

techniques = []
repeat_times = 0


if len(sys.argv) < 2:
	print "Usage: python "+sys.argv[0] + "[direct|indirect|both] <number of times to repeat each test>"
	sys.exit(1)

else:
	if sys.argv[1] == "both":
		techniques = ["direct","indirect"];
	else:
		techniques = [sys.argv[1]];

	repeat_times = int(sys.argv[2]);


i = 0
if not os.path.exists("/tmp/rip-eval"):
	os.system("mkdir /tmp/rip-eval");

total_ok=0;
total_fail=0;
total_some=0;
total_np = 0;

recordok=[]
recordfail=[]
recordnp=[]

for attack in attacks:
	for tech in techniques:
		for loc in locations:
			for ptr in code_ptr:
				for func in funcs:
					i = 0
					s_attempts = 0
					attack_possible = 1
					while i < repeat_times:
						i += 1

						os.system("rm /tmp/ripe_log")
						cmdline = "./build/ripe_attack_generator -t "+tech+" -i "+attack+" -c " + ptr + "  -l " + loc +" -f " + func + " > /tmp/ripe_log 2>&1"
						os.system(cmdline)
						log = open("/tmp/ripe_log","r")
		

						if log.read().find("Impossible") != -1:
							print cmdline,"\t\t","NOT POSSIBLE"
							recordnp.append(cmdline)
							attack_possible = 0;
							break;	#Not possible once, not possible always :)


						if os.path.exists("/tmp/rip-eval/f_xxxx"):
							s_attempts += 1		
							os.system("rm /tmp/rip-eval/f_xxxx")


					if attack_possible == 0:
						total_np += 1;
						continue

					if s_attempts == repeat_times:
						print cmdline,"\t\tOK\t", s_attempts,"/",repeat_times
						recordok.append(cmdline)
						total_ok += 1;
					elif s_attempts == 0:
						print cmdline,"\t\tFAIL\t",s_attempts,"/",repeat_times
						recordfail.append(cmdline)
						total_fail += 1;
					else:
						print cmdline,"\t\tSOMETIMES\t", s_attempts,"/",repeat_times
						total_some +=1;
						

total_attacks = total_ok + total_some + total_fail + total_np;
print "\n||Summary|| OK: ",total_ok," ,SOME: ",total_some," ,FAIL: ",total_fail," ,NP: ",total_np," ,Total Attacks: ",total_attacks

f=open('record','wb')
f.write("OK=====================\n")
for i in range(len(recordok)):
	f.write(str(i)+':    '+recordok[i]+'\n')
f.write("FAIL=====================\n")
for i in range(len(recordfail)):
	f.write(str(i)+':    '+recordfail[i]+'\n')
f.write("NP=====================\n")
for i in range(len(recordnp)):
	f.write(str(i)+':    '+recordnp[i]+'\n')
f.close()
						
					



