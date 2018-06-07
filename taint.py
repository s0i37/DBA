#!/usr/bin/python
from sanlib.emulate import execute, CPU
import argparse
import colorama

parser = argparse.ArgumentParser( description='data flow analisys tool' )
parser.add_argument("tracefile", type=str, help="trace.txt")
parser.add_argument("symbols", nargs='?', default='', help="symbols.csv")
parser.add_argument("-taint_addr", type=str, default='', help="taint [takt:]address:size (1200:0x402000:10)")
parser.add_argument("-taint_data", type=str, default=0, help="taint data (GET / HTTP/1.1)")
args = parser.parse_args()

tainted_regs = set()
tainted_mems = set()
from_takt = 0

def taint(used_registers, used_memory):
	global tainted_regs, tainted_mems

	used_regs_r, used_regs_w = used_registers
	used_mems_r, used_mems_w = used_memory
	is_spread = False

	for used_reg in used_regs_r:
		used_reg = CPU.get_full_register(used_reg)
		if used_reg and used_reg in tainted_regs:
			is_spread = True
			print colorama.Fore.GREEN + "[+] use tainted register: %s" % (used_reg,) + colorama.Fore.RESET

	for used_memory_cell in used_mems_r:
		if used_memory_cell in tainted_mems:
			is_spread = True
			print colorama.Fore.GREEN + "[+] use tainted memory: 0x%08x" % (used_memory_cell,) + colorama.Fore.RESET

	if is_spread:
		for used_reg in used_regs_w:
			used_reg = CPU.get_full_register(used_reg)
			if used_reg:
				print colorama.Fore.GREEN + "[+] taint register %s" % (used_reg,) + colorama.Fore.RESET
				tainted_regs.add(used_reg)
		for used_memory_cell in used_mems_w:
			print colorama.Fore.GREEN + "[+] taint memory 0x%08x" % (used_memory_cell,) + colorama.Fore.RESET
			tainted_mems.add(used_memory_cell)
	else:
		for used_reg in used_regs_w:
			used_reg = CPU.get_full_register(used_reg)
			if used_reg in tainted_regs:
				tainted_regs.remove(used_reg)
		for used_memory_cell in used_mems_w:
			print colorama.Fore.GREEN + "[-] release memory 0x%08x" % (used_memory_cell,) + colorama.Fore.RESET
			if used_memory_cell in tainted_mems:
				tainted_mems.remove(used_memory_cell)

	return is_spread

if args.taint_addr:
	option_value = args.taint_addr.split(':')
	if len(option_value) == 3:
		(from_takt,taint_addr,taint_size) = option_value
		from_takt = int(from_takt)
	else:
		(taint_addr,taint_size) = option_value
	taint_addr = int(taint_addr,16)
	taint_size = int(taint_size)
	for addr in xrange(taint_addr, taint_addr+taint_size):
		print colorama.Fore.LIGHTBLACK_EX + "[*] tainting memory: 0x%08x" % addr + colorama.Fore.RESET
		tainted_mems.add(addr)

if not tainted_mems and tainted_regs:
	print "[-] no tainted memory or registers"
	exit()

with open(args.tracefile) as trace:
	for line in trace:
		result = execute(line)
		if not result:
			continue
		(cpu, used_registers, used_memory) = result
		if from_takt <= cpu.takt:
			if taint(used_registers, used_memory):
				print colorama.Fore.LIGHTGREEN_EX + "[+] %d:0x%08x: %s" % (cpu.takt, cpu.eip_before, cpu.instruction) + colorama.Fore.RESET