#!/usr/bin/python
from lib.emulate import Trace, CPU
import argparse
import colorama
import json
from os import path

parser = argparse.ArgumentParser( description='data flow analisys tool' )
parser.add_argument("tracefile", type=str, help="trace.txt")
parser.add_argument("-symbols", type=str, default='', help="symbols.json")
parser.add_argument("-taint_addr", type=str, default='', help="taint [takt:]address:size (1200:0x402000:10)")
parser.add_argument("-taint_reg", type=str, default='', help="taint takt:reg (1200:ESI)")
parser.add_argument("-taint_data", type=str, default='', help='taint data: "GET / HTTP/1.1" or input.bin')
parser.add_argument("-taint_offset", type=int, default=0, help="from offset (subdata)")
parser.add_argument("-taint_size", type=int, default=0, help="size bytes (subdata)")
parser.add_argument("-from_addr", type=int, default=0, help="print tainted instruction only from address")
parser.add_argument("-to_addr", type=int, default=0, help="print tainted instruction only to address")
parser.add_argument("-from_takt", type=int, default=0, help="print tainted instruction only after takt")
parser.add_argument("-to_takt", type=int, default=0, help="print tainted instruction only before takt")
parser.add_argument("-module", type=str, default='', help="show tainted instruction just this module")
parser.add_argument("-n", dest= "limit", type=int, default=0, help="count of print tainted instructions")
parser.add_argument("-v", dest="verbose", type=bool, default=False, help="verbose")
args = parser.parse_args()

if path.isfile(args.taint_data):
	with open(args.taint_data) as f:
		args.taint_data = f.read()

tainted_registers = set()
tainted_memory = set()

def get_symbol(trace):
	return False
	for symbol in trace.symbols.keys():
		if trace.symbols[symbol][0] <= trace.cpu.eip_before <= trace.symbols[symbol][1]:
			return "%s+%d" % (symbol, trace.cpu.eip_before-trace.symbols[symbol][0])

def find_string(memory, addr, string):
	was_found = False
	low_boundary_search = addr - len(string)
	i = 0
	while addr >= low_boundary_search:
		for i in xrange( len(string) ):
			value = memory.get_byte(addr + i)
			if value == None:
				return None
			if string.find( chr(value) ) == -1:
				was_found = False
				addr -= 1
				break
			else:
				was_found = True
		if was_found:
			return addr
	return None

def is_tainted_reg(reg):
	global tainted_registers
	for tainted_register in tainted_registers:
		if reg in CPU.get_sub_registers(tainted_register):
			return True
	return False

def untaint_reg(reg):
	global tainted_registers
	if reg in CPU.get_sub_registers(reg):
		tainted_registers.remove(reg)

def taint_reg(reg):
	global tainted_registers
	tainted_registers.add(reg)

def taint(used_registers, used_memory, memory):
	global tainted_registers, tainted_memory, trace
	tainted_regs = set()
	tainted_mems = set()

	used_regs_r, used_regs_w = used_registers
	used_mems_r, used_mems_w = used_memory
	is_spread = False

	if args.taint_data:
		for used_memory_cell in used_mems_r:
			string_ptr = find_string(memory, used_memory_cell, args.taint_data)
			if string_ptr:
				is_spread = True
				i = 0
				for ptr in xrange(string_ptr, string_ptr+len(args.taint_data)):
					if not args.taint_size or args.taint_offset <= i < args.taint_offset + args.taint_size:
						tainted_memory.add(ptr)
					i += 1
				if args.verbose:
					print colorama.Fore.YELLOW + "[+] found tainted data in 0x%08x: %s" % (string_ptr, args.taint_data) + colorama.Fore.RESET

	for used_reg in used_regs_r:
		if used_reg and is_tainted_reg(used_reg):
			is_spread = True
			tainted_regs.add(used_reg)
			if args.verbose:
				print colorama.Fore.YELLOW + "[+] using tainted register: %s" % (used_reg,) + colorama.Fore.RESET

	for used_memory_cell in used_mems_r:
		if used_memory_cell in tainted_memory:
			is_spread = True
			tainted_mems.add(used_memory_cell)
			if args.verbose:
				print colorama.Fore.YELLOW + "[+] using tainted memory: 0x%08x" % (used_memory_cell,) + colorama.Fore.RESET

	if is_spread:
		mnem = trace.cpu.disas()
		for used_reg in used_regs_w:
			if used_reg:

				if mnem.split()[0] in ('push','pop'):
					if used_reg in ('rsp','esp'):
						continue
				elif mnem.split()[0] in ('rep', 'repne'):
					if used_reg in ('rcx','rsi','rdi','ecx','esi','edi'):
						continue

				if args.verbose:
					print colorama.Fore.YELLOW + "[+] tainting register %s" % (used_reg,) + colorama.Fore.RESET
				taint_reg(used_reg)
		for used_memory_cell in used_mems_w:
			if args.verbose:
				print colorama.Fore.YELLOW + "[+] tainting memory 0x%08x" % (used_memory_cell,) + colorama.Fore.RESET
			tainted_memory.add(used_memory_cell)
	else:
		for used_reg in used_regs_w:
			if is_tainted_reg(used_reg):
				untaint_reg(used_reg)
		for used_memory_cell in used_mems_w:
			if used_memory_cell in tainted_memory:
				if args.verbose:
					print colorama.Fore.YELLOW + "[-] release memory 0x%08x" % (used_memory_cell,) + colorama.Fore.RESET
				tainted_memory.remove(used_memory_cell)

	return (tainted_regs, tainted_mems)

if args.taint_addr:
	option_value = args.taint_addr.split(':')
	if len(option_value) == 3:
		(from_takt,taint_addr,taint_size) = option_value
		args.from_takt = int(from_takt)
	else:
		(taint_addr,taint_size) = option_value
	taint_addr = int(taint_addr,16)
	taint_size = int(taint_size)
	for addr in xrange(taint_addr, taint_addr+taint_size):
		print colorama.Fore.LIGHTBLACK_EX + "[*] tainting memory: 0x%08x" % addr + colorama.Fore.RESET
		tainted_memory.add(addr)

if args.taint_reg:
	(from_takt,reg) = args.taint_reg.split(':')
	args.from_takt = int(from_takt)
	print colorama.Fore.LIGHTBLACK_EX + "[*] tainting register: %s" % reg.upper() + colorama.Fore.RESET
	taint_reg(reg.lower())

if not tainted_memory and not tainted_registers:
	print "[-] no tainted memory or registers"
	exit()

taint_no = 0
with Trace( open(args.tracefile) ) as trace:
	if args.symbols and path.isfile(args.symbols):
		with open(args.symbols) as s:
			for symbol in json.loads( s.read() ):
				trace.symbols[symbol['name']] = [symbol['offset'], symbol['offset']+symbol['size']]
	while True:
		info = trace.instruction() # 5 time faster, but no trace.cpu.REG_after value
		#info = trace.execute() # more right way, but more slower
		if not info:
			continue
		
		if args.module and (not args.from_addr and not args.to_addr) and args.module in trace.modules.keys():
			(args.from_addr,args.to_addr) = trace.modules[args.module]

		(used_registers, used_memory) = info
		if args.from_takt <= trace.cpu.takt:
			(tainted_regs, tainted_mems) = taint(used_registers, used_memory, trace.io.ram)
			if tainted_regs or tainted_mems:
				if (args.from_addr == 0 and args.to_addr == 0) or args.from_addr <= trace.cpu.eip_before <= args.to_addr:
					taint_no += 1
					if args.limit == 0 or args.limit >= taint_no:
						symbol = get_symbol(trace)
						if symbol:
							print colorama.Fore.LIGHTYELLOW_EX + "[+] %d:%d:%s: %s;" % (taint_no, trace.cpu.takt, symbol, trace.cpu.instruction) + colorama.Fore.GREEN,
						else:
							print colorama.Fore.LIGHTYELLOW_EX + "[+] %d:%d:0x%08x: %s;" % (taint_no, trace.cpu.takt, trace.cpu.eip_before, trace.cpu.instruction) + colorama.Fore.GREEN,
						for tainted_reg in tainted_regs:
							tainted_reg = CPU.get_full_register(tainted_reg)
							print " %s=0x%08x," % ( tainted_reg.upper(), trace.cpu.get(tainted_reg) ),
						mem_shown = 0
						for tainted_mem in tainted_mems:
							if mem_shown + 4 < tainted_mem:
								print " 0x%08x -> 0x%08x," % ( tainted_mem, trace.io.ram.get_dword(tainted_mem) ),
								mem_shown = tainted_mem
						print colorama.Fore.RESET
					else:
						break
		
		if args.to_takt and trace.cpu.takt >= args.to_takt:
			break
