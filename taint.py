#!/usr/bin/python2
from lib.emulate import Trace, CPU
import argparse
import colorama
import json
from os import path


class Thread:
	def __init__(self):
		self.tainted_registers = set()
		self.tainted_offset = {}

threads = {}
tainted_memory = set()
tainted_data = {}
settings = {}


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


def on_found_string(string_ptr, thread_id):
	global settings, tainted_data
	i = 0
	for ptr in xrange(string_ptr, string_ptr+len(settings['taint_data'])):
		if not settings['taint_size'] or settings['taint_offset'] <= i < settings['taint_offset'] + settings['taint_size']:
			taint_memory(thread_id, ptr)
			tainted_data[ptr] = i
		i += 1
	if settings['verbose']:
		print colorama.Fore.YELLOW + "[+] found tainted data in 0x%08x: %s" % (string_ptr, settings['taint_data']) + colorama.Fore.RESET


def is_tainted_reg(thread_id, reg):
	global tainted_registers
	for tainted_register in threads[thread_id].tainted_registers:
		if reg in CPU.get_sub_registers(tainted_register):
			return True
	return False

def untaint_reg(thread_id, reg):
	global tainted_registers
	if reg in CPU.get_sub_registers(reg):
		threads[thread_id].tainted_registers.remove(reg)

def taint_reg(thread_id, reg):
	global tainted_registers
	threads[thread_id].tainted_registers.add(reg)

def is_tainted_memory(thread_id, addr):
	global tainted_memory, tainted_data, threads
	is_taint = addr in tainted_memory
	if is_taint:
		threads[thread_id].tainted_offset = tainted_data.get(addr)
	return is_taint

def untaint_memory(addr):
	global tainted_memory
	tainted_memory.remove(addr)

def taint_memory(thread_id, addr):
	global tainted_memory, tainted_data, threads
	tainted_memory.add(addr)
	if threads[thread_id].tainted_offset:
		tainted_data[addr] = threads[thread_id].tainted_offset


def taint(thread_id, used_registers, used_memory, memory, mnem):
	global threads, settings
	tainted_regs = set()
	tainted_mems = set()
	spread_regs = set()
	spread_mems = set()

	used_regs_r, used_regs_w = used_registers
	used_mems_r, used_mems_w = used_memory
	is_spread = False

	try:	threads[thread_id]
	except:	threads[thread_id] = Thread()

	if settings['taint_data']:
		for used_memory_cell in used_mems_r:
			string_ptr = find_string(memory, used_memory_cell, settings['taint_data'])
			if string_ptr:
				for callback in settings['on_found_string']:
					callback(string_ptr, thread_id)

	for used_reg in used_regs_r:
		if used_reg and is_tainted_reg(thread_id, used_reg):
			is_spread = True
			tainted_regs.add(used_reg)
			if settings['verbose']:
				print colorama.Fore.YELLOW + "[+] using tainted register: %s" % (used_reg,) + colorama.Fore.RESET

	for used_memory_cell in used_mems_r:
		if is_tainted_memory(thread_id, used_memory_cell):
			is_spread = True
			tainted_mems.add(used_memory_cell)
			if settings['verbose']:
				print str(used_memory)
				print colorama.Fore.YELLOW + "[+] using tainted memory: 0x%08x" % (used_memory_cell,) + colorama.Fore.RESET

	if is_spread:
		for used_reg in used_regs_w:
			if used_reg:

				if mnem.split()[0] in ('push','pop'):
					if used_reg in ('rsp','esp'):
						continue
				elif mnem.split()[0] in ('rep', 'repne'):
					if used_reg in ('rcx','rsi','rdi','ecx','esi','edi'):
						continue

				if settings['verbose']:
					print colorama.Fore.YELLOW + "[+] tainting register %s" % (used_reg,) + colorama.Fore.RESET
				taint_reg(thread_id, used_reg)
				spread_regs.add(used_reg)
		for used_memory_cell in used_mems_w:
			if settings['verbose']:
				print colorama.Fore.YELLOW + "[+] tainting memory 0x%08x" % (used_memory_cell,) + colorama.Fore.RESET
			taint_memory(thread_id, used_memory_cell)
			spread_mems.add(used_memory_cell)
	else:
		for used_reg in used_regs_w:
			if is_tainted_reg(thread_id, used_reg):
				untaint_reg(thread_id, used_reg)
		for used_memory_cell in used_mems_w:
			if is_tainted_memory(thread_id, used_memory_cell):
				if settings['verbose']:
					print colorama.Fore.YELLOW + "[-] release memory 0x%08x" % (used_memory_cell,) + colorama.Fore.RESET
				untaint_memory(used_memory_cell)

	return (tainted_regs, tainted_mems, spread_regs, spread_mems)


def init(taint_mem, taint_reg):
	global settings
	if taint_mem:
		option_value = taint_mem.split(':')
		if len(option_value) == 3:
			(from_takt,taint_addr,taint_size) = option_value
			settings['from_takt'] = int(from_takt)
		else:
			(taint_addr,taint_size) = option_value
		taint_addr = int(taint_addr,16)
		taint_size = int(taint_size)
		for addr in xrange(taint_addr, taint_addr+taint_size):
			print colorama.Fore.LIGHTBLACK_EX + "[*] tainting memory: 0x%08x" % addr + colorama.Fore.RESET
			tainted_memory.add(addr)

	if taint_reg:
		(from_takt,reg) = taint_reg.split(':')
		settings['from_takt'] = int(from_takt)
		print colorama.Fore.LIGHTBLACK_EX + "[*] tainting register: %s" % reg.upper() + colorama.Fore.RESET
		taint_reg(reg.lower())

	if settings['taint_data']:
		settings['on_found_string'] = [on_found_string]

def analyze(trace):
	global settings
	taint_no = 0
	
	if settings['symbols'] and path.isfile(settings['symbols']):
		with open(settings['symbols']) as s:
			for symbol in json.loads( s.read() ):
				trace.symbols[symbol['name']] = [symbol['offset'], symbol['offset']+symbol['size']]
	while True:
		info = trace.instruction() # 5 time faster, but no trace.cpu.REG_after value
		#info = trace.execute() # more right way, but more slower
		if not info:
			continue
		
		if settings['module'] and (not settings['from_addr'] and not settings['to_addr']) and settings['module'] in trace.modules.keys():
			(settings['from_addr'],settings['to_addr']) = trace.modules[ settings['module'] ]

		(used_registers, used_memory) = info
		if settings['from_takt'] <= trace.cpu.takt:
			(tainted_regs, tainted_mems, spread_regs, spread_mems) = taint(trace.cpu.thread_id, used_registers, used_memory, trace.io.ram, trace.cpu.disas())
			if tainted_regs or tainted_mems:
				if (settings['from_addr'] == 0 and settings['to_addr'] == 0) or settings['from_addr'] <= trace.cpu.eip_before <= settings['to_addr']:
					taint_no += 1
					if settings['limit'] == 0 or settings['limit'] >= taint_no:
						yield (tainted_regs, tainted_mems, spread_regs, spread_mems)
					else:
						break
		
		if settings['to_takt'] and trace.cpu.takt >= settings['to_takt']:
			break


def highlight(haystack, needle):
	return haystack.replace( "%x"%needle, colorama.Back.GREEN + colorama.Fore.BLACK + "%x"%needle + colorama.Back.RESET + colorama.Fore.GREEN, 1 )


if __name__ == '__main__':
	parser = argparse.ArgumentParser( description='data flow analisys tool' )
	parser.add_argument("tracefile", type=str, help="trace.log")
	parser.add_argument("-symbols", type=str, default='', help="symbols.json")
	parser.add_argument("-taint_mem", type=str, default='', help="taint [takt:]address:size (1200:0x402000:10)")
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
	
	settings = vars(args)
	init(args.taint_mem, args.taint_reg)
	trace = Trace( open(args.tracefile) )
	taint_no = 0
	for access in analyze(trace):
		taint_no += 1
		symbol = get_symbol(trace)
		if symbol:
			print colorama.Fore.LIGHTYELLOW_EX + "[+] %d:%d:%s: %s;" % (taint_no, trace.cpu.takt, symbol, trace.cpu.instruction) + colorama.Fore.GREEN,
		else:
			print colorama.Fore.LIGHTYELLOW_EX + "[+] %d:%d:0x%08x: %s;" % (taint_no, trace.cpu.takt, trace.cpu.eip_before, trace.cpu.instruction) + colorama.Fore.GREEN,
		(tainted_regs, tainted_mems, spread_regs, spread_mems) = access
		for tainted_reg in tainted_regs:
			full_tainted_reg = CPU.get_full_register(tainted_reg)
			print highlight( " %s=0x%08x," % ( full_tainted_reg.upper(), trace.cpu[full_tainted_reg] ), trace.cpu[tainted_reg]),
		mem_shown = 0
		tainted_bytes = []
		for tainted_mem in tainted_mems:
			if mem_shown + 0 < tainted_mem:
				print " 0x%08x -> %02X," % ( tainted_mem, trace.io.ram.get_byte(tainted_mem) ),
				mem_shown = tainted_mem
			tainted_bytes.append(tainted_data[tainted_mem])
		if tainted_bytes:
			print colorama.Fore.YELLOW + " " + str(tainted_bytes),
		else:
			print colorama.Fore.YELLOW + " " + str(threads[trace.cpu.thread_id].tainted_offset),
		print colorama.Fore.RESET
