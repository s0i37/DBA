#!/usr/bin/python
from sys import argv
from os import path
from capstone import *
import sqlite3

if len(argv) < 2:
	print "%s trace.txt [symbols.db]" % argv[0]
	exit()

def try_ascii(hexstr):
	out = ''
	for i in xrange(0,len(hexstr),2):
		byte = int( '0x'+hexstr[i:i+2], 16 )
		if 0x20 <= byte <= 0x7f:
			out += chr(byte)
		else:
			out += '.'
	return out

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True
trace_file = argv[1]
modules = {}
functions = {}

symbols = {}

if len(argv) > 2:
	symbols_db = argv[2]
	db = sqlite3.connect(symbols_db)
	sql = db.cursor()

	for symbol,start,end,args in sql.execute("select symbol,start,end,args from symbols"):
		symbols[symbol] = (
			[ int(start), int(end) ],
			args
		)
	db.close()

def get_symbol(eip):
	for symbol in symbols.keys():
		(bounds,args) = symbols[symbol]
		if bounds[0] <= eip <= bounds[1]:
			return symbol,args
	return (None,0)

def get_relative(addr):
	for module_name,module_range in modules.items():
		low,high = module_range
		if low <= addr <= high:
			return module_name, addr - low
	return (None,0)

def get_func_name(addr):
	for func_addr,func_name in functions.items():
		if func_addr == addr:
			return func_name

def meta(line):
	if line.startswith('[*] module'):
		_, _, low, high, module = line.split()
		low = int(low, 16)
		high = int(high, 16)
		modules[ path.basename(module) ] = (low, high)

	elif line.startswith('[*] function'):
		_, _, func, addr = line.split()
		addr = int(addr, 16)
		functions[addr] = func

execs = 0
threads = {}
with open(trace_file) as f:
	for line in f:
		inst = None
		if line.startswith('['):
			meta(line)
			continue
		if line.find('{') == -1:
			continue
		try:
			execs += 1
			count_eip_thr, opcodes, REGS = line.split()
			count,eip,thr = count_eip_thr.split(':')
			eip = int(eip, 16)
			thr = int(thr, 16)
			opcodes = opcodes[1:-1]
			#if eip >= 0x80000000:
			#	continue
			for inst in md.disasm( opcodes.decode('hex'), eip ):
				break
		except Exception as e:
			#print line
			pass

		if not inst:
			continue
		if not thr in threads.keys():
			threads[thr] = { 'called': None, 'deep': 0, 'args': [] }
		
		if not threads[thr]['called']:
			( threads[thr]['called'], args_count ) = get_symbol(eip)
			if not threads[thr]['called']:
				threads[thr]['called'] = eip

			addr = threads[thr]['called']
			func_name = get_func_name(addr)
			if func_name:
				func = func_name
			else:
				module,addr = get_relative(addr)
				if module:
					func = "%s+0x%x" % (module, addr)
				else:
					func = "0x%x" % threads[thr]['called']
			print "%d:%d" % (threads[thr]['deep'], thr) + " "*threads[thr]['deep'] + func + '(' + ','.join( threads[thr]['args'][1:args_count] ) + ')'

		if inst.mnemonic == 'call':
			threads[thr]['called'] = None
			threads[thr]['deep'] += 1
		elif inst.mnemonic == 'ret':
			if threads[thr]['deep'] > 0:
				threads[thr]['deep'] -= 1
		elif inst.mnemonic == 'push':
			threads[thr]['args'].append(inst.op_str)
		elif inst.mnemonic == 'pop':
			if threads[thr]['args']:
				threads[thr]['args'].pop()
