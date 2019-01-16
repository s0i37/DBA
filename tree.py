#!/usr/bin/python
from sys import argv
from os import path
from capstone import *
import sqlite3

if len(argv) < 2:
	print "%s trace.txt symbols.txt" % argv[0]
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
	with open( argv[2] ) as f:
		for line in f:
			(symbol,start,end) = line.split()
			start = int(start, 16)
			end = int(end, 16)
			symbols[symbol] = ( [start, end], 0 )  # start, end, args_count


def get_symbol(eip):
	for symbol in symbols.keys():
		(ranges,args) = symbols[symbol]
		if ranges[0] <= eip <= ranges[1]:
			return symbol,args
	return (None,0)

def get_relative(addr):
	for module_name,module_range in modules.items():
		start,end = module_range
		if start <= addr <= end:
			return module_name, addr - start
	return (None,0)

def get_func_name(addr):
	for func_addr,func_name in functions.items():
		if func_addr == addr:
			return func_name

def meta(line):
	if line.startswith('[*] module'):
		(_, _, module, start, end)  = line.split()
		start = int(start, 16)
		end = int(end, 16)
		modules[ path.basename(module) ] = (start, end)

	elif line.startswith('[*] function'):
		(_, _, func, start, end) = line.split()
		addr = int(start, 16)
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
			count_eip_thr, opcode, REGS = line.split()
			count,eip,thr = count_eip_thr.split(':')
			eip = int(eip, 16)
			thr = int(thr, 16)
			opcode = opcode[1:-1]
			#if eip >= 0x80000000:
			#	continue
			for inst in md.disasm( opcode.decode('hex'), eip ):
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
#				module,addr = get_relative(addr)
#				if module:
#					func = "%s+0x%x" % (module, addr)
#				else:
				func = "0x%08x" % threads[thr]['called']
			print "%02d:%d:%06d" % (threads[thr]['deep'], thr, execs) + " "*threads[thr]['deep'] + func + '(' + ','.join( threads[thr]['args'][0:args_count] ) + ')'

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
