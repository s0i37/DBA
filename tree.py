#!/usr/bin/python
from sys import argv
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

execs = 0
threads = {}
with open(trace_file) as f:
	for line in f:
		inst = None
		try:
			execs += 1
			eip_thr, opcodes, REGS = line.split()
			eip = int( eip_thr[:10], 16 )
			thr = int( eip_thr[11:] )
			opcodes = opcodes[1:-1]
			if eip >= 0x80000000:
				continue
			for inst in md.disasm( opcodes.decode('hex'), eip ):
				break
		except Exception as e:
			continue

		if not inst:
			continue
		if not thr in threads.keys():
			threads[thr] = { 'called': None, 'deep': 0, 'args': [] }
		
		if not threads[thr]['called']:
			( threads[thr]['called'], args_count ) = get_symbol(eip)
			if not threads[thr]['called']:
				threads[thr]['called'] = "0x%08x"%eip
			print "%d:%d" % (threads[thr]['deep'], thr) + " "*threads[thr]['deep'] + threads[thr]['called'] + '(' + ','.join( threads[thr]['args'][1:args_count] ) + ')'

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
