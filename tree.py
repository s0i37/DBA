#!/usr/bin/python
from sys import argv
from capstone import *
import sqlite3

if len(argv) != 3:
	print "%s trace.txt symbols.db" % argv[0]
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
symbols_db = argv[2]
db = sqlite3.connect(symbols_db)
sql = db.cursor()

symbols = {}
for symbol,start,end,args in sql.execute("select symbol,start,end,args from symbols"):
	symbols[symbol] = (
		[ int(start), int(end) ],
		args
	)

def get_symbol(eip):
	for symbol in symbols.keys():
		(bounds,args) = symbols[symbol]
		if bounds[0] <= eip <= bounds[1]:
			return symbol,args
	return (0,0)

execs = 0
args = []
deep = 0
called = None
with open(trace_file) as f:
	for line in f:
		inst = None
		if line.startswith('x'):
			execs += 1
			_, eip, opcodes, REGS = line.split()
			eip = int( eip[1:11], 16 )
			opcodes = opcodes[1:-1]
			if eip >= 0x80000000:
				continue
			for inst in md.disasm( opcodes.decode('hex'), eip ):
				break

		if not inst:
			continue
		
		if not called:
			(called,args_count) = get_symbol(eip)
			if not called:
				called = "0x%08x"%eip
			print str(deep) + " "*deep + called + '(' + ','.join(args[1:args_count]) + ')'

		if inst.mnemonic == 'call':
			called = None
			deep += 1
			#args.append('ret')
		elif inst.mnemonic == 'ret':
			if deep > 0:
				deep -= 1
		elif inst.mnemonic == 'push':
			args.append(inst.op_str)
		elif inst.mnemonic == 'pop':
			if args:
				args.pop()

	#if execs % 10000 == 0:
	#	print execs