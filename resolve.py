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
			return symbol,bounds
	return (None,tuple())

with open(trace_file) as f:
	for line in f.read().split('\n'):		
		for word in line.split():
			try:
				eip = int( word[:10], 16 )
			except Exception as e:
				continue
			(symbol,bounds) = get_symbol(eip)
			if symbol:
				resolved_name = "%s+%d" % ( symbol, eip-bounds[0] )
				line = line.replace( word, resolved_name + word[10:] )
		print line
		