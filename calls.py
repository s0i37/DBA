#!/usr/bin/python
from sys import argv, stdout
from bisect import bisect_left,insort_left
import sqlite3

if len(argv) != 3:
	print "%s trace.txt symbols.db" % argv[0]
	exit()

def get_module(eip):
	for module,bounds in modules.items():
		if bounds[0] <= eip <= bounds[1]:
			return module

def get_symbol(eip):
	for i in xrange(symbol_bounds_len):
		bounds = symbol_bounds[i]
		if bounds[0] <= eip <= bounds[1]:
			return (symbol_names[i], bounds)
	return ('',(0,0))


trace_file = argv[1]
symbols_db = argv[2]
db = sqlite3.connect(symbols_db)
sql = db.cursor()

modules = {}
for info in sql.execute( 'select * from modules' ).fetchall():
	module,start,end = info
	modules.update( { module: [ int(start), int(end) ] } )
symbols = {}
for info in sql.execute( 'select * from symbols' ).fetchall():
	module,symbol,start,end = info
	symbols.update( { symbol: [ int(start), int(end) ] } )

db.close()
symbol_names = symbols.keys()
symbol_bounds = symbols.values()
symbol_bounds_len = len(symbol_bounds)

lines = 0
execs = 0
eips_uniq = []
eips_exec = {}
with open(trace_file) as f:
	modules_exec = {'unkn':0, 'kernel':0}
	for line in f:
		eip = line[3:13]
		eip = int(eip, 16)
		execs += 1
		if eip < 0x80000000:
			module = get_module(eip)
			if module:
				try:
					modules_exec[module] += 1
				except:
					modules_exec[module] = 0
			else:
				modules_exec['unkn'] += 1

			try:	eips_exec[eip] += 1
			except:	eips_exec[eip] = 0

			index = bisect_left(eips_uniq,eip)
			if not index < len(eips_uniq) or eips_uniq[index] != eip:
				insort_left(eips_uniq,eip)
			
		else:
			modules_exec['kernel'] += 1
		if execs % 100000 == 0:
			stdout.write( "\rinstructions: %d" % execs )
			stdout.flush()
	stdout.write( "\rinstructions: %d\n" % execs )
	stdout.flush()

print "unique instructions: %d" % len(eips_uniq)

symbols_exec = {}
bounds = (0,0)
execs = 0
for eip in eips_uniq:
	execs += 1
	if not bounds[0] <= eip <= bounds[1]:
		(symbol,bounds) = get_symbol(eip)
		if symbol:
			symbols_exec[symbol] = eip
	if execs % 1000 == 0:
		stdout.write( "\rinstructions: %d" % execs )
		stdout.flush()
stdout.write( "\rinstructions: %d\n" % execs )
stdout.flush()

with open('stat.txt','w') as o:
	for module,execs in modules_exec.items():
		o.write( "%s %d\n" % (module,execs) )
	for symbol,eip in symbols_exec.items():
		o.write( "%s %d\n" % ( symbol, eips_exec[eip] ) )