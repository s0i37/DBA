#!/usr/bin/python
import os
from sys import argv, stdout


if len(argv) < 2:
	print "%s trace.txt [symbols.txt]" % argv[0]
	exit()

trace_file = argv[1]

modules_used = {}
symbols_used = {}
modules_exec = {}
symbols_exec = {}

modules = {}
symbols = {}

#for performance reason
last_module = {}
last_symbol = {}

def get_module(eip):
	global modules
	for (modulename,_range) in modules.items():
		(start,end) = _range
		if start <= eip <= end:
			return { 'name': modulename, 'start': start, 'end': end }
	return {}

def get_symbol(eip):
	global symbols
	for (symbol,_range) in symbols.items():
		(start,end) = _range
		if start <= eip <= end:
			return { 'name': symbol, 'start': start, 'end': end }
	return {}

def whereis(eip):
	global last_module, last_symbol, modules_used, symbols_used
	if not ( last_module and last_module['start'] <= eip <= last_module['end'] ):
		last_module = get_module(eip)

		if last_module and not last_module['name'] in modules_used.keys():
			modules_used[ last_module['name'] ] = [ last_module['start'], last_module['end'] ]

	if not last_symbol or last_symbol['start'] > eip or eip > last_symbol['end']:
		last_symbol = get_symbol(eip)
		if last_symbol and not last_symbol['name'] in symbols_used.keys():
			symbols_used[ last_symbol['name'] ] = [ last_symbol['start'], last_symbol['end'] ]
	return (last_module,last_symbol)


instr = 0
memop_r = 0
memop_w = 0

#load trace
if os.path.isfile(trace_file):
	with open(trace_file) as f:
		for line in f:
			try:
				#comment found
				if line.startswith('[#]'):
					continue
				#module found
				elif line.startswith('[*] module'):
					(_, _, modulename, start, end) = line.split()
					start = int(start, 16)
					end = int(end, 16)
					modules[modulename] = [start, end]
					print "[*] %s 0x%08x 0x%08x" % (modulename, start, end)
					continue
				#symbol found
				elif line.startswith('[*] function'):
					(_, _, symbol, start, end) = line.split()
					start = int(start, 16)
					end = int(end, 16)
					symbols[symbol] = [start, end]
					continue
				#instruction found
				elif line.find('{') != -1:
					(eip,opcode,regs) = line.split()
					takt = int( eip.split(':')[0] )
					(eip,thread) = map( lambda x: int(x, 16), eip.split(':')[1:] )
					(eax,ecx,edx,ebx,esp,ebp,esi,edi) = map( lambda x: int(x,16), regs.split(',') )
					memory = None
				#memory found
				elif line.find('[') != -1:
					(eip,memory,direction,value) = line.split()
					takt = int( eip.split(':')[0] )
					(eip,thread) = map( lambda x: int(x, 16), eip.split(':')[1:] )
					memory = int( memory[1:-1], 16 )
					value = int( value, 16 )
					opcode = None
					if direction == "->":
						memop_r += 1
					elif direction == "<-":
						memop_w += 1
				#nothing
				else:
					continue
			except Exception as e:
				continue

			if opcode:
				(module,symbol) = whereis(eip)
				if module:
					try:
						modules_exec[ module['name'] ] += 1
					except:
						modules_exec[ module['name'] ] = 1
				if symbol:
					try:
						symbols_exec[ symbol['name'] ] += 1
					except:
						symbols_exec[ symbol['name'] ] = 1

			if takt and takt % 10000 == 0:
				stdout.write( "\rx:%d, r:%d, w:%d %s %s" % ( takt, memop_r, memop_w, last_module.get('name') or '', last_symbol.get('name') or '' ) )
				stdout.flush()

print ''
for module,module_range in modules_used.items():
	print "%s\t\t%d execs" % ( module, modules_exec.get(module, 0) )
	for symbol,symbol_range in symbols_used.items():
		if module_range[0] <= symbol_range[0] and symbol_range[1] <= module_range[1]:
			print "\t%s\t%d execs" % ( symbol, symbols_exec.get(symbol, 0) )
