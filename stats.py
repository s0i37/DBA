#!/usr/bin/python
from lib.emulate import Trace, StopExecution
import argparse
import colorama


parser = argparse.ArgumentParser( description='data flow analisys tool' )
parser.add_argument("tracefile", type=str, help="trace.txt")
parser.add_argument("-diff", type=str, default='', help="print difference between two traces")
parser.add_argument("-comp", type=str, default='', help="print comparison between two traces")
args = parser.parse_args()

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

class Function:
	def __init__(self, start):
		self.start = start
		self.execs = 0
		self.calls = 0

def get_covered_functions(tracefile):
	current_function = None
	functions = {}
	stack = []
	with Trace( open(tracefile) ) as trace:
		try:
			while True:
				trace.instruction()
				if not current_function:
					current_function = functions.get(trace.cpu.eip_before)
					if current_function:
						current_function.calls += 1
					else:
						current_function = Function(trace.cpu.eip_before)
						current_function.calls += 1
						functions[trace.cpu.eip_before] = current_function
				current_function.execs += 1

				mnem = trace.cpu.disas()
				if mnem.split()[0] in ('call', ):
					stack.append(current_function)
					current_function = None
				elif mnem.split()[0] in ('ret', ):
					current_function = stack.pop()

		except StopExecution:
			return functions

def diff_cover(functions_after, functions_before):
	functions_diff = {}
	for addr in functions_after.keys():
		if not addr in functions_before.keys():
			functions_diff[addr] = functions_after[addr]
	return functions_diff


def print_stats(functions):
	stats = []
	for addr,function in functions.items():
		stats.append( ( addr, function.calls, function.execs ) )

	print "\nsymbol:\t\tcalls:\texecs:"
	for stat in sorted(stats, key=lambda columns: columns[1], reverse=True):
		print "0x%08x\t%d\t%d" % ( stat[0], stat[1], stat[2] )


def print_compared_stats(functions_after, functions_before):
	def print_diff(a,b):
		if a > b:
			print "+%d\t" % (a-b),
		elif a < b:
			print "%d\t" % (a-b),
		else:
			print "0\t",

	stats = []
	for addr,function in functions_after.items():
		stats.append( ( addr, function.calls, function.execs ) )

	print "\nsymbol:\t\tcalls1:\texecs1:\tcalls2:\texecs2:"
	for stat in sorted(stats, key=lambda columns: columns[1], reverse=True):
		addr = stat[0]
		calls_after = stat[1]
		execs_after = stat[2]
		if addr in functions_before.keys():
			calls_before = functions_before[addr].calls
			execs_before = functions_before[addr].execs
			print "0x%08x\t" % addr,
			print_diff(calls_after, calls_before)
			print_diff(execs_after, execs_before)
			print "%d\t" % calls_before,
			print "%d\t" % execs_before,
			print ''
		else:
			print colorama.Fore.GREEN + "0x%08x\t%d\t%d\t-\t-" % (addr,calls_after,execs_after) + colorama.Fore.RESET

	stats = []
	for addr,function in functions_before.items():
		stats.append( ( addr, function.calls, function.execs ) )
	for stat in sorted(stats, key=lambda columns: columns[1], reverse=True):
		if not addr in functions_after.keys():
			print colorama.Fore.RED + "0x%08x\t-\t-\t%d\t%d" % ( stat[0], stat[1], stat[2] ) + colorama.Fore.RESET


functions = get_covered_functions(args.tracefile)
if args.diff:
	functions_diff = get_covered_functions(args.diff)
	functions = diff_cover(functions, functions_diff)
elif args.comp:
	functions_comp = get_covered_functions(args.comp)
	print_compared_stats(functions, functions_comp)
	exit()
print_stats(functions)


exit()
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

