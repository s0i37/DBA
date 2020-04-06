#!/usr/bin/python
from lib.emulate import Trace, StopExecution
from os import path
import argparse
import colorama


parser = argparse.ArgumentParser( description='show executed statistic' )
parser.add_argument("tracefile", type=str, help="trace.txt")
parser.add_argument("-modules", action='store_true', default=False, help="show modules statistic")
parser.add_argument("-module", type=str, default='', help="show statistic only by module")
parser.add_argument("-symbols", action='store_true', default=False, help="show symbols statistic")

parser.add_argument("-diff", type=str, default='', help="print difference between two traces")
parser.add_argument("-comp", type=str, default='', help="print comparison between two traces")
args = parser.parse_args()


def get_module(modules, addr):
	for module_name,module_range in modules.items():
		(start,end) = module_range
		if start <= addr <= end:
			return path.basename(module_name.replace('\\','/')), (start, end)
	return None, (0,0)

def get_symbol(symbols, addr):
	for symbol_name,symbol_range in symbols.items():
		(start,end) = symbol_range
		if addr == start:
			return symbol_name

class Module:
	def __init__(self, addr):
		self.addr = addr
		self.execs = 0

	def load_module(self, modules):
		(self.name, _range) = get_module(modules, self.addr)
		(self.start, self.end) = _range 

class Function:
	def __init__(self, addr):
		self.addr = addr
		self.execs = 0
		self.calls = 0

	def load_symbol(self, symbols):
		self.symbol = get_symbol(symbols, self.addr)

	def get_module(self, modules):
		module = Module(self.addr)
		module.load_module(modules)
		if module.end != 0:
			return module

def find_module(modules, addr):
	for module in modules:
		if module.start <= addr <= module.end:
			return module

def in_module(addr, module_name):
	global modules
	for module in modules:
		if module.start <= addr <= module.end and module.name.lower() == module_name:
			return True
	return False

def get_coverage(tracefile):
	current_function = None
	modules = []
	functions = {}
	stack = {}
	with Trace( open(tracefile) ) as trace:
		try:
			while True:
				trace.instruction()
				thr = trace.cpu.thread_id
				if not current_function:
					current_function = functions.get(trace.cpu.eip_before)
					if current_function:
						current_function.calls += 1
					else:
						current_function = Function(trace.cpu.eip_before)
						current_function.load_symbol(trace.symbols)
						current_function.calls += 1
						functions[trace.cpu.eip_before] = current_function

					current_module = find_module(modules, trace.cpu.eip_before)
					if not current_module:
						current_module = current_function.get_module(trace.modules)
						if current_module:
							modules.append(current_module)
					
				if current_module:
					current_module.execs += 1
				current_function.execs += 1

				mnem = trace.cpu.disas()
				if not thr in stack.keys():
					stack[thr] = []
				if mnem.split()[0] in ('call', ):
					stack[thr].append(current_function)
					current_function = None
					current_module = None
				elif mnem.split()[0] in ('ret', ):
					try:	current_function = stack[thr].pop()
					except:	current_function = Function(0)
		
		except KeyboardInterrupt:
			return (modules,functions)
		except StopExecution:
			return (modules,functions)

def diff_cover(functions_after, functions_before):
	functions_diff = {}
	for addr in functions_after.keys():
		if not addr in functions_before.keys():
			functions_diff[addr] = functions_after[addr]
	return functions_diff

def print_modules_stats(modules):
	stats = []
	for module in modules:
		stats.append( ( module.start, module.name, module.execs ) )

	print ""
	print "base: \t\t module: \t execs:"
	for stat in sorted(stats, key=lambda columns: columns[0], reverse=False):
		print "{base} \t {module} \t {execs}".format(base=hex(stat[0]), module=stat[1], execs=stat[2])

def print_functions_stats(functions):
	stats = []
	for addr,function in functions.items():
		if not args.module or in_module(addr, args.module):
			if function.symbol:
				addr = function.symbol
			else:
				addr = "0x%08x" % addr
			stats.append( ( addr, function.calls, function.execs ) )

	print ""
	print "symbol: \t calls:  execs:"
	for stat in sorted(stats, key=lambda columns: columns[1], reverse=True):
		print "{function} \t {calls} \t {execs}".format( function=stat[0], calls=stat[1], execs=stat[2] )


def print_compared_functions_stats(functions_after, functions_before):
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


(modules,functions) = get_coverage(args.tracefile)
if args.diff:
	(modules_diff,functions_diff) = get_coverage(args.diff)
	functions = diff_cover(functions, functions_diff)
elif args.comp:
	(modules_comp,functions_comp) = get_coverage(args.comp)
	print_compared_functions_stats(functions, functions_comp)
	exit()

if args.modules:
	print_modules_stats(modules)
if args.symbols:
	print_functions_stats(functions)
