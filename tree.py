#!/usr/bin/python
from lib.emulate import Trace, StopExecution
from os import path
import argparse


parser = argparse.ArgumentParser( description='show calls tree' )
parser.add_argument("tracefile", type=str, help="trace.txt")
parser.add_argument("-deep", type=int, default=-1, help="print calls not deeper then N")
parser.add_argument("-thread", type=int, default=-1, help="print calls only of thread")
parser.add_argument("-module", type=str, default='', help="print calls only for module")
args = parser.parse_args()

def try_ascii(hexstr):
	out = ''
	for i in xrange(0,len(hexstr),2):
		byte = int( '0x'+hexstr[i:i+2], 16 )
		if 0x20 <= byte <= 0x7f:
			out += chr(byte)
		else:
			out += '.'
	return out



def get_module(modules, addr):
	for module_name,module_range in modules.items():
		(start,end) = module_range
		if start <= addr <= end:
			return path.basename(module_name.replace('\\','/'))

def get_symbol(symbols, addr):
	for symbol_name,symbol_range in symbols.items():
		(start,end) = symbol_range
		if addr == start:
			return symbol_name



execs = 0
threads = {}
with Trace( open(args.tracefile) ) as trace:
	try:
		while True:
			trace.instruction()
			execs += 1
			thr = trace.cpu.thread_id

			if not thr in threads.keys():
				threads[thr] = { 'called': None, 'deep': 0, 'args': [] }

			if not threads[thr]['called']:
				threads[thr]['called'] = trace.cpu.eip_before

				addr = threads[thr]['called']

				module = get_module(trace.modules, addr) or ""

				symbol = get_symbol(trace.symbols, addr)
				if symbol:
					func = symbol
				else:
					func = "0x%08x" % threads[thr]['called']
				if args.deep < 0 or args.deep >= threads[thr]['deep']:
					if args.thread == -1 or args.thread == thr:
						if not args.module or args.module.lower() == module.lower():
							print "%02d:%d:%06d" % (threads[thr]['deep'], thr, execs) + " " + " "*threads[thr]['deep'] + (module+"!" if module else "") + func + '()'

			mnem = trace.cpu.disas()
			if mnem.split()[0] == 'call':
				threads[thr]['called'] = None
				threads[thr]['deep'] += 1
			elif mnem.split()[0] == 'ret':
				if threads[thr]['deep'] > 0:
					threads[thr]['deep'] -= 1
			#elif mnem.split()[0] == 'push':
			#	threads[thr]['args'].append(inst.op_str)
			#elif mnem.split()[0] == 'pop':
			#	if threads[thr]['args']:
			#		threads[thr]['args'].pop()
	except StopExecution:
		pass
