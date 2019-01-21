#!/usr/bin/python
from lib.emulate import Trace, StopExecution
from os import path
import argparse


parser = argparse.ArgumentParser( description='data flow analisys tool' )
parser.add_argument("tracefile", type=str, help="trace.txt")
parser.add_argument("-deep", type=int, default=-1, help="print calls not deeper then N")
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


modules = {}
functions = {}


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
				func_name = get_func_name(addr)
				if func_name:
					func = func_name
				else:
	#				module,addr = get_relative(addr)
	#				if module:
	#					func = "%s+0x%x" % (module, addr)
	#				else:
					func = "0x%08x" % threads[thr]['called']
				if args.deep < 0 or args.deep >= threads[thr]['deep']:
					print "%02d:%d:%06d" % (threads[thr]['deep'], thr, execs) + " "*threads[thr]['deep'] + func + '()'

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