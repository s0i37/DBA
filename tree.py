#!/usr/bin/python
from lib.emulate import Trace, StopExecution, get_module, get_symbol
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


def tree_simple():
	delta = 0
	threads = {}
	with Trace( open(args.tracefile) ) as trace:
		try:
			while True:
				trace.instruction()
				delta += 1
				thr = trace.cpu.thread_id

				if not thr in threads.keys():
					threads[thr] = { 'called': None, 'deep': 0, 'args': [] }
					#threads[thr] = [{ 'called': None, 'deep': 0, 'cov': set(), 'args': [] }]

				if not threads[thr]['called']:
					threads[thr]['called'] = trace.cpu.eip_before

					addr = threads[thr]['called']

					module = get_module(trace, addr) or None

					symbol = get_symbol(trace, addr) or ""
					if symbol:
						func = symbol
					else:
						func = "0x%08x" % threads[thr]['called']
					if args.deep < 0 or args.deep >= threads[thr]['deep']:
						if args.thread == -1 or args.thread == thr:
							if not args.module or args.module.lower() == module.name.lower():
								print " "*threads[thr]['deep'] + (module.name+"!" if module else "") + func + '()' + " // " + "%d,%d,%d,+%d" % (threads[thr]['deep'], thr, trace.cpu.takt, delta)
								delta = 0

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

def tree_consolidated():
	threads = {'addr': 0, 'calls': [], 'called': None, 'calls_count': 0, 'execs': 0, 'instr_sets': set()}
	ptr = threads
	is_call = False
	delta = 0
	with Trace( open(args.tracefile) ) as trace:
		try:
			while True:
				trace.instruction()
				delta += 1
				thr = trace.cpu.thread_id

				if not threads['addr']:
					threads['addr'] = trace.cpu.eip_before

				if is_call:
					is_new = True
					for sub in ptr['calls']:
						if sub['addr'] == trace.cpu.eip_before:
							ptr['execs'] += delta
							delta = 0
							ptr = sub
							ptr['calls_count'] += 1
							is_new = False
							break

					if is_new:
						ptr['execs'] += delta
						delta = 0
						called = ptr
						ptr['calls'].append({'addr': trace.cpu.eip_before, 'calls': [], 'called': called, 'calls_count': 1, 'execs': 0, 'instr_sets': set()})
						ptr = ptr['calls'][-1]

				mnem = trace.cpu.disas()
				if mnem.split()[0] in ('shr','shl','mul','div','imul','idiv'):
					ptr['instr_sets'].add('arithmetic')
				elif mnem.split()[0] in ('repe','repne'):
					ptr['instr_sets'].add('rep')
				elif mnem.split()[0].startswith('f'):
					ptr['instr_sets'].add('float')

				is_call = False
				if mnem.split()[0] == 'call':
					is_call = True
				elif mnem.split()[0] == 'ret':
					if ptr['called']:
						ptr['execs'] += delta
						delta = 0
						ptr = ptr['called']
		except StopExecution:
			pass
	
	def walk(call, deep=0):
		print (" "*deep) + ("0x%08x"%call['addr']) + " // " + "%d,+%d,%s"%(call['calls_count'], call['execs'], '/'.join(call['instr_sets']))
		for sub in call['calls']:
			walk(sub, deep+1)
	walk(threads)

#tree_simple()
tree_consolidated()
