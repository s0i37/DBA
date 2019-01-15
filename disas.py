#!/usr/bin/python
from lib.emulate import Trace, CPU
from sys import stdin
import argparse
import colorama


parser = argparse.ArgumentParser( description='data flow analisys tool' )
parser.add_argument("tracefile", type=str, help="trace.txt")

parser.add_argument("-from_takt", type=int, default=0, help="print tainted instruction only after takt")
parser.add_argument("-to_takt", type=int, default=0, help="print tainted instruction only before takt")
parser.add_argument("-takts", type=int, default=0, help="print tainted instruction only before takt")

parser.add_argument("-regs", type=str, default='', help="print reg1,reg2,regN")

parser.add_argument("-deep", type=int, default=-1, help="print tainted instruction only before takt")
parser.add_argument("-func", dest="just_func", type=bool, default=False, help="disas just function")

parser.add_argument("-ir", dest="ir", type=bool, default=False, help="IR")
parser.add_argument("-anal", dest="anal", type=bool, default=False, help="analyze")

parser.add_argument("-diff", type=str, default='', help="print difference between two traces")
args = parser.parse_args()

if args.ir:
	from miasm2.core.locationdb import LocationDB
	from miasm2.analysis.machine import Machine
	machine = Machine('x86_32')

if args.diff:
	import difflib

	eips_a = []
	eips_b = []
	new_eips = []
	lost_eips = []
	with open(args.diff) as f:
		for line in f:
			if line.find('{') != -1:
				eips_a.append( line.split(':')[1] )
	with open(args.tracefile) as f:
		for line in f:
			if line.find('{') != -1:
				eips_b.append( line.split(':')[1] )
	
	print '[*] loaded %d instructions of "%s"' % (len(eips_a), args.diff)
	print '[*] loaded %d instructions of "%s"' % (len(eips_b), args.tracefile)
	for diff in difflib.unified_diff(eips_a, eips_b):
		if diff.find('+0x') != -1:
			new_eips.append( int(diff[1:], 16) )
		elif diff.find('-0x') != -1:
			lost_eips.append( int(diff[1:], 16) )
	print '[+] found %d new instructions' % len(new_eips)
	print '[+] found %d lost instructions' % len(lost_eips)
	new_eip = new_eips.pop(0)
	diff_no = 1
	del eips_a
	del eips_b


with Trace( open(args.tracefile) if args.tracefile != '-' else stdin ) as trace:
	deep = 0
	while True:
		used_registers, used_memory = None, None
		if args.anal:
			info = trace.execute()
			if info:
				(used_registers, used_memory) = info
		else:
			info = trace.instruction()

		args.takts -= 1
		if args.takts == 0:
			break

		mnem = trace.cpu.disas()

		if args.deep >= 0 and deep > args.deep:
			continue

		if mnem.split()[0] in ('call', ):
			deep += 1
		elif mnem.split()[0] in ('ret', ):
			deep -= 1

		if args.just_func and mnem[0] in ('ret', ):
			break


		if args.diff:
			if not new_eips:
				break
			if trace.cpu.eip_before == new_eip:
				new_eip = new_eips.pop(0)
				print "%d:" % diff_no,
				diff_no += 1
			else:
				continue
		
		
		if args.ir:
			loc_db = LocationDB()
			instr = machine.mn.dis(trace.cpu.opcode, 32)
			ira = machine.ira(loc_db)
			ircfg = ira.new_ircfg()
			ira.add_instr_to_ircfg(instr, ircfg)
			for lbl, irblock in ircfg.blocks.items():
				print irblock.to_string(loc_db)
		else:
			print "{takt}:{offset}: {disas}".format( takt=trace.cpu.takt, offset=hex(trace.cpu.eip_before), disas=mnem ),
			if args.regs:
				print ';',
				for reg in args.regs.split(','):
					print "%s=0x%X," % (reg, trace.cpu.get(reg)),
			print ''
		

		if used_registers:
			regs_r, regs_w = used_registers
			for reg_r in regs_r:
				print "%s -> 0x%X," % (reg_r, trace.cpu.get(reg_r, when='before')),
			for reg_w in regs_w:
				print "%s <- 0x%X," % (reg_w, trace.cpu.get(reg_w, when='after')),
			print ''
		if used_memory:
			mems_r, mems_w = used_memory
			for mem_r in mems_r:
				print "[0x%x] -> 0x%X," % (mem_r, trace.io.ram.get_dword(mem_r)),
			for mem_w in mems_w:
				print "[0x%x] <- 0x%X," % (mem_w, trace.io.ram.get_dword(mem_w)),
			print ''
