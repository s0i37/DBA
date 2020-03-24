#!/usr/bin/python2
from lib.emulate import Trace
from sys import stdin
import argparse
import colorama


parser = argparse.ArgumentParser( description='data flow analisys tool' )
parser.add_argument("tracefile", type=str, help="trace.txt")

parser.add_argument("-from_takt", type=int, default=0, help="disas only after takt")
parser.add_argument("-to_takt", type=int, default=0, help="disas only before takt")
parser.add_argument("-takts", type=int, default=0, help="disas only N takts")

parser.add_argument("-regs", type=str, default='', help="print reg1,reg2,regN")
parser.add_argument("-mems", type=str, default='', help="print [imm1],[reg1],[immN]")

parser.add_argument("-function", dest="just_function", type=bool, default=False, help="disas only current function")
parser.add_argument("-from_deep", type=int, default=-1, help="disas only deeper then N")
parser.add_argument("-to_deep", type=int, default=-1, help="disas only not deeper then N")

parser.add_argument("-ir", dest="ir", type=bool, default=False, help="print IR instead of disas")
parser.add_argument("-anal", dest="anal", type=bool, default=False, help="print REGs access, MEMs access")

parser.add_argument("-diff", type=str, default='', help="print difference between two traces")
args = parser.parse_args()

if args.ir:
	from miasm.core.locationdb import LocationDB
	from miasm.analysis.machine import Machine
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
	after_call = False
	after_ret = False
	while True:
		used_registers, used_memory = None, None
		if args.anal:
			info = trace.execute()
			if info:
				(used_registers, used_memory) = info
		else:
			info = trace.instruction()

		if args.from_takt and trace.cpu.takt < args.from_takt:
			continue
		if args.to_takt and trace.cpu.takt > args.to_takt:
			break

		args.takts -= 1
		if args.takts == 0:
			break

		mnem = trace.cpu.disas()

		if after_call:
			deep += 1
			after_call = False
		elif after_ret:
			deep -= 1
			after_ret = False

		if mnem.split()[0] in ('call', ):
			after_call = True
		elif mnem.split()[0] in ('ret', ):
			after_ret = True

		if args.to_deep >= 0 and deep > args.to_deep:
			continue
		if args.from_deep >= 0 and deep < args.from_deep:
			continue

		if args.just_function:
			if deep > 0:
				continue
			if deep < 0:
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
		if args.mems:
			print ';',
			for mem in args.mems.split(','):
				try:
					imm = int(mem,16)
					print "[0x%08x]=0x%08X," % (imm, trace.io.ram.get_dword(imm)),
				except:
					reg = mem
					ptr = trace.cpu.get(reg)
					print "[%s=0x%08x]=0x%08X," % (reg, ptr, trace.io.ram.get_dword(ptr)),

		if used_registers:
			print ';',
			regs_r, regs_w = used_registers
			for reg_r in regs_r:
				print "%s -> 0x%X," % (reg_r, trace.cpu.get(reg_r, when='before')),
			for reg_w in regs_w:
				print "%s <- 0x%X," % (reg_w, trace.cpu.get(reg_w, when='after')),
		if used_memory:
			print ';',
			mems_r, mems_w = used_memory
			for mem_r in mems_r:
				print "[0x%x] -> 0x%X," % (mem_r, trace.io.ram.get_dword(mem_r)),
			for mem_w in mems_w:
				print "[0x%x] <- 0x%X," % (mem_w, trace.io.ram.get_dword(mem_w)),

		print ''