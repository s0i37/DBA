#!/usr/bin/python2
import argparse
from lib.emulate import Trace, BPX, BPM, memmap as _memmap, read_mem as _read_mem, get_symbol, get_module
from ipdb import set_trace
from capstone import *
from capstone.x86 import *
from os.path import basename


parser = argparse.ArgumentParser( description='replay execution trace' )
parser.add_argument("tracefile", type=str, help="trace.log")
parser.add_argument("-bpx", type=str, dest="bpx", default='', help="breakpoint on execute [takt:]address[:thread]")
parser.add_argument("-bpm", type=str, dest="bpm", default='', help="breakpoint on memory address[:read|write]")
args = parser.parse_args()

md = Cs(CS_ARCH_X86, CS_MODE_64)

def get_bpx(bpx):
	param = bpx.split(':')
	takt = None
	addr = None
	thr = None
	if len(param) == 3:
		takt = int(param[0]) if param[0] else None
		addr = int(param[1]) if param[1] else None
		thr = int(param[2]) if param[2] else None
	elif len(param) == 2:
		addr = int(param[0]) if param[0] else None
		thr = int(param[1]) if param[1] else None
	elif len(param) == 1:
		addr = int(param[0])
	return (takt, addr, thr)

def get_bpm(bpm):
	param = bpm.split(':')
	addr = None
	op = 'read'
	if len(param) == 2:
		addr = int(param[0])
		op = param[1]
	elif len(param) == 1:
		addr = int(param[0])
	return (addr, op)

def HEX(val):
	#return "0x%08x" % val
	return "0x%016x" % val

def disas(addr=None):
	if not addr:
		addr = trace.cpu.pc
	code = ''
	for byte in _read_mem(trace, addr, 30):
		if byte == None:
			break
		code += chr(byte)
	for instr in md.disasm(code, trace.cpu.pc):
		print "{offset}: {bytes}   {instr}".format(offset=HEX(instr.address), bytes=str(instr.bytes).encode('hex'), instr="%s %s"%(instr.mnemonic, instr.op_str))
	
def regs():
	print "RAX: {RAX}, RDX: {RDX}, RCX: {RCX}, RBX: {RBX}".format(RAX=HEX(trace.cpu['rax']), RDX=HEX(trace.cpu['rdx']), RCX=HEX(trace.cpu['rcx']), RBX=HEX(trace.cpu['rbx']))
	print "RSP: {RSP}, RBP: {RBP}, RSI: {RSI}, RDI: {RDI}".format(RSP=HEX(trace.cpu['rsp']), RBP=HEX(trace.cpu['rbp']), RSI=HEX(trace.cpu['rsi']), RDI=HEX(trace.cpu['rdi']))
	print "RIP: {RIP}".format(RIP=HEX(trace.cpu.pc))

def hexdump(addr, len=0x20):
	start = ((addr >> 4) << 4)
	end = (((addr+len) >> 4) << 4) + 0x10
	a = start
	for a in xrange(start, addr):
		if a % 0x10 == 0:
			print "\n0x%08x: " % a,
		print "** ",
	for byte in _read_mem(trace, addr, len):
		if a % 0x10 == 0:
			print "\n0x%08x: " % a,
		print "%02X " % byte if byte != None else "?? ",
		a += 1
	if a % 0x10 != 0:
		for a in xrange(addr+len, end):
			print "** ",
	print ""

def stack(size=0x80, addr=None):
	if not addr:
		addr = trace.cpu['rsp']
	step = 8
	for a in xrange(addr, addr+size, step):
		qword = trace.io.ram.get_qword(a)
		if qword != None:
			print "{addr}: {val}".format(addr=HEX(a), val=HEX(qword))
		else:
			print "{addr}: {val}".format(addr=HEX(a), val="????????????????")

def backtrace(deep=30):
	for thr in trace.callstack.keys():
		print "callstack thread {thr}:".format(thr=hex(thr))
		i = 0
		for function in trace.callstack[thr]:
			symbol = get_symbol(trace, function)
			module = get_module(trace, function)
			i += 1
			if i >= deep:
				print "..."
				break
			print " " + ("{module}.{symbol}".format(module=basename(module.name.replace('\\','/')), symbol=symbol) if module and symbol else HEX(function))

def modules():
	columns = []
	for module in trace.modules:
		columns.append( (module.start, module.name) )

	for column in sorted(columns, key=lambda cols: cols[0], reverse=False):
		print "{base} {module}".format(base=hex(column[0]), module=column[1])

def memmap(addr=None):
	def to_str(perm):
		if perm == 7:
			return 'rwx'
		elif perm == 6:
			return 'rw-'
		elif perm == 5:
			return 'r-x'
		elif perm == 4:
			return 'r--'
		elif perm == 3:
			return '-wx'
		elif perm == 2:
			return '-w-'
		elif perm == 1:
			return '--x'
		else:
			return '---'
	for page in _memmap(trace):
		if not addr or page.start <= addr < page.end:
			name = page.module.name if page.module else "" 
			print "{start} {end} {perm} \t r:{r} w:{w} x:{x} \t {name}".format(start=hex(page.start), end=hex(page.end), perm=to_str(page.perm),
				r=page.reads, w=page.writes, x=page.execs,
				name=name,)


def symbols(module=None):
	columns = []
	(start,end) = (0,0)
	if module:
		for _module in trace.modules:
			if _module.name.lower().find(module.lower()) != -1:
				(start,end) = (_module.start, _module.end)
				break

	for symbol in trace.symbols.keys():
		if not module or start <= trace.symbols[symbol][0] and end >= trace.symbols[symbol][1]:
			if not symbol or symbol.lower() == symbol.lower():
				columns.append( (trace.symbols[symbol][0], symbol) )

	for column in sorted(columns, key=lambda cols: cols[0], reverse=False):
		print "{base} {symbol}".format(base=hex(column[0]), symbol=column[1])

def symbol(symbol):
	for symbol_name in trace.symbols.keys():
		if symbol.lower() == symbol_name.lower():
			print "{base} {symbol}".format(base=hex(trace.symbols[symbol_name][0]), symbol=symbol_name)
			break

def mem_access():
	for readed_cell in trace.io.readed_cells:
		print "R: {cell}".format(cell=HEX(readed_cell))
	for writed_cell in trace.io.writed_cells:
		print "W: {cell}".format(cell=HEX(writed_cell))


def on_exec(trace, takt, thread_id):
	if not takt or takt == trace.cpu.takt:
		if not thread_id or thread_id.cpu.thread_id:
			locals = globals
			print ""
			disas()
			regs()
			mem_access()
			set_trace()

def on_mem(trace, access_type, access_allow):
	if access_type == access_allow:
		locals = globals
		print ""
		disas()
		regs()
		mem_access()
		set_trace()

def si():
	trace.step()
	disas()
	regs()
	mem_access()

def bpx(addr, thr=None, takt=None):
	trace.bpx[addr] = BPX(on_exec, takt, thr)

def bpm(addr, op='read'):
	trace.bpm[addr] = BPM(on_mem, op)

def del_bpx(addr):
	del trace.bpx[addr]

def list_bpx():
	for addr in trace.bpx.keys():
		print hex(addr)

with Trace( open(args.tracefile) ) as trace:
	trace.callstack = {}
	if args.bpx:
		takt,addr,thr = get_bpx(args.bpx)
		trace.bpx[addr] = BPX(on_exec, takt, thr)
	if args.bpm:
		addr,op = get_bpm(args.bpm)
		trace.bpm[addr] = BPM(on_mem, op)
	
	while True:
		try:
			trace.cont()

		except KeyboardInterrupt:
			set_trace()
