#!/usr/bin/python3.8
from triton import *
import argparse
from struct import pack
from os import path
import codecs

ctx = TritonContext()
ctx.setArchitecture(ARCH.X86_64)
ctx.setMode(MODE.ALIGNED_MEMORY, True)
#ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)

def emulate(instruction):
	for addr in instruction.mem:
		ctx.setConcreteMemoryAreaValue(addr, instruction.mem[addr])
	
	ctx.setConcreteRegisterValue(ctx.registers.rax, instruction.rax)
	ctx.setConcreteRegisterValue(ctx.registers.rbx, instruction.rbx)
	ctx.setConcreteRegisterValue(ctx.registers.rcx, instruction.rcx)
	ctx.setConcreteRegisterValue(ctx.registers.rdx, instruction.rdx)
	ctx.setConcreteRegisterValue(ctx.registers.rsi, instruction.rsi)
	ctx.setConcreteRegisterValue(ctx.registers.rdi, instruction.rdi)
	ctx.setConcreteRegisterValue(ctx.registers.rip, instruction.addr)
	ctx.setConcreteRegisterValue(ctx.registers.rbp, instruction.rbp)
	ctx.setConcreteRegisterValue(ctx.registers.rsp, instruction.rsp)

	
	inst = Instruction()
	inst.setOpcode(instruction.opcode)
	inst.setAddress(instruction.addr)
	ctx.processing(inst)
	if inst.isTainted():
		if args.from_addr and args.from_addr > instruction.addr or args.to_addr and instruction.addr > args.to_addr:
			return
		if args.from_takt and args.from_takt > instruction.takt or args.to_takt and instruction.takt > args.to_takt:
			return
		print('[taint] %s' % str(inst))
	#next = ctx.getConcreteRegisterValue(ctx.registers.rip)

memory = {}
def save_mem(addr, mem):
	global memory
	for i in range(len(val)):
		memory[addr+i] = mem[i]

def find_mem(addr, needle, size):
	was_found = False
	high_boundary_search = addr + size
	while addr <= high_boundary_search:
		for i in range(len(needle)):
			value = memory.get(addr + i)
			if value == None:
				return None
			if needle.find( chr(value) ) == -1:
				was_found = False
				addr += 1
				break
			else:
				was_found = True
		if was_found:
			return addr
	return None

def align(size):
	return ((size >> 2) +1) << 2

class Step:
	def __init__(self):
		self.mem = {}
	def mem_read(self, addr, val):
		self.mem[addr] = val
	def mem_write(self, addr, val):
		self.mem[addr] = val
	def set_registers(self, regs):
		(self.rax,self.rcx,self.rdx,self.rbx,self.rsp,self.rbp,self.rsi,self.rdi) = regs


parser = argparse.ArgumentParser( description='data flow analisys tool' )
parser.add_argument("tracefile", type=str, help="trace.log")
parser.add_argument("-taint_data", type=str, default='', help='taint data: "GET / HTTP/1.1" or input.bin')
parser.add_argument("-from_takt", type=int, default=0, help="print tainted instruction only after takt")
parser.add_argument("-to_takt", type=int, default=0, help="print tainted instruction only before takt")
parser.add_argument("-from_addr", type=int, default=0, help="print tainted instruction only from address")
parser.add_argument("-to_addr", type=int, default=0, help="print tainted instruction only to address")
args = parser.parse_args()

if path.isfile(args.taint_data):
	with open(args.taint_data) as f:
		args.taint_data = f.read()

instruction = None
has_tainted_data = False
tainted_memory = set()
with open(args.tracefile, 'r') as f:
	while True:
		line = f.readline()
		if not line:
			break
		if line.startswith('['):
			continue

		line = line.split('\n')[0]
		#print(line)
		if line.find('{') != -1:
			addr,opcode,regs = line.split(' ')
			opcode = codecs.decode(opcode[1:-1],'hex')
			rax,rcx,rdx,rbx,rsp,rbp,rsi,rdi = map(lambda r:int(r,16), regs.split(','))
			if instruction and has_tainted_data:
				try:
					emulate(instruction)
				except Exception as e:
					#print(hex(instruction.addr))
					#print(str(e))
					pass
			instruction = Step()
			instruction.set_registers((rax,rcx,rdx,rbx,rsp,rbp,rsi,rdi))
			instruction.opcode = opcode
			icount,addr,thread = addr.split(':')
			instruction.takt = int(icount)
			if instruction.takt % 10000 == 0:
				print("[*] %d" % instruction.takt)
			instruction.addr = int(addr, 16)
		elif line.find('[') != -1:
			if line.find('-') != -1:
				addr,mem,access,val = line.split(' ')
				mem = int(mem[1:-1], 16)
				size = len(val[2:])
				if not val:
					continue
				val = int(val, 16)
				if size == 2: 
					val = pack('B', val)
				elif size == 4:
					val = pack('<H', val)
				elif size == 8:
					val = pack('<L', val)
				elif size == 16:
					val = pack('<Q', val)
				else:
					val = None
				if val:
					if access == '->':
						instruction.mem_read(mem, val)
					elif access == '<-':
						instruction.mem_write(mem, val)
			elif line.find(':') != -1:
				addr,mem,val = line.split(' ')
				mem = int(mem[1:-2], 16)
				val = codecs.decode(val,'hex')
				save_mem(mem,val)
				ptr = find_mem(mem, args.taint_data, len(val))
				if ptr and not ptr in tainted_memory:
					print("[*] 0x%08x taint memory 0x%08x" % (instruction.addr,ptr))
					ctx.taintMemory(MemoryAccess(ptr, align(len(args.taint_data))))
					has_tainted_data = True
					tainted_memory.add(ptr)
