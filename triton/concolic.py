#!/usr/bin/python3.8
from triton import *
import argparse
from struct import pack
from os import path
import codecs


ctx = TritonContext()
ctx.setArchitecture(ARCH.X86_64)
ctx.setMode(MODE.ALIGNED_MEMORY, True)
astCtxt = ctx.getAstContext()
#ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)

def emulate(instruction):
	for addr in instruction.mem:
		if not ctx.isMemorySymbolized(addr):
			ctx.setConcreteMemoryAreaValue(addr, instruction.mem[addr])

	if not ctx.isRegisterSymbolized(ctx.registers.rax):
		ctx.setConcreteRegisterValue(ctx.registers.rax, instruction.rax)
	if not ctx.isRegisterSymbolized(ctx.registers.rbx):
		ctx.setConcreteRegisterValue(ctx.registers.rbx, instruction.rbx)
	if not ctx.isRegisterSymbolized(ctx.registers.rcx):
		ctx.setConcreteRegisterValue(ctx.registers.rcx, instruction.rcx)
	if not ctx.isRegisterSymbolized(ctx.registers.rdx):
		ctx.setConcreteRegisterValue(ctx.registers.rdx, instruction.rdx)
	if not ctx.isRegisterSymbolized(ctx.registers.rsi):
		ctx.setConcreteRegisterValue(ctx.registers.rsi, instruction.rsi)
	if not ctx.isRegisterSymbolized(ctx.registers.rdi):
		ctx.setConcreteRegisterValue(ctx.registers.rdi, instruction.rdi)
	if not ctx.isRegisterSymbolized(ctx.registers.rbp):
		ctx.setConcreteRegisterValue(ctx.registers.rbp, instruction.rbp)
	if not ctx.isRegisterSymbolized(ctx.registers.rsp):
		ctx.setConcreteRegisterValue(ctx.registers.rsp, instruction.rsp)

	inst = Instruction()
	inst.setOpcode(instruction.opcode)
	inst.setAddress(instruction.addr)
	ctx.processing(inst)
	if inst.isSymbolized():
		print('[symbolic] %s' % str(inst))
		if inst.isBranch():
			#for constraint in ctx.getModel(ctx.getPathPredicate()).values():
			for constraint in ctx.getModel(astCtxt.lnot(ctx.getPathPredicate())).values():
				#import ipdb;ipdb.set_trace()
				name = constraint.getVariable().getName()
				size = int(constraint.getVariable().getBitSize()/8)
				solve = constraint.getValue().to_bytes(size, byteorder='little')
				print("[+] {addr}: {solve}".format(addr=hex(inst.getAddress()), solve=str(solve)))

memory = {}
def save_mem(addr, mem):
	global memory
	for i in range(len(mem)):
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
parser.add_argument("-symbolic_data", type=str, default='', help='symbolic data: "GET / HTTP/1.1" or input.bin')
args = parser.parse_args()

if path.isfile(args.symbolic_data):
	with open(args.symbolic_data) as f:
		args.symbolic_data = f.read()

instruction = None
has_symbolic_data = False
symbolic_memory = set()
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
			if instruction and has_symbolic_data:
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
			icount = int(icount)
			if icount % 10000 == 0:
				print("[*] %d" % icount)
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
				ptr = find_mem(mem, args.symbolic_data, len(val))
				if ptr and not ptr in symbolic_memory:
					print("[*] symbolize memory 0x%08x" % ptr)
					#import ipdb;ipdb.set_trace()
					ctx.setConcreteMemoryAreaValue(ptr, bytes(args.symbolic_data, 'utf8'))
					ctx.symbolizeMemory(MemoryAccess(ptr, align(len(args.symbolic_data))))
					has_symbolic_data = True
					symbolic_memory.add(ptr)
