#!/usr/bin/python3.8
from triton import *

code = {
	0x555555555145:      b"\x55",
	0x555555555146:      b"\x48\x89\xe5",
	0x555555555149:      b"\x48\x89\x7d\xe8",
	0x55555555514d:      b"\x48\x8b\x45\xe8",
	0x555555555151:      b"\x48\x83\xc0\x03",
	0x555555555155:      b"\x0f\xb6\x00",
	0x555555555158:      b"\x88\x45\xff",
	0x55555555515b:      b"\x48\x8b\x45\xe8",
	0x55555555515f:      b"\x0f\xb7\x00",
	0x555555555162:      b"\x66\x89\x45\xfc",
	0x555555555166:      b"\x80\x7d\xff\x00",
	0x55555555516a:      b"\x74\x33",
	0x55555555516c:      b"\x80\x7d\xff\x72",
	0x555555555170:      b"\x75\x26",
	0x555555555172:      b"\x0f\xb6\x45\xff",
	0x555555555176:      b"\x83\xc0\x22",
	0x555555555179:      b"\x88\x45\xfb",
	0x55555555517c:      b"\x80\x75\xfb\x11",
	0x555555555180:      b"\x0f\xb6\x45\xfb",
	0x555555555184:      b"\x66\x39\x45\xfc",
	0x555555555188:      b"\x75\x07",
	0x55555555518a:      b"\xb8\x03\x00\x00\x00",
	0x55555555518f:      b"\xeb\x13",
	0x555555555191:      b"\xb8\x02\x00\x00\x00",
	0x555555555196:      b"\xeb\x0c",
	0x555555555198:      b"\xb8\x01\x00\x00\x00",
	0x55555555519d:      b"\xeb\x05",
	0x55555555519f:      b"\xb8\x00\x00\x00\x00",
	0x5555555551a4:      b"\x5d",
	0x5555555551a5:      b"\xc3",
}

ctx = TritonContext()
ctx.setArchitecture(ARCH.X86_64)
ctx.setMode(MODE.ALIGNED_MEMORY, True)
#ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)

ctx.setConcreteMemoryAreaValue(0x7ffffffde000, open('/tmp/1.bin','rb').read())
ctx.setConcreteMemoryAreaValue(0x555555555000, open('/tmp/2.bin','rb').read())
ctx.setConcreteRegisterValue(ctx.registers.rax, 0x7fffffffe146)
ctx.setConcreteRegisterValue(ctx.registers.rbx, 0x00000000)
ctx.setConcreteRegisterValue(ctx.registers.rcx, 0x7ffff7fa2a00)
ctx.setConcreteRegisterValue(ctx.registers.rdx, 0x7ffff7fa5590)
ctx.setConcreteRegisterValue(ctx.registers.rsi, 0x74726577)
ctx.setConcreteRegisterValue(ctx.registers.rdi, 0x7fffffffe146)
ctx.setConcreteRegisterValue(ctx.registers.r8, 0x7fffffffe146)
ctx.setConcreteRegisterValue(ctx.registers.r9, 0x00000000)
ctx.setConcreteRegisterValue(ctx.registers.r10, 0x00000410)
ctx.setConcreteRegisterValue(ctx.registers.r11, 0x00000246)
ctx.setConcreteRegisterValue(ctx.registers.r12, 0x555555555060)
ctx.setConcreteRegisterValue(ctx.registers.r13, 0x7fffffffe230)
ctx.setConcreteRegisterValue(ctx.registers.r14, 0x00000000)
ctx.setConcreteRegisterValue(ctx.registers.r15, 0x00000000)
ctx.setConcreteRegisterValue(ctx.registers.rip, 0x55555555514d)
ctx.setConcreteRegisterValue(ctx.registers.rbp, 0x7fffffffe130)
ctx.setConcreteRegisterValue(ctx.registers.eflags, 0x00000246)
ctx.setConcreteRegisterValue(ctx.registers.rsp, 0x7fffffffe130)

ctx.taintMemory(MemoryAccess(0x7fffffffe146, 8))
addr = 0x55555555514d
while addr in code:
	inst = Instruction()
	inst.setOpcode(code[addr])
	inst.setAddress(addr)
	ctx.processing(inst)
	if inst.isTainted():
		print('[tainted] %s' % str(inst))
	else:
		print('[*] %s' % str(inst))
	addr = ctx.getConcreteRegisterValue(ctx.registers.rip)
