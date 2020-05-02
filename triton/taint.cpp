#include <iostream>
#include <triton/api.hpp>
#include <triton/x86Specifications.hpp>

using namespace triton;
using namespace triton::arch;
using namespace triton::arch::x86;

struct op {
	long int    addr;
	unsigned char*  inst;
	unsigned int    size;
};

struct op trace[] = {
	{0x555555555145, (unsigned char *)"\x55", 1},
	{0x555555555146, (unsigned char *)"\x48\x89\xe5", 3},
	{0x555555555149, (unsigned char *)"\x48\x89\x7d\xe8", 4},
	{0x55555555514d, (unsigned char *)"\x48\x8b\x45\xe8", 4},
	{0x555555555151, (unsigned char *)"\x48\x83\xc0\x03", 4},
	{0x555555555155, (unsigned char *)"\x0f\xb6\x00", 3},
	{0x555555555158, (unsigned char *)"\x88\x45\xff", 3},
	{0x55555555515b, (unsigned char *)"\x48\x8b\x45\xe8", 4},
	{0x55555555515f, (unsigned char *)"\x0f\xb7\x00", 3},
	{0x555555555162, (unsigned char *)"\x66\x89\x45\xfc", 4},
	{0x555555555166, (unsigned char *)"\x80\x7d\xff\x00", 4},
	{0x55555555516a, (unsigned char *)"\x74\x33", 2},
	{0x55555555516c, (unsigned char *)"\x80\x7d\xff\x72", 4},
	{0x555555555170, (unsigned char *)"\x75\x26", 2},
	{0x555555555172, (unsigned char *)"\x0f\xb6\x45\xff", 4},
	{0x555555555176, (unsigned char *)"\x83\xc0\x22", 3},
	{0x555555555179, (unsigned char *)"\x88\x45\xfb", 3},
	{0x55555555517c, (unsigned char *)"\x80\x75\xfb\x11", 4},
	{0x555555555180, (unsigned char *)"\x0f\xb6\x45\xfb", 4},
	{0x555555555184, (unsigned char *)"\x66\x39\x45\xfc", 4},
	{0x555555555188, (unsigned char *)"\x75\x07", 2},
	{0x55555555518a, (unsigned char *)"\xb8\x03\x00\x00\x00", 5},
	{0x55555555518f, (unsigned char *)"\xeb\x13", 2},
	{0x555555555191, (unsigned char *)"\xb8\x02\x00\x00\x00", 5},
	{0x555555555196, (unsigned char *)"\xeb\x0c", 2},
	{0x555555555198, (unsigned char *)"\xb8\x01\x00\x00\x00", 5},
	{0x55555555519d, (unsigned char *)"\xeb\x05", 2},
	{0x55555555519f, (unsigned char *)"\xb8\x00\x00\x00\x00", 5},
	{0x5555555551a4, (unsigned char *)"\x5d", 1},
	{0x5555555551a5, (unsigned char *)"\xc3", 1},
	{0x0,      nullptr,                                     0}
};

std::vector<triton::uint8> get_memory()
{
	std::vector<triton::uint8> memory = {};
	char b;
	FILE *f = fopen("/tmp/1.bin", "rb");
	while(!feof(f))
	{
		fread(&b, 1, 1, f);
		memory.push_back(b);
	}
	fclose(f);
	return memory;
}

int in_area(long int addr)
{
	for(int i = 0; i < sizeof(trace); i++)
		if(trace[i].addr == addr)
			return i;
	return -1;
}

int main(void)
{
	triton::API api;
	Instruction inst;
	triton::uint64 addr;
	int op;

	api.setArchitecture(ARCH_X86_64);
	//api.setMode(triton::modes::ALIGNED_MEMORY, true);
	api.setConcreteMemoryAreaValue( (triton::uint64)0x7ffffffde000, get_memory());
	api.taintMemory(MemoryAccess(0x7fffffffe146, 8));

	api.setConcreteRegisterValue(api.registers.x86_rax, 0x7fffffffe146);
	api.setConcreteRegisterValue(api.registers.x86_rbx, 0x00000000);
	api.setConcreteRegisterValue(api.registers.x86_rcx, 0x7ffff7fa2a00);
	api.setConcreteRegisterValue(api.registers.x86_rdx, 0x7ffff7fa5590);
	api.setConcreteRegisterValue(api.registers.x86_rsi, 0x74726577);
	api.setConcreteRegisterValue(api.registers.x86_rdi, 0x7fffffffe146);
	api.setConcreteRegisterValue(api.registers.x86_r8, 0x7fffffffe146);
	api.setConcreteRegisterValue(api.registers.x86_r9, 0x00000000);
	api.setConcreteRegisterValue(api.registers.x86_r10, 0x00000410);
	api.setConcreteRegisterValue(api.registers.x86_r11, 0x00000246);
	api.setConcreteRegisterValue(api.registers.x86_r12, 0x555555555060);
	api.setConcreteRegisterValue(api.registers.x86_r13, 0x7fffffffe230);
	api.setConcreteRegisterValue(api.registers.x86_r14, 0x00000000);
	api.setConcreteRegisterValue(api.registers.x86_r15, 0x00000000);
	api.setConcreteRegisterValue(api.registers.x86_rip, 0x55555555514d);
	api.setConcreteRegisterValue(api.registers.x86_rbp, 0x7fffffffe130);
	api.setConcreteRegisterValue(api.registers.x86_eflags, 0x00000246);
	api.setConcreteRegisterValue(api.registers.x86_rsp, 0x7fffffffe130);

	addr = 0x55555555514d;
	while( (op = in_area(addr)) != -1 )
	{
		inst.setAddress(trace[op].addr);
		inst.setOpcode(trace[op].inst, trace[op].size);

	    //api.symbolizeRegister(api.registers.x86_rax);

		api.processing(inst);
		if(inst.isTainted())
			std::cout << "[taint] 0x" << std::hex << addr << ": " << inst.getDisassembly() << std::endl;
		else
			std::cout << "[*] 0x" << std::hex << addr << ": " << inst.getDisassembly() << std::endl;
		addr = (triton::uint64) api.getConcreteRegisterValue(api.registers.x86_rip);
		inst.setTaint(false);
	}
	return 0;
}
