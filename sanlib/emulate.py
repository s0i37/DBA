from unicorn import *
from unicorn.x86_const import *
from capstone import *
import struct
import string
import colorama

__version__ = '0.11'

PAGE_SIZE = 0x1000

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

class StopExecution(BaseException):
	pass


class CPU:
	def __init__(self):
		self.cache = {}
		self.ins_count = 0

	def execute(self, line):
		self.ins_count += 1
		(pc,opcode,regs) = line.split()
		self.eip_before = int( pc.split(':')[0], 16 )
		self.thread_id = int( pc.split(':')[1], 16 )
		self.opcode = opcode[1:-1].decode('hex')
		(self.eax_before, self.ecx_before, self.edx_before, self.ebx_before, self.esp_before, self.ebp_before, self.esi_before, self.edi_before) = map( lambda v: int(v, 16), regs.split(',') )

	def get(self, regname, when='before'):
		return self.__dict__[ CPU.get_full_register(regname) + '_' + when ]
		
	def disas(self):
		mnem = ""
		for inst in md.disasm(self.opcode, 0):
			mnem = "%s %s" % (inst.mnemonic, inst.op_str)
			break
		return mnem

	def get_used_registers(self):
		read = set()
		write = set()
		for inst in md.disasm(self.opcode, 0):
			(regs_read, regs_write) = inst.regs_access()
			break
		for reg_read_id in regs_read:
			read.add( inst.reg_name(reg_read_id) )
		for reg_write_id in regs_write:
			write.add( inst.reg_name(reg_write_id) )
		return (read, write)

	@staticmethod
	def get_full_register(register):
		register = register.lower()
		if register in ('eax', 'ax', 'ah', 'al'):
			return 'eax'
		elif register in ('ecx', 'cx', 'ch', 'cl'):
			return 'ecx'
		elif register in ('edx', 'dx', 'dh', 'dl'):
			return 'edx'
		elif register in ('ebx', 'bx', 'bh', 'bl'):
			return 'ebx'
		elif register in ('esp', 'sp'):
			return 'esp'
		elif register in ('ebp', 'bp'):
			return 'ebp'
		elif register in ('esi', 'si'):
			return 'esi'
		elif register in ('edi', 'di'):
			return 'edi'
		else:
			return ''

class EMU:
	def _mem_access(uc, access, address, size, value, user_data):
		global cpu
		#print "[debug] access memory 0x%08x:%d" % (address, size)
		if access in (UC_MEM_WRITE,):
			for i in range(size):
				EMU.write.add( address + i )
			cpu.cache[address] = value
		else:
			for i in range(size):
				EMU.read.add( address + i )

	def _mem_add_page(uc, access, address, size, value, user_data):
		try:
			EMU._alloc_region(address)
		except:
			print colorama.Back.RED + "[!] error allocating memory at 0x%08x" % (address,) + colorama.Back.RESET

	@staticmethod
	def _alloc_region(address):
		address &= 0xfffff000
		print colorama.Fore.BLUE + "[*] allocate 0x%08x" % address + colorama.Fore.RESET
		EMU.mu.mem_map( address, PAGE_SIZE )
		EMU.allocated_regions.add( address )

	mu = Uc(UC_ARCH_X86, UC_MODE_32)
	mu.hook_add(UC_HOOK_MEM_READ, _mem_access)
	mu.hook_add(UC_HOOK_MEM_WRITE, _mem_access)
	mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_READ_INVALID | UC_HOOK_MEM_WRITE_INVALID, _mem_add_page)

	read = set()
	write = set()
	allocated_regions = set()

	@staticmethod
	def free_regions():
		for region in EMU.allocated_regions:
			try:
				EMU.mu.mem_unmap(region, PAGE_SIZE)
				print colorama.Fore.BLUE + "[*] free 0x%08x" % (region,) + colorama.Fore.RESET
			except Exception as e:
				print str(e)
		EMU.allocated_regions = set()

	@staticmethod
	def get_used_memory(cpu):
		EMU.read = set()
		EMU.write = set()

		if not ( cpu.eip_before + len(cpu.opcode) ) & 0xfffff000 in EMU.allocated_regions:
			EMU._alloc_region( cpu.eip_before + len(cpu.opcode) )
		if not cpu.eip_before & 0xfffff000 in EMU.allocated_regions:
			EMU._alloc_region(cpu.eip_before)
				
		try:
			EMU.mu.mem_write(cpu.eip_before, cpu.opcode)
		except Exception as e:
			print hex(cpu.eip_before)
			raise e

		max_attempts = 5
		while True:
			try:
				cpu.has_emulated = False
				max_attempts -= 1
				if max_attempts <= 0:
					print(colorama.Fore.RED + "[!] error emulation %s" % cpu.disas() + colorama.Fore.RESET)
					break

				EMU.mu.reg_write(UC_X86_REG_EAX, cpu.eax_before)
				EMU.mu.reg_write(UC_X86_REG_ECX, cpu.ecx_before)
				EMU.mu.reg_write(UC_X86_REG_EDX, cpu.edx_before)
				EMU.mu.reg_write(UC_X86_REG_EBX, cpu.ebx_before)
				EMU.mu.reg_write(UC_X86_REG_ESP, cpu.esp_before)
				EMU.mu.reg_write(UC_X86_REG_EBP, cpu.ebp_before)
				EMU.mu.reg_write(UC_X86_REG_ESI, cpu.esi_before)
				EMU.mu.reg_write(UC_X86_REG_EDI, cpu.edi_before)
				EMU.mu.emu_start(cpu.eip_before, 0, 0, 1)
				EMU.mu.emu_stop()
				cpu.eax_after = EMU.mu.reg_read(UC_X86_REG_EAX)
				cpu.ecx_after = EMU.mu.reg_read(UC_X86_REG_ECX)
				cpu.edx_after = EMU.mu.reg_read(UC_X86_REG_EDX)
				cpu.ebx_after = EMU.mu.reg_read(UC_X86_REG_EBX)
				cpu.esp_after = EMU.mu.reg_read(UC_X86_REG_ESP)
				cpu.ebp_after = EMU.mu.reg_read(UC_X86_REG_EBP)
				cpu.esi_after = EMU.mu.reg_read(UC_X86_REG_ESI)
				cpu.edi_after = EMU.mu.reg_read(UC_X86_REG_EDI)
				cpu.eip_after = EMU.mu.reg_read(UC_X86_REG_EIP)
				cpu.has_emulated = True
				break
			except Exception as e:
				EMU.mu.emu_stop()
				EMU.read = set()
				EMU.write = set()
				print colorama.Fore.LIGHTBLACK_EX + "[!] " + str(e) + colorama.Fore.RESET
		return (EMU.read, EMU.write)


cpu = CPU()

def execute(line):
	global cpu
	try:
		cpu.execute(line)
	except Exception as e:
		print str(e)
		return False

	cpu.instruction = cpu.disas()
	
	if cpu.ins_count and not cpu.ins_count % 1000:
		print colorama.Fore.LIGHTCYAN_EX + "[%d] 0x%08x: %s" % (cpu.ins_count, cpu.eip_before, cpu.instruction) + colorama.Fore.RESET
	
	if cpu.instruction.split()[0] in ('ret', 'call'):
		#return False
		pass

	if cpu.instruction.split()[0] == 'sysenter':
		print colorama.Fore.GREEN + "[%d] sysenter (EAX=0x%x)" % (cpu.ins_count, cpu.eax_before) + colorama.Fore.RESET

	used_registers = cpu.get_used_registers()
	used_memory = EMU.get_used_memory(cpu)
	#EMU.free_regions()
	
	return (cpu, used_registers, used_memory)

