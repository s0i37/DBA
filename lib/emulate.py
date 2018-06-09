from unicorn import *
from unicorn.x86_const import *
from capstone import *
from sys import stdout
import struct
import string
import colorama

__version__ = '0.12'

PAGE_SIZE = 0x1000

mu = Uc(UC_ARCH_X86, UC_MODE_32)
md = Cs(CS_ARCH_X86, CS_MODE_32)


class StopExecution(BaseException):
	pass

class Cache:
	def __init__(self):
		self.mem = {}

	def get_byte(self,addr):
		return self.mem.get(addr) or 0xff

	def set_byte(self,addr,val):
		self.mem[addr] = val

	def get_word(self,addr):
		return (self.get_byte(addr+1) << 8) + self.get_byte(addr)

	def set_word(self,addr,val):
		self.mem[addr] = val % 0x100
		self.mem[addr+1] = ( val >> 8 ) % 0x100

	def get_dword(self,addr):
		return (self.get_word(addr+2) << 16) + self.get_word(addr)

	def set_dword(self,addr,val):
		self.mem[addr] = val % 0x100
		self.mem[addr+1] = ( val >> 8 ) % 0x100
		self.mem[addr+2] = ( val >> 16 ) % 0x100
		self.mem[addr+3] = ( val >> 24 ) % 0x100

	def get_qword(self,addr):
		return (self.get_dword(addr+4) << 32) + self.get_dword(addr)

	def set_qword(self,addr,val):
		self.mem[addr] = val % 0x100
		self.mem[addr+1] = ( val >> 8 ) % 0x100
		self.mem[addr+2] = ( val >> 16 ) % 0x100
		self.mem[addr+3] = ( val >> 24 ) % 0x100
		self.mem[addr+4] = ( val >> 32 ) % 0x100
		self.mem[addr+5] = ( val >> 40 ) % 0x100
		self.mem[addr+6] = ( val >> 48 ) % 0x100
		self.mem[addr+7] = ( val >> 56 ) % 0x100


class CPU:
	def __init__(self):
		self.cache = Cache()
		self.takt = 0
		self.exception = False
		self.md = md
		self.md.detail = True
		self.mu = mu
		self.ram = None	

	def set_state(self, trace_line):
		(pc,opcode,regs) = trace_line.split()
		self.takt = int( pc.split(':')[0] )
		self.eip_before = int( pc.split(':')[1], 16 )
		self.thread_id = int( pc.split(':')[2], 16 )
		self.opcode = opcode[1:-1].decode('hex')
		(self.eax_before, self.ecx_before, self.edx_before, self.ebx_before, self.esp_before, self.ebp_before, self.esi_before, self.edi_before) = map( lambda v: int(v, 16), regs.split(',') )

	def get(self, regname, when='before'):
		return self.__dict__.get( CPU.get_full_register(regname) + '_' + when ) or 0xffffffff
		
	def disas(self):
		mnem = ""
		for inst in self.md.disasm(self.opcode, 0):
			mnem = "%s %s" % (inst.mnemonic, inst.op_str)
			break
		return mnem

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

	def execute(self):	
		max_attempts = 5
		try:
			self.mu.reg_write(UC_X86_REG_EAX, self.eax_before)
			self.mu.reg_write(UC_X86_REG_ECX, self.ecx_before)
			self.mu.reg_write(UC_X86_REG_EDX, self.edx_before)
			self.mu.reg_write(UC_X86_REG_EBX, self.ebx_before)
			self.mu.reg_write(UC_X86_REG_ESP, self.esp_before)
			self.mu.reg_write(UC_X86_REG_EBP, self.ebp_before)
			self.mu.reg_write(UC_X86_REG_ESI, self.esi_before)
			self.mu.reg_write(UC_X86_REG_EDI, self.edi_before)
			self.mu.emu_start(self.eip_before, 0, 0, 1)
			self.mu.emu_stop()
			self.eax_after = self.mu.reg_read(UC_X86_REG_EAX)
			self.ecx_after = self.mu.reg_read(UC_X86_REG_ECX)
			self.edx_after = self.mu.reg_read(UC_X86_REG_EDX)
			self.ebx_after = self.mu.reg_read(UC_X86_REG_EBX)
			self.esp_after = self.mu.reg_read(UC_X86_REG_ESP)
			self.ebp_after = self.mu.reg_read(UC_X86_REG_EBP)
			self.esi_after = self.mu.reg_read(UC_X86_REG_ESI)
			self.edi_after = self.mu.reg_read(UC_X86_REG_EDI)
			self.eip_after = self.mu.reg_read(UC_X86_REG_EIP)
			self.exception = False
		except Exception as e:
			self.mu.emu_stop()
			self.exception = True
			print colorama.Fore.LIGHTBLACK_EX + "[!] %s: %s" % ( self.disas(), str(e) ) + colorama.Fore.RESET

		readed_registers = set()
		writed_registers = set()
		for inst in self.md.disasm(self.opcode, 0):
			(regs_read, regs_write) = inst.regs_access()
			break
		for reg_read_id in regs_read:
			readed_registers.add( inst.reg_name(reg_read_id) )
		for reg_write_id in regs_write:
			writed_registers.add( inst.reg_name(reg_write_id) )

		return (readed_registers, writed_registers)

class RAM:
	def __init__(self):
		self.mu = mu
		self.mu.hook_add(UC_HOOK_MEM_READ, self.access)
		self.mu.hook_add(UC_HOOK_MEM_WRITE, self.access)
		self.mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_READ_INVALID | UC_HOOK_MEM_WRITE_INVALID, self.error)
		self.readed_cells = set()
		self.writed_cells = set()
		self.allocated_regions = set()
		self.cpu = None

	def save_state(self, trace_line):
		(pc,address,direction,value) = trace_line.split()
		address = int( address[1:-1], 16 )

		try:
			if len(value[2:]) == 1:
				value = struct.pack( "B", int(value,16) )
			elif len(value[2:]) == 2:
				value = struct.pack( "<H", int(value,16) )
			elif len(value[2:]) == 4:
				value = struct.pack( "<I", int(value,16) )
		except:
			value = None

		if value:
			if direction == '->':
				self.save(address, value)
			elif direction == '<-':
				self.allocate(address)

	def access(self, uc, access, address, size, value, user_data):
		#print "[debug] access memory 0x%08x:%d" % (address, size)
		if access in (UC_MEM_WRITE,):
			for cell in xrange(address, address+size):
				self.writed_cells.add(cell)
			if size == 1:
				self.cpu.cache.set_byte(address,value)
			if size == 2:
				self.cpu.cache.set_word(address,value)
			if size == 4:
				self.cpu.cache.set_dword(address,value)
			if size == 8:
				self.cpu.cache.set_qword(address,value)
		else:
			for cell in xrange(address, address+size):
				self.readed_cells.add(cell)

	def error(self, uc, access, address, size, value, user_data):
		#try:
		#	self.allocate(address)
		#except:
		print colorama.Fore.RED + "[!] error allocating memory at 0x%08x" % (address,) + colorama.Fore.RESET
		pass

	def save(self, addr, val):
		if not ( addr + len(val) ) & 0xfffff000 in self.allocated_regions:
			self.allocate(addr + len(val))
		if not addr & 0xfffff000 in self.allocated_regions:
			self.allocate(addr)
		self.mu.mem_write(addr, val)

	def allocate(self, address):
		region = address & 0xfffff000
		if not region in self.allocated_regions:
			print colorama.Fore.BLUE + "[*] allocate 0x%08x" % region + colorama.Fore.RESET
			self.mu.mem_map( region, PAGE_SIZE )
			self.allocated_regions.add( region )

	def free(self):
		for region in self.allocated_regions:
			self.mu.mem_unmap(region, PAGE_SIZE)
			print colorama.Fore.BLUE + "[*] free 0x%08x" % (region,) + colorama.Fore.RESET
			self.allocated_regions.remove(region)


cpu = CPU()
ram = RAM()
ram.cpu = cpu

def execute(trace):
	instruction_loaded = False
	while True:
		line = trace.readline()
		if line.find('{') != -1:
			if instruction_loaded:
				trace.seek(-len(line), 1)
				break
			cpu.set_state(line)
			instruction_loaded = True
		elif line.find('[0x') != -1:
			ram.save_state(line)
		else:
			continue
		

	cpu.instruction = cpu.disas()

	if cpu.takt and not cpu.takt % 1000:
		stdout.write("\r" + " "*75)
		stdout.write( colorama.Fore.CYAN + "\r[*] %d:0x%08x: %s" % (cpu.takt, cpu.eip_before, cpu.instruction) + colorama.Fore.RESET )
		stdout.flush()
		
	#if cpu.instruction.split()[0] in ('ret', 'call'):
	#	return False

	if cpu.instruction.split()[0] == 'sysenter':
		print colorama.Fore.CYAN + "[*] %d:sysenter (EAX=0x%x)" % (cpu.takt, cpu.eax_before) + colorama.Fore.RESET

	ram.save(cpu.eip_before, cpu.opcode)
	ram.readed_cells = set()
	ram.writed_cells = set()
	used_registers = cpu.execute()
	used_memory = (ram.readed_cells, ram.writed_cells)

	#ram.free()

	return (cpu, used_registers, used_memory)

