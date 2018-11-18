from unicorn import *
from unicorn.x86_const import *
from capstone import *
from sys import stdout
import struct
import string
import colorama

__version__ = '0.13'

PAGE_SIZE = 0x1000

mu = Uc(UC_ARCH_X86, UC_MODE_32)
md = Cs(CS_ARCH_X86, CS_MODE_32)


class StopExecution(BaseException):
	pass

class Cache:
	def __init__(self):
		self.L2 = {}

	def __setitem__(self,attr,val):
		addr = attr
		for i in xrange( len(val) ):
			self.set_byte( addr+i, ord(val[i]) )

	def get_byte(self,addr):
		return self.L2.get(addr) or 0x00

	def set_byte(self,addr,val):
		self.L2[addr] = val

	def get_word(self,addr):
		return (self.get_byte(addr+1) << 8) + self.get_byte(addr)

	def set_word(self,addr,val):
		self.L2[addr] = val % 0x100
		self.L2[addr+1] = ( val >> 8 ) % 0x100

	def get_dword(self,addr):
		return (self.get_word(addr+2) << 16) + self.get_word(addr)

	def set_dword(self,addr,val):
		self.L2[addr] = val % 0x100
		self.L2[addr+1] = ( val >> 8 ) % 0x100
		self.L2[addr+2] = ( val >> 16 ) % 0x100
		self.L2[addr+3] = ( val >> 24 ) % 0x100

	def get_qword(self,addr):
		return (self.get_dword(addr+4) << 32) + self.get_dword(addr)

	def set_qword(self,addr,val):
		self.L2[addr] = val % 0x100
		self.L2[addr+1] = ( val >> 8 ) % 0x100
		self.L2[addr+2] = ( val >> 16 ) % 0x100
		self.L2[addr+3] = ( val >> 24 ) % 0x100
		self.L2[addr+4] = ( val >> 32 ) % 0x100
		self.L2[addr+5] = ( val >> 40 ) % 0x100
		self.L2[addr+6] = ( val >> 48 ) % 0x100
		self.L2[addr+7] = ( val >> 56 ) % 0x100


class CPU:
	def __init__(self):
		self.takt = 0
		self.cache = None
		self.exception = False
		self.md = md
		self.md.detail = True
		self.mu = mu

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

	def get_used_regs(self):
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
			#print colorama.Fore.LIGHTBLACK_EX + "\n[!] %s: %s" % ( self.disas(), str(e) ) + colorama.Fore.RESET,


class MCH:
	'''
	Memory Controller Hub - memory IO
	'''
	def __init__(self):
		self.mu = mu
		self.mu.hook_add(UC_HOOK_MEM_READ, self.access)
		self.mu.hook_add(UC_HOOK_MEM_WRITE, self.access)
		self.mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_READ_INVALID | UC_HOOK_MEM_WRITE_INVALID, self.error)
		self.readed_cells = set()
		self.writed_cells = set()
		self.allocated_regions = set()
		self.cache = None
		self.ram = None

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
			elif len(value[2:]) == 8:
				value = struct.pack( "<Q", int(value,16) )
			else:
				value = None
		except:
			value = None

		if value:
			if direction == '->':
				self.save(address, value)
				self.ram[address] = value
				for cell in xrange(address, address+len(value)):
					self.readed_cells.add(cell)
			elif direction == '<-':
				self.allocate(address)
				self.ram[address] = value
				for cell in xrange(address, address+len(value)):
					self.writed_cells.add(cell)

	def access(self, uc, access, address, size, value, user_data):
		#print "[debug] access memory 0x%08x:%d" % (address, size)
		if access in (UC_MEM_WRITE,):
			for cell in xrange(address, address+size):
				self.writed_cells.add(cell)
			if size == 1:
				value = struct.pack( "B", value)
			elif size == 2:
				value = struct.pack( "<H", value)
			elif size == 4:
				value = struct.pack( "<I", value)
			elif size == 8:
				value = struct.pack( "<Q", value)
			self.cache[address] = value
		else:
			for cell in xrange(address, address+size):
				self.readed_cells.add(cell)

	def error(self, uc, access, address, size, value, user_data):
		#try:
		#	self.allocate(address)
		#except:
		#print colorama.Fore.RED + "\n[!] error allocating memory at 0x%08x" % (address,) + colorama.Fore.RESET,
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
			#print colorama.Fore.BLUE + "\n[*] allocate 0x%08x" % region + colorama.Fore.RESET,
			self.mu.mem_map( region, PAGE_SIZE )
			self.allocated_regions.add( region )

	def free(self):
		for region in self.allocated_regions:
			self.mu.mem_unmap(region, PAGE_SIZE)
			print colorama.Fore.BLUE + "\n[*] free 0x%08x" % (region,) + colorama.Fore.RESET,
			self.allocated_regions.remove(region)


class RAM:
	'''
	For only memory dump files. If taint_data not exists in cpu.cache
	'''
	def __init__(self):
		self.mem = {}

	def __setitem__(self,attr,val):
		addr = attr
		for i in xrange( len(val) ):
			self.set_byte( addr+i, ord(val[i]) )

	def get_byte(self,addr):
		return self.mem.get(addr) or 0x00

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


class Trace:
	def __init__(self, trace):
		self.trace = trace
		self.trace.seek(0,2)
		self.eof_trace = trace.tell()
		self.trace.seek(0)
		self.cpu = CPU()
		self.io = MCH()
		self.cpu.cache = self.io.cache = Cache()
		self.io.ram = RAM()
		self.breakpoints = set()
		self.callstack = {}

	def step(self):
		'''
		load instruction
		'''
		was_instruction_load = False
		while True:
			if self.trace.tell() == self.eof_trace:
				raise StopExecution
			line = self.trace.readline()
			if line.startswith('['):
				self.trace.seek(-len(line), 1)
				break
			if line.find('{') != -1:
				if was_instruction_load:
					self.trace.seek(-len(line), 1)
					break
				self.cpu.set_state(line)
				was_instruction_load = True
			elif line.find('[0x') != -1:
				self.io.save_state(line)
			else:
				continue

		self.cpu.instruction = self.cpu.disas()

	def instruction(self):
		'''
		get info about instruction (without emulation)

		:return: (usable_registers, usable_memory)
		'''
		self.io.readed_cells = set()
		self.io.writed_cells = set()
		self.step()

		if self.cpu.takt and not self.cpu.takt % 1000:
			stdout.write("\r" + " "*75)
			stdout.write( colorama.Fore.CYAN + "\r[*] %d:0x%08x: %s" % (self.cpu.takt, self.cpu.eip_before, self.cpu.instruction) + colorama.Fore.RESET )
			stdout.flush()

		used_registers = self.cpu.get_used_regs()
		used_memory = (self.io.readed_cells, self.io.writed_cells)
		return (used_registers, used_memory)

	def execute(self):
		'''
		emulate one instruction from trace

		:return: (usable_registers, usable_memory)
		'''
		self.step()

		if self.cpu.eip_before in self.breakpoints:
			print "\n[*] 0x%08x: %s   EAX=%d" % (self.cpu.eip_before, self.cpu.instruction, self.cpu.eax_before)
			print "\n".join( map( hex, self.callstack[ self.cpu.thread_id ] ) )

		if self.cpu.takt and not self.cpu.takt % 1000:
			stdout.write("\r" + " "*75)
			stdout.write( colorama.Fore.CYAN + "\r[*] %d:0x%08x: %s" % (self.cpu.takt, self.cpu.eip_before, self.cpu.instruction) + colorama.Fore.RESET )
			stdout.flush()
			
		if self.cpu.instruction.split()[0] in ('ret', 'call', 'int') or self.cpu.instruction.split()[0].startswith('j'):
			if self.cpu.instruction.split()[0] == 'call':
				try:
					self.callstack[ self.cpu.thread_id ].insert(0, self.cpu.eip_before)
				except:
					self.callstack[ self.cpu.thread_id ] = [ self.cpu.eip_before ]
			elif self.cpu.instruction.split()[0] == 'ret':
				try:
					self.callstack[ self.cpu.thread_id ].pop(0)
				except:
					pass
			return

		if self.cpu.instruction.split()[0] == 'sysenter':
			print colorama.Fore.CYAN + "\n[*] %d:sysenter (EAX=0x%x)" % (self.cpu.takt, self.cpu.eax_before) + colorama.Fore.RESET,

		self.io.save(self.cpu.eip_before, self.cpu.opcode)
		self.io.readed_cells = set()
		self.io.writed_cells = set()
		used_registers = self.cpu.get_used_regs()
		self.cpu.execute()
		used_memory = (self.io.readed_cells, self.io.writed_cells)

		#self.io.free()

		return (used_registers, used_memory)

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc_val, exc_tb):
		self.trace.close()
