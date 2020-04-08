from unicorn import *
from unicorn.x86_const import *
from capstone import *
from capstone.x86 import *
from sys import stdout
from os.path import basename
import struct
import string
import colorama

__version__ = '0.16'

PAGE_SIZE = 0x1000
#BITS = 32
BITS = 64

mu = Uc( UC_ARCH_X86, {32: UC_MODE_32, 64: UC_MODE_64}[BITS] )
md = Cs( CS_ARCH_X86, {32: CS_MODE_32, 64: CS_MODE_64}[BITS] )


class StopExecution(BaseException):
	pass

class BPX:
	def __init__(self, callback, *opts):
		self.callback = callback
		self.opts = opts

	def __call__(self, trace):
		self.callback(trace, *self.opts)


class Cache:
	def __init__(self):
		self.L2 = {}

	def __setitem__(self,attr,val):
		addr = attr
		for i in xrange( len(val) ):
			self.set_byte( addr+i, ord(val[i]) )

	def get_byte(self,addr):
		return self.L2.get(addr)

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
		self.inst = None

	def set_state(self, trace_line):
		(pc,opcode,regs) = trace_line.split()
		self.takt = int( pc.split(':')[0] )
		self.eip_before = self.pc = int( pc.split(':')[1], 16 )
		self.thread_id = int( pc.split(':')[2], 16 )
		self.opcode = opcode[1:-1].decode('hex')
		self.cache[self.pc] = self.opcode
		if BITS == 32:
			(self.eax_before, self.ecx_before, self.edx_before, self.ebx_before, self.esp_before, self.ebp_before, self.esi_before, self.edi_before) = map( lambda v: int(v, 16), regs.split(',') )
		elif BITS == 64:
			(self.rax_before, self.rcx_before, self.rdx_before, self.rbx_before, self.rsp_before, self.rbp_before, self.rsi_before, self.rdi_before) = map( lambda v: int(v, 16), regs.split(',') )
		self.eflags_before = 0 # not implemented yet
		self.inst = None

	def __getitem__(self, reg):
		if reg in ('rax','rdx','rcx','rbx','rsp','rbp','rdi','rsi'):
			return getattr(self, "{reg}_before".format(reg=reg))
		elif reg in ('eax','edx','ecx','ebx','esp','ebp','edi','esi'):
			if BITS == 32:
				return getattr(self, "{reg}_before".format(reg=reg))
			else:
				reg = CPU.get_full_register(reg)
				return getattr(self, "{reg}_before".format(reg=reg)) % 0x100000000
		elif reg in ('ax','dx','cx','bx','sp','bp','di','si'):
			reg = CPU.get_full_register(reg)
			return getattr(self, "{reg}_before".format(reg=reg)) % 0x10000
		elif reg in ('ah','dh','ch','bh'):
			reg = CPU.get_full_register(reg)
			return ( getattr(self, "{reg}_before".format(reg=reg)) >> 8 ) % 0x100
		elif reg in ('al','dl','cl','bl'):
			reg = CPU.get_full_register(reg)
			return getattr(self, "{reg}_before".format(reg=reg)) % 0x100
		else:
			return 0xffffffff

	def get(self, regname, when='before'):
		val = self.__dict__.get( CPU.get_full_register(regname) + '_' + when )
		return val if val != None else 0xffffffff

	@staticmethod
	def get_full_register(register):
		register = register.lower()
		if register in ('rax', 'eax', 'ax', 'ah', 'al'):
			return 'rax' if BITS == 64 else 'eax'
		elif register in ('rcx', 'ecx', 'cx', 'ch', 'cl'):
			return 'rcx' if BITS == 64 else 'ecx'
		elif register in ('rdx', 'edx', 'dx', 'dh', 'dl'):
			return 'rdx' if BITS == 64 else 'edx'
		elif register in ('rbx', 'ebx', 'bx', 'bh', 'bl'):
			return 'rbx' if BITS == 64 else 'ebx'
		elif register in ('rsp', 'esp', 'sp'):
			return 'rsp' if BITS == 64 else 'esp'
		elif register in ('rbp', 'ebp', 'bp'):
			return 'rbp' if BITS == 64 else 'ebp'
		elif register in ('rsi', 'esi', 'si'):
			return 'rsi' if BITS == 64 else 'esi'
		elif register in ('rdi', 'edi', 'di'):
			return 'rdi' if BITS == 64 else 'edi'
		else:
			return register

	@staticmethod
	def get_sub_registers(register):
		register = register.lower()
		for sub_registers in [ 
				['rax', 'eax', 'ax', 'ah', 'al'],
				['rdx', 'edx', 'dx', 'dh', 'dl'],
				['rcx', 'ecx', 'cx', 'ch', 'cl'],
				['rbx', 'ebx', 'bx', 'bh', 'bl'],
				['rbp', 'esp', 'sp'],
				['rsp', 'ebp', 'bp'],
				['rdi', 'edi', 'di'],
				['rsi', 'esi', 'si'],
				['r8', 'r8d', 'r8w', 'r8b'],
				['r9', 'r9d', 'r9w', 'r9b'],
				['r10', 'r10d', 'r10w', 'r10b'],
				['r11', 'r11d', 'r11w', 'r11b'],
				['r12', 'r12d', 'r12w', 'r12b'],
				['r13', 'r13d', 'r13w', 'r13b'],
				['r14', 'r14d', 'r14w', 'r14b'],
				['r15', 'r15d', 'r15w', 'r15b'],
			]:
			if register in sub_registers:
				index = sub_registers.index(register)
				if index < 3:
					return sub_registers[index:] # AX has [AH,AL]
				else:
					return [sub_registers[index]] # AH hasn't AL
		return [register]

	def disas(self):
		if not self.inst:
			self.analyze()
		return "%s %s" % (self.inst.mnemonic, self.inst.op_str)

	def analyze(self):
		for inst in self.md.disasm(self.opcode, 0):
			self.inst = inst
			break
		return self

	def get_used_regs(self):
		readed_registers = set()
		writed_registers = set()
		(regs_read, regs_write) = self.inst.regs_access()
		for reg_read_id in regs_read:
			readed_registers.add( self.inst.reg_name(reg_read_id) )
		for reg_write_id in regs_write:
			writed_registers.add( self.inst.reg_name(reg_write_id) )
		return (readed_registers, writed_registers)

	def get_used_regs__(self):
		readed_registers = set()
		writed_registers = set()
		for operand in self.inst.operands:
			if operand.type == X86_OP_REG:
				if operand.access in (CS_AC_READ, CS_AC_READ|CS_AC_WRITE):
					readed_registers.add( self.inst.reg_name( operand.value.reg ) )
				elif operand.access == CS_AC_WRITE:
					writed_registers.add( self.inst.reg_name( operand.value.reg ) )
		return (readed_registers, writed_registers)

	def analyze_operands(self):
		readed_registers = set()
		writed_registers = set()
		op = 0
		for operand in self.inst.operands:
			if operand.access == CS_AC_READ:
				access = "READ"
			elif operand.access == CS_AC_WRITE:
				access = "WRITE"
			elif operand.access == CS_AC_READ|CS_AC_WRITE:
				access = "READ|WRITE"
			else:
				access = ""
			#print "operands[{op}].access: {access}".format(op=op, access=access)

			size = operand.size
			#print "operands[{op}].size: {size}".format(op=op, size=size)
		
			if operand.type == X86_OP_REG:
				reg = self.inst.reg_name( operand.value.reg )
				#print "operands[{op}].type: REG = {reg}".format(op=op, reg=reg)
				if access == "READ":
					readed_registers.add(reg)
				elif access == "WRITE":
					writed_registers.add(reg)
				elif access == "READ|WRITE":
					readed_registers.add(reg)
					writed_registers.add(reg)
			elif operand.type == X86_OP_IMM:
				imm = operand.value.imm
				#print "operands[{op}].type: IMM = {imm}".format(op=op, imm=imm)
			elif operand.type == X86_OP_MEM:
				#print "operands[{op}].type: MEM".format(op=op)
				if operand.value.mem.disp != 0:
					pass
					#print "\t" + "operands[{op}].mem.disp: {val}".format(op=op, val=hex(operand.value.mem.disp))
				if operand.value.mem.base != 0:
					pass
					#print "\t" + "operands[{op}].mem.base: REG = {val}".format(op=op, val=instr.reg_name( operand.value.mem.base ))
			op += 1
		return (readed_registers, writed_registers)

	def execute(self):
		max_attempts = 5
		try:
			if BITS == 32:
				self.mu.reg_write(UC_X86_REG_EAX, self.eax_before)
				self.mu.reg_write(UC_X86_REG_ECX, self.ecx_before)
				self.mu.reg_write(UC_X86_REG_EDX, self.edx_before)
				self.mu.reg_write(UC_X86_REG_EBX, self.ebx_before)
				self.mu.reg_write(UC_X86_REG_ESP, self.esp_before)
				self.mu.reg_write(UC_X86_REG_EBP, self.ebp_before)
				self.mu.reg_write(UC_X86_REG_ESI, self.esi_before)
				self.mu.reg_write(UC_X86_REG_EDI, self.edi_before)
			if BITS == 64:
				self.mu.reg_write(UC_X86_REG_RAX, self.eax_before)
				self.mu.reg_write(UC_X86_REG_RCX, self.ecx_before)
				self.mu.reg_write(UC_X86_REG_RDX, self.edx_before)
				self.mu.reg_write(UC_X86_REG_RBX, self.ebx_before)
				self.mu.reg_write(UC_X86_REG_RSP, self.esp_before)
				self.mu.reg_write(UC_X86_REG_RBP, self.ebp_before)
				self.mu.reg_write(UC_X86_REG_RSI, self.esi_before)
				self.mu.reg_write(UC_X86_REG_RDI, self.edi_before)
			self.mu.emu_start(self.eip_before, 0, 0, 1)
			self.mu.emu_stop()
			if BITS == 32:
				self.eax_after = self.mu.reg_read(UC_X86_REG_EAX)
				self.ecx_after = self.mu.reg_read(UC_X86_REG_ECX)
				self.edx_after = self.mu.reg_read(UC_X86_REG_EDX)
				self.ebx_after = self.mu.reg_read(UC_X86_REG_EBX)
				self.esp_after = self.mu.reg_read(UC_X86_REG_ESP)
				self.ebp_after = self.mu.reg_read(UC_X86_REG_EBP)
				self.esi_after = self.mu.reg_read(UC_X86_REG_ESI)
				self.edi_after = self.mu.reg_read(UC_X86_REG_EDI)
				self.eip_after = self.mu.reg_read(UC_X86_REG_EIP)
			if BITS == 64:
				self.eax_after = self.mu.reg_read(UC_X86_REG_RAX)
				self.ecx_after = self.mu.reg_read(UC_X86_REG_RCX)
				self.edx_after = self.mu.reg_read(UC_X86_REG_RDX)
				self.ebx_after = self.mu.reg_read(UC_X86_REG_RBX)
				self.esp_after = self.mu.reg_read(UC_X86_REG_RSP)
				self.ebp_after = self.mu.reg_read(UC_X86_REG_RBP)
				self.esi_after = self.mu.reg_read(UC_X86_REG_RSI)
				self.edi_after = self.mu.reg_read(UC_X86_REG_RDI)
				self.eip_after = self.mu.reg_read(UC_X86_REG_RIP)
			self.eflags_after = 0 # not implemented yet
			self.exception = False
		except Exception as e:
			self.mu.emu_stop()
			self.exception = True
			#print colorama.Fore.LIGHTBLACK_EX + "\n[!] %s: %s" % ( self.disas(), str(e) ) + colorama.Fore.RESET,

class Page:
	R = 4
	W = 2
	X = 1
	def __init__(self, addr):
		self.start = (addr >> 12) << 12
		self.size = 4096
		self.end = self.start + self.size
		self.perm = 0

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
		self.pages = {}
		self.cache = None
		self.ram = None

	def save_state(self, trace_line):
		(pc,address,direction,value) = trace_line.split()
		pc = int(pc.split(':')[1], 16)
		address = int( address[1:-1], 16 )
		size = len(value[2:])/2

		try:
			if size == 1:
				value = struct.pack( "B", int(value,16) )
			elif size == 2:
				value = struct.pack( "<H", int(value,16) )
			elif size == 4:
				value = struct.pack( "<I", int(value,16) )
			elif size == 8:
				value = struct.pack( "<Q", int(value,16) )
			else:
				value = None
		except:
			value = None

		if value:
			if direction == '->':
				base = self.allocate(address)
				self.pages[base].perm |= Page.R
				#self.save(address, value) # for Unicorn
				self.ram[address] = value
				for cell in xrange(address, address+size):
					self.readed_cells.add(cell)
			elif direction == '<-':
				base = self.allocate(address)
				self.pages[base].perm |= Page.W
				self.ram[address] = value
				for cell in xrange(address, address+size):
					self.writed_cells.add(cell)

		base = self.allocate(pc)
		self.pages[base].perm |= Page.R
		self.pages[base].perm |= Page.X

	def save_memory(self, trace_line):
		(pc,address,value) = trace_line.split()
		address = int( address[1:-2], 16 )
		for offset in xrange(0, len(value), 2):
			byte = struct.pack( "B", int(value[offset:offset+2], 16) )
			self.ram[address+offset/2] = byte

	def access(self, uc, access, address, size, value, user_data):
		#print "[debug] access memory 0x%08x:%d" % (address, size)
		if access in (UC_MEM_WRITE,):
			for cell in xrange(address, address+size):
				self.writepagesd_cells.add(cell)
			if size == 1:
				value = struct.pack( "B", value)
			elif size == 2:
				value = struct.pack( "<H", value)
			elif size == 4:
				value = struct.pack( "<I", value)
			elif size == 8:
				value = struct.pack( "<q", value)
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
		high_region = ( addr + len(val) ) >> 12
		high_region <<= 12
		low_region = addr >> 12
		low_region <<= 12
		if not high_region in self.allocated_regions:
			self.allocate(addr + len(val))
		if not low_region in self.allocated_regions:
			self.allocate(addr)
		self.mu.mem_write(addr, val)

	def allocate(self, address):
		region = address >> 12
		region <<= 12
		if not region in self.allocated_regions:
			#print colorama.Fore.BLUE + "\n[*] allocate 0x%08x" % region + colorama.Fore.RESET,
			#self.mu.mem_map( region, PAGE_SIZE )
			self.allocated_regions.add( region )
			self.pages[region] = Page(region)
		return region

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
		size = len(val)
		for i in xrange(size):
			self.set_byte( addr+i, ord(val[size-i-1]) )

	def get_byte(self,addr):
		return self.mem.get(addr)

	def set_byte(self,addr,val):
		self.mem[addr] = val

	def get_word(self,addr):
		try:
			return (self.get_byte(addr+1) << 8) + self.get_byte(addr)
		except:
			return None

	def set_word(self,addr,val):
		self.mem[addr] = val % 0x100
		self.mem[addr+1] = ( val >> 8 ) % 0x100

	def get_dword(self,addr):
		try:
			return (self.get_word(addr+2) << 16) + self.get_word(addr)
		except:
			return None

	def set_dword(self,addr,val):
		self.mem[addr] = val % 0x100
		self.mem[addr+1] = ( val >> 8 ) % 0x100
		self.mem[addr+2] = ( val >> 16 ) % 0x100
		self.mem[addr+3] = ( val >> 24 ) % 0x100

	def get_qword(self,addr):
		try:
			return (self.get_dword(addr+4) << 32) + self.get_dword(addr)
		except:
			return None

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
		self.cpu = CPU()
		self.io = MCH()
		self.cpu.cache = self.io.cache = Cache()
		self.io.ram = RAM()
		self.breakpoints = {}
		self.callstack = {}
		self.modules = {}
		self.symbols = {}
		self.reverse = False
		self.__line = ''
		#self.__buf = ''
		#self.i1 = 0
		#self.i2 = 0

	def cont(self):
		while True:
			self.step()

	def step(self):
		'''
		load instruction
		'''
		was_instruction_loaded = False

		'''
		if not self.__buf:
			self.__buf = self.trace.read()
		'''

		while True:
			'''
			if not self.__line:
				self.i2 += self.__buf[self.i1:self.i1+1000].find('\n')
				self.__line = self.__buf[self.i1:self.i2]
				self.i2 += 1
				self.i1 = self.i2
			if not self.__line:
				raise StopExecution
			'''

			
			if not self.__line:
				self.__line = self.trace.readline()
			if not self.__line:
				raise StopExecution

			
			#print self.__line
			try:
				if self.__line.startswith('[#]'):
					self.__line = ''
					continue
				elif self.__line.startswith('[*]'):
					if self.__line.find('[*] module') != -1:
						(_,_,module,start,end) = self.__line.split()
						self.modules[basename(module)] = [ int(start,16), int(end,16) ]
					elif self.__line.find('[*] function') != -1:
						(_,_,symbol,start,end) = self.__line.split()
						self.symbols[symbol] = [ int(start,16), int(end,16) ]
					self.__line = ''
					continue
				elif self.__line.find('{') != -1:
					if was_instruction_loaded:
						break
					self.cpu.set_state(self.__line)
					was_instruction_loaded = True
				elif self.__line.find('[0x') != -1 and ( self.__line.find('->') != -1 or self.__line.find('<-') != -1):
					self.io.save_state(self.__line)
				elif self.__line.find('[0x') != -1 and self.__line.find(':') != -1:
					self.io.save_memory(self.__line)
				else:
					self.__line = ''
					continue
			except Exception as e:
				#print str(e)
				#print self.__line
				#exit()
				pass
			self.__line = ''


		if self.cpu.pc in self.breakpoints.keys():
			self.breakpoints[self.cpu.pc](self)

		if self.cpu.takt and not self.cpu.takt % 10000:
			stdout.write("\r" + " "*75)
			stdout.write( colorama.Fore.CYAN + "\r[*] %d:0x%08x: %s" % (self.cpu.takt, self.cpu.eip_before, self.cpu.disas()) + colorama.Fore.RESET )
			stdout.flush()

	def instruction(self):
		'''
		get info about instruction (without emulation)

		:return: (usable_registers, usable_memory)
		'''
		self.io.readed_cells = set()
		self.io.writed_cells = set()
		self.step()

		used_registers = self.cpu.analyze().get_used_regs()
		used_memory = (self.io.readed_cells, self.io.writed_cells)
		return (used_registers, used_memory)

	def execute(self):
		'''
		emulate one instruction from trace
		set self.cpu.REG_after

		:return: (usable_registers, usable_memory)
		'''
		self.step()

		if self.cpu.eip_before in self.breakpoints.keys():
			print "\n[*] 0x%08x: %s   EAX=%d" % (self.cpu.eip_before, self.cpu.disas(), self.cpu.eax_before)
			print "\n".join( map( hex, self.callstack[ self.cpu.thread_id ] ) )

		if self.cpu.takt and not self.cpu.takt % 1000:
			stdout.write("\r" + " "*75)
			stdout.write( colorama.Fore.CYAN + "\r[*] %d:0x%08x: %s" % (self.cpu.takt, self.cpu.eip_before, self.cpu.disas()) + colorama.Fore.RESET )
			stdout.flush()
			
		if self.cpu.disas().split()[0] in ('ret', 'call', 'int') or self.cpu.disas().split()[0].startswith('j'):
			if self.cpu.disas().split()[0] == 'call':
				try:
					self.callstack[ self.cpu.thread_id ].insert(0, self.cpu.eip_before)
				except:
					self.callstack[ self.cpu.thread_id ] = [ self.cpu.eip_before ]
			elif self.cpu.disas().split()[0] == 'ret':
				try:
					self.callstack[ self.cpu.thread_id ].pop(0)
				except:
					pass
			return # problem with emulation call/jmp/ret/int instructions

		if self.cpu.disas().split()[0] == 'sysenter':
			print colorama.Fore.CYAN + "\n[*] %d:sysenter (EAX=0x%x)" % (self.cpu.takt, self.cpu.eax_before) + colorama.Fore.RESET,

		self.io.save(self.cpu.eip_before, self.cpu.opcode)
		self.io.readed_cells = set()
		self.io.writed_cells = set()
		used_registers = self.cpu.analyze().get_used_regs()
		self.cpu.execute()
		used_memory = (self.io.readed_cells, self.io.writed_cells)

		#self.io.free()

		return (used_registers, used_memory)

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc_val, exc_tb):
		self.trace.close()


def memmap(trace):
	bases = trace.io.pages.keys()
	bases.sort()
	for base in bases:
		yield trace.io.pages[base]

def read_mem(trace, addr, size):
	_bytes = []
	for a in xrange(addr, addr+size):
		byte = trace.io.ram.get_byte(a)
		if byte == None:
			byte = trace.io.cache.get_byte(a)
		_bytes.append(byte)
	return _bytes
