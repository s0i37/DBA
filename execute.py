from unicorn import *
from unicorn.x86_const import *
from capstone import *
import struct
import string
import colorama
import sys
import traceback

PAGE_SIZE = 0x1000
ins_count = 0

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

class StopExecution(BaseException):
	pass


class CPU:
	def __init__(self, line):
		(pc,opcode,regs) = line.split()
		self.eip = int( pc.split(':')[0], 16 )
		self.thread_id = int( pc.split(':')[1] )
		self.opcode = opcode[1:-1].decode('hex')
		(self.eax, self.ecx, self.edx, self.ebx, self.esp, self.ebp, self.esi, self.edi) = map( lambda v: int(v, 16), regs.split(',') )

	def get(self, register):
		return self.__dict__[register]

	def show_registers(self, group=''):
		if group == '':
			for register in ['eax','ecx','edx','ebx','esp','ebp','esi','edi','eip']:
				print colorama.Fore.GREEN + "%s 0x%08x" % ( register.upper(), self.__dict__[register] ) + colorama.Fore.RESET
		elif group == 'mmx':
			for register in ['xmm0','xmm1','xmm2','xmm3','xmm4','xmm5','xmm6','xmm7']:
				print colorama.Fore.GREEN + "%s 0x%08x" % ( register.upper(), self.__dict__[register] ) + colorama.Fore.RESET
		elif group == 'sse':
			for register in ['st0','st1','st2','st3','st4','st5','st6','st7']:
				print colorama.Fore.GREEN + "%s 0x%08x" % ( register.upper(), self.__dict__[register] ) + colorama.Fore.RESET

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
			break
		for reg_read_id in inst.regs_read:
			read.add( inst.reg_name(reg_read_id) )
		for reg_write_id in inst.regs_write:
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
		print "[debug] access memory 0x%08x:%d" % (address, size)
		if access in (UC_MEM_WRITE,):
			for i in range(size):
				EMU.write.add( address + i )
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
		print colorama.Fore.BLUE + "[i] allocate 0x%08x" % address + colorama.Fore.RESET
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
				#print( colorama.Fore.BLUE + "[i] free(0x%08x)" % (region,) + colorama.Fore.RESET )
			except Exception as e:
				print(str(e))
		EMU.allocated_regions = set()

	@staticmethod
	def get_used_memory(cpu):
		EMU.read = set()
		EMU.write = set()
		
		#try:
		if not cpu.eip & 0xfffff000 in EMU.allocated_regions:
			EMU._alloc_region(cpu.eip)
		EMU.mu.mem_write(cpu.eip, cpu.opcode)
		#except Exception as e:
		#	print str(e)

		max_attempts = 5
		while True:
			try:
				max_attempts -= 1
				if max_attempts <= 0:
					#print(colorama.Back.RED + "[!] error emulation\n"  + colorama.Back.RESET)
					break

				EMU.mu.reg_write(UC_X86_REG_EAX, cpu.eax)
				EMU.mu.reg_write(UC_X86_REG_ECX, cpu.ecx)
				EMU.mu.reg_write(UC_X86_REG_EDX, cpu.edx)
				EMU.mu.reg_write(UC_X86_REG_EBX, cpu.ebx)
				EMU.mu.reg_write(UC_X86_REG_ESP, cpu.esp)
				EMU.mu.reg_write(UC_X86_REG_EBP, cpu.ebp)
				EMU.mu.reg_write(UC_X86_REG_ESI, cpu.esi)
				EMU.mu.reg_write(UC_X86_REG_EDI, cpu.edi)
				EMU.mu.emu_start(cpu.eip, 0, 0, 1)
				EMU.mu.emu_stop()
				break
			except KeyboardInterrupt:
				EMU.mu.emu_stop()
				break
			except Exception as e:
				EMU.mu.emu_stop()
				EMU.read = set()
				EMU.write = set()
				print str(e)
		return (EMU.read, EMU.write)

	@staticmethod
	def show_registers():
		for reg,val in {
			'EAX': EMU.mu.reg_read(UC_X86_REG_EAX),
			'ECX': EMU.mu.reg_read(UC_X86_REG_ECX),
			'EDX': EMU.mu.reg_read(UC_X86_REG_EDX),
			'EBX': EMU.mu.reg_read(UC_X86_REG_EBX),
			'ESP': EMU.mu.reg_read(UC_X86_REG_ESP),
			'EBP': EMU.mu.reg_read(UC_X86_REG_EBP),
			'ESI': EMU.mu.reg_read(UC_X86_REG_ESI),
			'EDI': EMU.mu.reg_read(UC_X86_REG_EDI),
		}.items():
			print colorama.Fore.GREEN + "%s: 0x%08x" % (reg,val) + colorama.Fore.RESET


def analyze(used_registers, used_memory):
	pass

def execute(line):
	global ins_count
	try:
		cpu = CPU(line)
	except:
		return False

	#cpu.show_registers()
	instruction = cpu.disas()
	print instruction
	
	if ins_count and not ins_count % 1000:
		print colorama.Fore.LIGHTBLACK_EX + "[*][%d] 0x%08x: %s" % (ins_count, cpu.eip, instruction) + colorama.Fore.RESET
	
	if instruction.split()[0] in ('call','ret') or instruction.startswith('j'):
		#print(colorama.Fore.YELLOW + "\t[i] ignore" + colorama.Fore.RESET)
		pass
	if instruction.split()[0] == 'sysenter':
		print colorama.Fore.GREEN + "[*][%d] sysenter (EAX=0x%x)" % (ins_count, cpu.eax) + colorama.Fore.RESET

	used_registers = cpu.get_used_registers()
	used_memory = EMU.get_used_memory(cpu)
	EMU.show_registers()

	analyze(used_registers, used_memory)
	#print colorama.Fore.LIGHTCYAN_EX + "[*][%d] 0x%08x: %s" % (ins_count, cpu.eip, instruction) + colorama.Fore.RESET
	
	#EMU.free_regions()
	
	ins_count += 1
	del cpu
	return True


trace_file = sys.argv[1]

with open( trace_file ) as trace:
	for line in trace:
		try:
			if execute(line):
				break
		except KeyboardInterrupt:
			break
		except StopExecution:
			break
		#except Exception as e:
		#	a,b,c = sys.exc_info()
		#	print traceback.extract_tb(c)
		#	print str(e)
