import pefile
from capstone import *

class PE:
	def __init__(self, filepath):
		self.__pe = pefile.PE(filepath)
	def section(self, index):
		return self.__pe.section[index].get_data()

class Disas:
	def __init__(self, base):
		self.__disassembler = Cs( CS_ARCH_X86, CS_MODE_32 )
		self.base = base
	def disas(self, code):
		for instruction in self.__disassembler.disasm( code, self.base ):
			print "{addr}: {instr} {operands}".format( addr=instruction.address, instr=instruction.mnemonic, operands=instruction.op_str )

