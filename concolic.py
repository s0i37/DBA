#!/usr/bin/python2
import argparse
import taint
from lib.emulate import CPU
from re import match

parser = argparse.ArgumentParser( description='data flow analisys tool' )
parser.add_argument("tracefile", type=str, help="trace.log")
parser.add_argument("-symbols", type=str, default='', help="symbols.json")
parser.add_argument("-symbolize_mem", type=str, dest="taint_mem", default='', help="symbolize [takt:]address:size (1200:0x402000:10)")
parser.add_argument("-symbolize_reg", type=str, dest="taint_reg", default='', help="symbolize takt:reg (1200:ESI)")
parser.add_argument("-symbolize_data", type=str, dest="taint_data", default='', help='symbolize data: "GET / HTTP/1.1" or input.bin')
parser.add_argument("-symbolize_offset", type=int, dest="taint_offset", default=0, help="from offset (subdata)")
parser.add_argument("-symbolize_size", type=int, dest="taint_size", default=0, help="size bytes (subdata)")
parser.add_argument("-from_addr", type=int, default=0, help="print tainted instruction only from address")
parser.add_argument("-to_addr", type=int, default=0, help="print tainted instruction only to address")
parser.add_argument("-from_takt", type=int, default=0, help="print tainted instruction only after takt")
parser.add_argument("-to_takt", type=int, default=0, help="print tainted instruction only before takt")
parser.add_argument("-module", type=str, default='', help="show tainted instruction just this module")
parser.add_argument("-n", dest= "limit", type=int, default=0, help="count of print tainted instructions")
parser.add_argument("-v", dest="verbose", type=bool, default=False, help="verbose")
args = parser.parse_args()

BITS = 64
symbolic_memory = {}
symbolic_registers = {}
ast = {}

class Thread:
	def __init__(self):
		self.condition = ''
		self.compare = ''
	def __find_tainted_subreg(self, reg):
		sub_regs = CPU.get_sub_registers( CPU.get_full_register(reg) )
		sub_regs.reverse()
		for reg in sub_regs:
			if hasattr(self, reg):
				return reg
	def __getitem__(self, reg):
		#import pdb;pdb.set_trace()
		if reg in ('rax','rdx','rcx','rbx','rsp','rbp','rdi','rsi'):
			return getattr(self, reg)
		elif reg in ('eax','edx','ecx','ebx','esp','ebp','edi','esi'):
			if BITS == 32:
				return getattr(self, reg)
			else:
				reg = self.__find_tainted_subreg(reg)
				return "{reg} % 0x100000000".format(reg=getattr(self, reg))
		elif reg in ('ax','dx','cx','bx','sp','bp','di','si'):
			reg = self.__find_tainted_subreg(reg)
			return "{reg} % 0x10000".format(reg=getattr(self, reg))
		elif reg in ('ah','dh','ch','bh'):
			reg = self.__find_tainted_subreg(reg)
			return "( {reg} >> 8 ) % 0x100".format(reg=getattr(self, reg))
		elif reg in ('al','dl','cl','bl'):
			reg = self.__find_tainted_subreg(reg)
			return "{reg} % 0x100".format(reg=getattr(self, reg))

	def __setitem__(self, reg, val):
		#print type(val), reg, val
		setattr(self, reg, val)


def symbolize_string(string_ptr, thread_id):
	i = 0
	for ptr in xrange(string_ptr, string_ptr+len(settings['taint_data'])):
		if not settings['taint_size'] or settings['taint_offset'] <= i < settings['taint_offset'] + settings['taint_size']:
			symbolic_memory[ptr] = "X%d"%i
		i += 1
	if settings['verbose']:
		print colorama.Fore.YELLOW + "[+] symbolized data in 0x%08x: %s" % (string_ptr, settings['taint_data']) + colorama.Fore.RESET

def solve(ast):
	pass

def ir(instruction):
	mnem = instruction.split()[0]
	if mnem in ('mov', 'movzx'):
		return "op2"
	elif mnem == 'add':
		return "(op1 + op2)"
	elif mnem == 'sub':
		return "(op1 - op2)"
	elif mnem == 'xor':
		return "(op1 ^ op2)"
	elif mnem == 'and':
		return "(op1 & op2)"
	elif mnem == 'or':
		return "(op1 | op2)"
	elif mnem == 'shl':
		return "(op1 << op2)"
	elif mnem == 'shr':
		return "(op1 >> op2)"

	elif mnem in ('cmp', 'test'):
		return "op1 ? op2"
	elif mnem in ('jl', 'jb'):
		return "cond <"
	elif mnem in ('jnb', 'jnl'):
		return "cond >="
	elif mnem in ('jbe', 'jle'):
		return "cond <="
	elif mnem in ('jnbe', 'jnle'):
		return "cond >"
	elif mnem in ('jz', 'je'):
		return "cond =="
	elif mnem in ('jnz', 'jne'):
		return "cond !="
	elif mnem == 'js':
		return "cond <"
	elif mnem == 'jns':
		return "cond >"
	elif mnem == 'jp':
		return "cond %2=="
	elif mnem == 'jnp':
		return "cond %2!="
	elif mnem == 'jo':
		pass
	elif mnem == 'jno':
		pass
	elif mnem == 'jcxz':
		pass
	elif mnem == 'jecxz':
		pass
	elif mnem == 'jrcxz':
		pass

def get_operands(instruction):
	mnem = instruction.split()[0]
	operands = ' '.join( instruction.split()[1:] )
	operands_type = {
		'op1': {
			'reg': '',
			'mem': '',
			'imm': ''
		},
		'op2': {
			'reg': '',
			'mem': '',
			'imm': ''
		}
	}
	directions = ['op2', 'op1']
	for operand in operands.split(','):
		direction = directions.pop()
		if operand.find('[') != -1:
			operands_type[direction]['mem'] = operand
		elif match('^[a-z]+', operand.strip()):
			operands_type[direction]['reg'] = operand
		elif match('^[0-9]+', operand.strip()):
			operands_type[direction]['imm'] = operand
	return operands_type
	
def concolic(access, instruction):
	expression = ir(instruction)
	operands = get_operands(instruction)
	if not expression:
		return
	
	try:	symbolic_registers[trace.cpu.thread_id]
	except:	symbolic_registers[trace.cpu.thread_id] = Thread()

	(tainted_regs, tainted_mems, spread_regs, spread_mems) = access

	#symbolic
	for tainted_reg in tainted_regs:
		ast = symbolic_registers[trace.cpu.thread_id][tainted_reg]
		if operands['op1']['reg'].find(tainted_reg) != -1:
			expression = expression.replace("op1", "({ast})".format(ast=ast))
		elif operands['op2']['reg'].find(tainted_reg) != -1:
			expression = expression.replace("op2", "({ast})".format(ast=ast))
		break
	for tainted_mem in tainted_mems:
		ast = symbolic_memory[tainted_mem]
		if operands['op1']['mem']:
			expression = expression.replace("op1", "({ast})".format(ast=ast))
		if operands['op2']['mem']:
			expression = expression.replace("op2", "({ast})".format(ast=ast))
		break

	#concrete
	if expression.find('op1') != -1:
		for (op_type,op_val) in operands['op1'].items():
			if op_val:
				if op_type == 'imm':
					expression = expression.replace('op1', "{concrete}".format(concrete=op_val.strip()))
				elif op_type == 'reg':
					expression = expression.replace('op1', "{concrete}".format(concrete=hex(trace.cpu[op_val.strip()])))
	if expression.find('op2') != -1:
		for (op_type,op_val) in operands['op2'].items():
			if op_val:
				if op_type == 'imm':
					expression = expression.replace('op2', "{concrete}".format(concrete=op_val.strip()))
				elif op_type == 'reg':
					expression = expression.replace('op2', "{concrete}".format(concrete=hex(trace.cpu[op_val.strip()])))

	for spread_reg in spread_regs:
		symbolic_registers[trace.cpu.thread_id][spread_reg] = expression
		break
	for spread_mem in spread_mems:
		symbolic_memory[spread_mem] = expression
		break

	if expression.find('cond ') != -1:
		expression = symbolic_registers[trace.cpu.thread_id].condition.replace('?', expression[5:])
		
	if expression.find('?') != -1:
		symbolic_registers[trace.cpu.thread_id].condition = "{ast}".format(ast=expression)
	
	print instruction + "\t\t" + expression


if __name__ == '__main__':
	settings = vars(args)
	taint.settings = settings
	taint.init(args.taint_mem, args.taint_reg)
	trace = taint.Trace( open(args.tracefile) )
	if args.taint_data:
		settings['on_found_string'].append(symbolize_string)
	for access in taint.analyze(trace):
		concolic(access, trace.cpu.disas())
