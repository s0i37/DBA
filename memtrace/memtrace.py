#!/usr/bin/python
# -*- coding: utf-8 -*-
from sys import argv, stdout
import re
import os
#import syscalls as SYSCALLS
import capstone

if len(argv) != 2:
	print "%s trace_file.txt" % argv[0]
	exit()

WHITESPACE_PADDING_SIZE = 0x50
pwd = os.path.dirname( os.path.realpath(__file__) )
trace_file = argv[1]

class Memtrace:
	def __init__(self):
		self.heap = set()
		self.stack = set()
		self.memory_writes = {}
		self.memory_reads = {}
		self.modules = {}
		self.syscalls = []
		self.data_pages = [0]
		self.code_pages = [0]
		self.code = {}

	def in_heap(self, addr):
		heap_number = 0
		for region in self.heap:
			heap_number += 1
			low_address, high_address = region
			if low_address <= addr <= high_address:
				return heap_number
		else:
			return False

	def get_page_type(self,addr):
		for module,module_range in self.modules.items():
			low_address,high_address = module_range
			if low_address <= addr <= high_address:
				return module.replace("\\","/").split("/").pop()
		for page in self.stack:
			if page <= addr < page | 0xfff:
				return "stack"
		return "heap"


def get_memtrace( trace_file ):
	memtrace = Memtrace()

	with open(trace_file) as f:
		for line in f:
			try:
				if line.startswith('[#]'):
					continue
				elif line.startswith('[*] module'):
					(_, _, modulename, start, end) = line.split()
					start = int(start, 16)
					end = int(end, 16)
					memtrace.modules[modulename] = (start,end)
				elif line.startswith('[*] function'):
					(_, _, symbol, start, end) = line.split()
					start = int(start, 16)
					end = int(end, 16)
				# will never happen
				elif line.startswith('[*] allocation'):
					region = 0
					size = 0
					memtrace.heap.add( (region, region+size) )
				elif line.find('{') != -1:
					(eip,opcode,regs) = line.split()
					takt = int( eip.split(':')[0] )
					(eip,thread) = map( lambda x: int(x, 16), eip.split(':')[1:] )
					opcode = opcode[1:-1]
					(eax,ecx,edx,ebx,esp,ebp,esi,edi) = map( lambda x: int(x,16), regs.split(',') )
					try:
						memtrace.code[eip].append( [ opcode, (eax,ecx,edx,ebx,esp,ebp,esi,edi), (takt,thread), (), () ] )
					except:
						memtrace.code[eip] = [ [ opcode, (eax,ecx,edx,ebx,esp,ebp,esi,edi), (takt,thread), (), () ] ]
				elif line.find('[') != -1:
					(eip,memory,direction,value) = line.split()
					takt = int( eip.split(':')[0] )
					(eip,thread) = map( lambda x: int(x, 16), eip.split(':')[1:] )
					memory = int( memory[1:-1], 16 )
					value = int( value, 16 )
					page = esp
					page >>= 12
					page <<= 12
					if direction == "<-":
						memtrace.code[eip][-1:][0][4] = (memory,value)
						try:	memtrace.memory_writes[memory].append( (eip,value) )
						except:	memtrace.memory_writes[memory] = [ (eip,value) ]
						memtrace.stack.add(page)
					elif direction == "->":
						memtrace.code[eip][-1:][0][3] = (memory,value)
						try:	memtrace.memory_reads[memory].append( (eip,value) )
						except:	memtrace.memory_reads[memory] = [ (eip,value) ]
						memtrace.stack.add(page)
			except Exception as e:
				#print str(e)
				#print line
				continue

	addresses = memtrace.memory_writes.keys() + memtrace.memory_reads.keys()
	addresses.sort()
	for addr in addresses:
		if addr >= max( memtrace.data_pages ) + WHITESPACE_PADDING_SIZE:
			addr //= WHITESPACE_PADDING_SIZE
			memtrace.data_pages.append(addr * WHITESPACE_PADDING_SIZE)
	memtrace.data_pages.pop(0)

	eips = memtrace.code.keys()
	eips.sort()
	for eip in eips:
		if eip >= max( memtrace.code_pages ) + WHITESPACE_PADDING_SIZE:
			eip //= WHITESPACE_PADDING_SIZE
			memtrace.code_pages.append(eip * WHITESPACE_PADDING_SIZE)
	memtrace.code_pages.pop(0)

	return memtrace

def print_modules(trace):
	for module,module_range in trace.modules.items():
		low_address,high_address = module_range
		print "0x%08x-0x%08x: %s" % (low_address,high_address, module)

def print_heap_regions(trace):
	for region in trace.heap:
		low_address, high_address = region
		print "region 0x%08x-0x%08x" % (low_address, high_address)

def print_stack_pages(trace):
	for page in trace.stack:
		print "stack: 0x%08x" % page

def print_memory_pages(trace):
	for page in trace.data_pages:
		print "page 0x%08X" % page

def print_syscalls(trace):
	for syscall in trace.syscalls:
		syscall_number, syscall_stack = syscall
		print "syscall: %s 0x%04x 0x%08X" % ( SYSCALLS.NT32_windows_7_sp1[syscall_number], syscall_number, syscall_stack )



def create_html(trace_file, outfile='out.html'):
	out = open(outfile, 'w')
	memtrace = get_memtrace( trace_file )
	val = ""
	operation_count_reads = 0
	out.write('''
		<link rel="stylesheet" href="static/jquery-ui/themes/smoothness/jquery-ui.min.css">
		<link rel="stylesheet" href="static/highlightjs/styles/default.css">
		<script src="static/jquery/dist/jquery.js"></script>
		<script src="static/jquery-ui/jquery-ui.js"></script>
		<script src="static/highlightjs/highlight.pack.js"></script>
		<script src="static/script.js?v=0.10"></script>
		<style>
		body { background-color: white; color: black; }
		#data { float: left; width: 60%; height: 100%; overflow-y: scroll; }
		#code { float: left; width: 40%; height: 100%; overflow-y: scroll; }
		#data table, #code table {width: 100%; }
		.heap0 { border: 2px solid blue; }
		.heap1 { border: 2px solid black; }
		.state, .instructionr, .instructionw, .memoryr, .memoryw { font-size: 9pt; }
		</style>
		<div id="dialog"></div>
	''')
	out.write("<div id='data'><table><tbody>")
	for page in memtrace.data_pages:
		page_type = memtrace.get_page_type(page)
		stdout.write("\r[*] data page 0x%08x" % page)
		stdout.flush()
		out.write("<tr><td><a name='data0x%(page)08x'>%(type)s.0x%(page)08x: </a></td>" % { 'page':page, 'type':page_type })
		addr = page
		while True:
			if addr in memtrace.memory_writes.keys():
				operation_type = 'w'
				operation_count_writes = len( memtrace.memory_writes[addr] )
				val = "%08X" % memtrace.memory_writes[addr][0][1]
				instructions_writes = memtrace.memory_writes[addr]
				del memtrace.memory_writes[addr]
			if addr in memtrace.memory_reads.keys():
				if not val:
					operation_type = 'r'
					val = "%08X" % memtrace.memory_reads[addr][0][1]
				operation_count_reads = len( memtrace.memory_reads[addr] )
				instructions_reads = memtrace.memory_reads[addr]
				del memtrace.memory_reads[addr]

			if val:
				if operation_type == 'w':
					css_color_graient = operation_count_writes * 16 if operation_count_writes < 16 else 255
					css_color_write = "#ff%02x%02x" % (0xff-css_color_graient, 0xff-css_color_graient)
					writes = ';'.join( map( lambda x: "0x%08x:0x%08X" % (x[0], x[1]) , instructions_writes ) ) or ''
					if operation_count_reads:
						reads = ';'.join( map( lambda x: "0x%08x:0x%08X" % (x[0], x[1]) , instructions_reads ) )
					else:
						reads = ''
					heap_number = memtrace.in_heap(addr)
					if heap_number:
						out.write("<td class='heap%(heap_no)d' style='background-color:%(color)s'><div class='byte' r='%(r_ops)s' w='%(w_ops)s'>%(value)s</div></td>" % { 'heap_no': heap_number%2, 'color':css_color_write, 'r_ops': reads ,'w_ops': writes, 'value': val[-2:] })
					else:
						out.write("<td style='background-color:%(color)s'><div class='byte'>%(value)s</div></td>" % { 'color': css_color_write, 'value': val[-2:] })
					#reads
					#writes
				elif operation_type == 'r':
					css_color_graient = operation_count_reads * 16 if operation_count_reads < 16 else 255
					css_color_read = "#%02xff%02x" % (0xff-css_color_graient, 0xff-css_color_graient)
					reads = ';'.join( map( lambda x: "0x%08x:0x%08X" % (x[0], x[1]) , instructions_reads ) ) or ''
					heap_number = memtrace.in_heap(addr)
					if heap_number:
						out.write("<td class='heap%(heap_no)d' style='background-color:%(color)s'><div class='byte' r='%(r_ops)s' w='%(w_ops)s'>%(value)s</div></td>" % { 'heap_no': heap_number%2, 'color':css_color_read, 'r_ops': reads ,'w_ops': '', 'value': val[-2:] })
					else:
						out.write("<td style='background-color:%(color)s'><div class='byte'>%(value)s</div></td>" % { 'color': css_color_read, 'value': val[-2:] })
					#reads
				val = val[:-2]
			else:
				heap_number = memtrace.in_heap(addr)
				if heap_number:
					out.write("<td class='heap%d'>**</td>" % (heap_number%2))
				else:
					out.write("<td>**</td>")

			addr += 1
			if addr >= page + WHITESPACE_PADDING_SIZE:
				break
			if not addr % 0x10:
				out.write("</tr>")
				out.write("<tr><td><a name='data0x%(addr)08x'>%(type)s.0x%(addr)08x: </a></td>" % { 'addr': addr, 'type': page_type })
		out.write("</tr>")
	out.write("</tbody></table></div>")

	out.write("<div id='code'><table><tbody>")
	dis = capstone.Cs( capstone.CS_ARCH_X86, capstone.CS_MODE_32 )
	for page in memtrace.code_pages:
		eip = page
		while True:
			if eip in memtrace.code.keys():
				stdout.write("\r[*] code 0x%08x" % eip)
				stdout.flush()
				states = []
				r_ops = []
				w_ops = []
				rw_addr = 0
				executions = 0
				for opcode, regs, opts, mem_r, mem_w in memtrace.code[eip]:
					executions += 1
					eax,ecx,edx,ebx,esp,ebp,esi,edi = regs
					number, threadid = opts
					states.append( "%s:%s:%s,%s,%s,%s,%s,%s,%s,%s" % (number,threadid, eax,ecx,edx,ebx,esp,ebp,esi,edi) )
					if mem_r:
						rw_addr,rw_val = mem_r
						r_ops.append( "0x%08x:0x%08X" % (rw_addr, rw_val) )
					elif mem_w:
						rw_addr,rw_val = mem_w
						w_ops.append( "0x%08x:0x%08X" % (rw_addr, rw_val) )
					disasm = '??'
					opcode = opcode[:2]
					next_instruction_offset = 6
					for instr in dis.disasm( opcode.decode('hex'), eip ):
						disasm = "%(command)s %(operands)s" % { 'command': instr.mnemonic, 'operands': instr.op_str }
						opcode = str(instr.bytes).encode('hex')
						next_instruction_offset = len( instr.bytes )
						break
				css_color_gradient = executions * 10 if executions * 10 < 255 else 255
				css_color_executions = "#ff%02x%02x" % (0xff-css_color_gradient, 0xff-css_color_gradient)
				#r_ops
				#w_ops
				#states
				if rw_addr:
					out.write('<tr style="background-color:%(color)s"><td class="states">%(exec_count)d</td><td><a name="code0x%(addr)08x">0x%(addr)08x</a></td><td>%(opcode)s</td><td><a href="#"><code class="instr">%(instr)s</code></a></td></tr>' % { 'color': css_color_executions, 'exec_count': executions, 'addr': eip, 'opcode': opcode, 'instr': disasm })
				else:
					out.write('<tr style="background-color:%(color)s"><td class="states">%(exec_count)d</td><td><a name="code0x%(addr)08x">0x%(addr)08x</a></td><td>%(opcode)s</td><td><code class="instr">%(instr)s</code></td></tr>' % { 'color': css_color_executions, 'exec_count': executions, 'addr':eip, 'opcode': opcode, 'instr': disasm })
				eip += next_instruction_offset
			else:
				out.write('<tr><td></td><td><a name="code0x%(addr)08x">0x%(addr)08x</a></td><td>**</td><td>**</td></tr>' % { 'addr': eip })
				eip += 1
			if eip >= page + WHITESPACE_PADDING_SIZE:
				break
	out.write("</tbody></table></div>")
	o.close()

#print "<pre>"
#print_modules()
#print_memory_pages()
#print_stack_pages()
#print_heap_regions()
#print_syscalls()
#print "</pre>"
create_html( trace_file )

'''
TODO:
сделать поддержку экспорта символов
*значения памяти и адреса инструкций записывать в базу - т.к. даже для /bin/ls файл получается слишком большой.
*нужен маленький веб-сервер, который будет извлекать значения памяти и адреса инструкций из базы веб-странице.
*сервер можно реализовать прямо в memtrace.py
!дизасм идёт по одному байту
'''