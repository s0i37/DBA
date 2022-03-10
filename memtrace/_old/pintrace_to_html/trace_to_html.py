from sys import argv
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

class Trace:
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
		return "unknown"


def load_trace( trace_file ):
	trace = Trace()

	with open(trace_file, 'rb') as f:
		for line in f.read().split("\r\n"):
			if line.find("module") != -1:
				m = re.match("[^\s]+ ([^\s]+) ([^\s]+) (.*)", line)
				if m:
					low_address, high_address, module = m.groups()
					low_address = int( low_address[2:10], 16 )
					high_address = int( high_address[2:10], 16 )
					trace.modules[module] = (low_address,high_address)
			elif line.find("alloc") != -1:
				m = re.match('alloc\(([^)]*)\): (.*)', line)
				if m:
					size, region = m.groups()
					size = int( size )
					region = int( region[2:10], 16 )
					if size > 0x10000:
						continue
					trace.heap.add( (region, region+size) )
			else:
				m = re.match("^([^:]*): \(([^\)]+)\)\[([^\]]+)\] {([^}]+)}.*\(([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+)\)", line)
				if m:
					eip, number,threadid, opcodes, eax,edx,ecx,ebx,esi,edi,ebp,esp = m.groups()
					eip = int( eip[2:10], 16 )
					try:
						trace.code[eip].append( [ opcodes, (eax,edx,ecx,ebx,esi,edi,ebp,esp), (number,threadid), (), () ] )
					except:
						trace.code[eip] = [ [ opcodes, (eax,edx,ecx,ebx,esi,edi,ebp,esp), (number,threadid), (), () ] ]
				if line.find("<-") != -1:
					m = re.match('^([^:]*):.*\[([^]]*)\].*<- ([^\s]*).*\(([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+)\)', line)
					if m:
						eip, addr, value, eax,edx,ecx,ebx,esi,edi,ebp,esp = m.groups()
						eip = int( eip[2:10], 16 )
						addr = int( addr[2:10], 16 )
						value = int( value[2:10], 16 )
						trace.code[eip][-1:][0][4] = (addr,value)
						try:	trace.memory_writes[addr].append( (eip,value) )
						except:	trace.memory_writes[addr] = [ (eip,value) ]
						trace.stack.add( int( esp[2:10], 16 ) & 0xfffff000 )
				elif line.find("->") != -1:
					m = re.match('^([^:]*):.*\[([^]]*)\]([^\s]*) ->.*\(([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+)\)', line)
					if m:
						eip, addr, value, eax,edx,ecx,ebx,esi,edi,ebp,esp = m.groups()
						eip = int( eip[2:10], 16 )
						addr = int( addr[2:10], 16 )
						value = int( value[2:10], 16 )
						trace.code[eip][-1:][0][3] = (addr,value)
						try:	trace.memory_reads[addr].append( (eip,value) )
						except:	trace.memory_reads[addr] = [ (eip,value) ]
						trace.stack.add( int( esp[2:10], 16 ) & 0xfffff000 )
				elif line.find("!!") != -1:
					m = re.match( "^([^:]*):.*\(([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+)\)", line )
					if m:
						eip, eax,edx,ecx,ebx,esi,edi,ebp,esp = m.groups()
						syscall_number = int( eax[2:10], 16 )
						syscall_stack = int( edx[2:10], 16 )
						trace.syscalls.append( (syscall_number,syscall_stack) )


	addresses = trace.memory_writes.keys() + trace.memory_reads.keys()
	addresses.sort()
	for addr in addresses:
		if addr >= max( trace.data_pages ) + WHITESPACE_PADDING_SIZE:
			trace.data_pages.append( addr & (0x100000000 - WHITESPACE_PADDING_SIZE) )
	trace.data_pages.pop(0)

	eips = trace.code.keys()
	eips.sort()
	for eip in eips:
		if eip >= max( trace.code_pages ) + WHITESPACE_PADDING_SIZE:
			trace.code_pages.append( eip & (0x100000000 - WHITESPACE_PADDING_SIZE) )
	trace.code_pages.pop(0)

	return trace

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






def text_print():
	trace = load_trace( trace_file )
	val = ""
	for page in data_pages:
		print "page 0x%08x" % (page)
		print ("0x%08x" % page) + ": ",
		addr = page
		while addr < page + 0x1000:		
			if addr in memory_writes.keys():
				val = "%08X" % memory_writes[addr]

			if val:
				if trace.in_heap(addr):
					print ( "(%s)" % val[-2:] ),
				else:
					print val[-2:],
				val = val[:-2]
			else:
				if trace.in_heap(addr):
					print "(**)",
				else:
					print "**",

			addr += 1
			if not addr % 0x10:
				print ""
				print ("0x%08x" % addr) + ": ",
		print "\n"

def html_print(trace_file):
	trace = load_trace( trace_file )
	val = ""
	operation_count_reads = 0
	print '''
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
	'''
	print "<div id='data'><table><tbody>"
	for page in trace.data_pages:
		page_type = trace.get_page_type(page)
		print  "<tr><td><a name='data0x%(page)08x'>%(type)s.0x%(page)08x: </a></td>" % { 'page':page, 'type':page_type }
		addr = page
		while True:
			if addr in trace.memory_writes.keys():
				operation_type = 'w'
				operation_count_writes = len( trace.memory_writes[addr] )
				val = "%08X" % trace.memory_writes[addr][0][1]
				instructions_writes = trace.memory_writes[addr]
				del trace.memory_writes[addr]
			if addr in trace.memory_reads.keys():
				if not val:
					operation_type = 'r'
					val = "%08X" % trace.memory_reads[addr][0][1]
				operation_count_reads = len( trace.memory_reads[addr] )
				instructions_reads = trace.memory_reads[addr]
				del trace.memory_reads[addr]

			if val:
				if operation_type == 'w':
					css_color_graient = operation_count_writes * 16 if operation_count_writes < 16 else 255
					css_color_write = "#ff%02x%02x" % (0xff-css_color_graient, 0xff-css_color_graient)
					writes = ';'.join( map( lambda x: "0x%08x:0x%08X" % (x[0], x[1]) , instructions_writes ) ) or ''
					if operation_count_reads:
						reads = ';'.join( map( lambda x: "0x%08x:0x%08X" % (x[0], x[1]) , instructions_reads ) )
					else:
						reads = ''
					heap_number = trace.in_heap(addr)
					if heap_number:
						print "<td class='heap%(heap_no)d' style='background-color:%(color)s'><div class='byte' r='%(r_ops)s' w='%(w_ops)s'>%(value)s</div></td>" % { 'heap_no': heap_number%2, 'color':css_color_write, 'r_ops': reads ,'w_ops': writes, 'value': val[-2:] }
					else:
						print "<td style='background-color:%(color)s'><div class='byte' r='%(r_ops)s' w='%(w_ops)s'>%(value)s</div></td>" % { 'color': css_color_write, 'r_ops': reads ,'w_ops': writes, 'value': val[-2:] }
				elif operation_type == 'r':
					css_color_graient = operation_count_reads * 16 if operation_count_reads < 16 else 255
					css_color_read = "#%02xff%02x" % (0xff-css_color_graient, 0xff-css_color_graient)
					reads = ';'.join( map( lambda x: "0x%08x:0x%08X" % (x[0], x[1]) , instructions_reads ) ) or ''
					heap_number = trace.in_heap(addr)
					if heap_number:
						print "<td class='heap%(heap_no)d' style='background-color:%(color)s'><div class='byte' r='%(r_ops)s' w='%(w_ops)s'>%(value)s</div></td>" % { 'heap_no': heap_number%2, 'color':css_color_read, 'r_ops': reads ,'w_ops': '', 'value': val[-2:] }
					else:
						print "<td style='background-color:%(color)s'><div class='byte' r='%(r_ops)s' w='%(w_ops)s'>%(value)s</div></td>" % { 'color': css_color_read, 'r_ops': reads ,'w_ops': '', 'value': val[-2:] }
						
				val = val[:-2]
			else:
				heap_number = trace.in_heap(addr)
				if heap_number:
					print "<td class='heap%d'>**</td>" % (heap_number%2)
				else:
					print "<td>**</td>"

			addr += 1
			if addr >= page + WHITESPACE_PADDING_SIZE:
				break
			if not addr % 0x10:
				print "</tr>"
				print "<tr><td><a name='data0x%(addr)08x'>%(type)s.0x%(addr)08x: </a></td>" % { 'addr': addr, 'type': page_type }
		print "</tr>"
	print "</tbody></table></div>"

	print "<div id='code'><table><tbody>"
	dis = capstone.Cs( capstone.CS_ARCH_X86, capstone.CS_MODE_32 )
	for page in trace.code_pages:
		eip = page
		while True:
			if eip in trace.code.keys():
				states = []
				r_ops = []
				w_ops = []
				rw_addr = 0
				executions = 0
				for opcodes, regs, opts, mem_r, mem_w in trace.code[eip]:
					executions += 1
					eax,edx,ecx,ebx,esi,edi,ebp,esp = regs
					number, threadid = opts
					states.append( "%s:%s:%s,%s,%s,%s,%s,%s,%s,%s" % (number,threadid, eax,edx,ecx,ebx,esi,edi,ebp,esp) )
					if mem_r:
						rw_addr,rw_val = mem_r
						r_ops.append( "0x%08x:0x%08X" % (rw_addr, rw_val) )
					elif mem_w:
						rw_addr,rw_val = mem_w
						w_ops.append( "0x%08x:0x%08X" % (rw_addr, rw_val) )
					disasm = '??'
					opcode = opcodes[:2]
					next_instruction_offset = 6
					for instr in dis.disasm( opcodes.decode('hex'), eip ):
						disasm = "%(command)s %(operands)s" % { 'command': instr.mnemonic, 'operands': instr.op_str }
						opcode = str(instr.bytes).encode('hex')
						next_instruction_offset = len( instr.bytes )
						break
				css_color_gradient = executions * 10 if executions * 10 < 255 else 255
				css_color_executions = "#ff%02x%02x" % (0xff-css_color_gradient, 0xff-css_color_gradient)
				if rw_addr:
					print '<tr style="background-color:%(color)s"><td class="states" states="%(states)s">%(exec_count)d</td><td><a name="code0x%(addr)08x">0x%(addr)08x</a></td><td>%(opcode)s</td><td><a href="#"><code class="instr" r="%(r_ops)s" w="%(w_ops)s">%(instr)s</code></a></td></tr>' % { 'color': css_color_executions, 'exec_count': executions, 'addr': eip, 'opcode': opcode, 'instr': disasm, 'states': ';'.join(states), 'r_ops': ';'.join(r_ops), 'w_ops': ';'.join(w_ops) }
				else:
					print '<tr style="background-color:%(color)s"><td class="states" states="%(states)s">%(exec_count)d</td><td><a name="code0x%(addr)08x">0x%(addr)08x</a></td><td>%(opcode)s</td><td><code class="instr">%(instr)s</code></td></tr>' % { 'color': css_color_executions, 'exec_count': executions, 'addr':eip, 'opcode': opcode, 'instr': disasm, 'states': ';'.join(states) }
				eip += next_instruction_offset
			else:
				print '<tr><td></td><td><a name="code0x%(addr)08x">0x%(addr)08x</a></td><td>**</td><td>**</td></tr>' % { 'addr': eip }
				eip += 1
			if eip >= page + WHITESPACE_PADDING_SIZE:
				break
	print "</tbody></table></div>"

print "<pre>"
#print_modules()
#print_memory_pages()
#print_stack_pages()
#print_heap_regions()
#print_syscalls()
print "</pre>"
html_print( trace_file )

