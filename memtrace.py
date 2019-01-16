#!/usr/bin/python
# -*- coding: utf-8 -*-
from lib.emulate import Trace, StopExecution
from sys import argv, stdout
from os import path


HEAP_ALLOCATOR = 0x0808F1B8


if len(argv) != 2:
	print "%s trace.txt" % argv[0]
	exit()

WHITESPACE_PADDING_SIZE = 0x50
trace_file = argv[1]

class Pages:
	data = [0]
	code = [0]

class Memory:
	heap = set()
	stack = set()
	writes = {}
	reads = {}
	modules = {}
	syscalls = []
	pages = Pages
	code = {}

def in_heap(addr):
	heap_number = 0
	for region in Memory.heap:
		heap_number += 1
		low_address, high_address = region
		if low_address <= addr <= high_address:
			return heap_number
	else:
		return False

def get_page_type(addr):
	for module,module_range in Memory.modules.items():
		low_address,high_address = module_range
		if low_address <= addr <= high_address:
			return path.basename(module)
	for page in Memory.stack:
		if page <= addr < page | 0xfff:
			return "stack"
	return "heap"


with Trace( open(trace_file) ) as trace:
	after_heap_allocate = None
	try:
		while True:
			used_registers, used_memory = None, None
			info = trace.instruction()
			if info:
				(used_registers, used_memory) = info

			if not trace.cpu.eip_before in Memory.code:
				Memory.code[trace.cpu.eip_before] = []
			Memory.code[trace.cpu.eip_before].append( {
				'opcode': trace.cpu.opcode,
				'disas': trace.cpu.disas()
			} )

			page = trace.cpu.esp_before
			page >>= 12
			page <<= 12
			Memory.stack.add(page)

			if used_memory:
				mems_r, mems_w = used_memory
				for mem_r in mems_r:
					value = trace.io.ram.get_dword(mem_r)
					if not mem_r in Memory.reads:
						Memory.reads[mem_r] = []
					Memory.reads[mem_r].append( (trace.cpu.eip_before,value) )
				for mem_w in mems_w:
					value = trace.io.ram.get_dword(mem_w)
					if not mem_w in Memory.writes:
						Memory.writes[mem_w] = []
					Memory.writes[mem_w].append( (trace.cpu.eip_before,value) )

			#if trace.cpu.eip_before == HEAP_ALLOCATOR:
			#	region_size = trace.cpu.ecx_before
			#	after_heap_allocate = trace.cpu.eip_before + len(trace.cpu.opcode)
			#elif trace.cpu.eip_before == after_heap_allocate:
			#	region = trace.cpu.eax_before
			#	Memory.heap.add( (region, region_size) )
			#	print "[+] heap allocate 0x%08x %d bytes" % (region, region_size)
			#	after_heap_allocate == None

	except StopExecution:
		for module,region in trace.modules.items():
			Memory.modules[module] = (region[0],region[1])

addresses = Memory.writes.keys() + Memory.reads.keys()
addresses.sort()
for addr in addresses:
	if addr >= max( Memory.pages.data ) + WHITESPACE_PADDING_SIZE:
		addr //= WHITESPACE_PADDING_SIZE
		Memory.pages.data.append(addr * WHITESPACE_PADDING_SIZE)
Memory.pages.data.pop(0)

eips = Memory.code.keys()
eips.sort()
for eip in eips:
	if eip >= max( Memory.pages.code ) + WHITESPACE_PADDING_SIZE:
		eip //= WHITESPACE_PADDING_SIZE
		Memory.pages.code.append(eip * WHITESPACE_PADDING_SIZE)
Memory.pages.code.pop(0)


def create_html(outfile='out.html'):
	out = open(outfile, 'w')
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
	for page in Memory.pages.data:
		page_type = get_page_type(page)
		stdout.write("\r[*] data region 0x%08x" % page)
		stdout.flush()
		out.write("<tr><td><a name='data0x%(page)08x'>%(type)s.0x%(page)08x: </a></td>" % { 'page':page, 'type':page_type })
		addr = page
		while True:
			# ===SLOWLY===
			#if addr in Memory.writes.keys():
			#	operation_type = 'w'
			#	operation_count_writes = len( Memory.writes[addr] )
			#	val = "%08X" % Memory.writes[addr][0][1]
			#	instructions_writes = Memory.writes[addr]
			#	del Memory.writes[addr]
			#if addr in Memory.reads.keys():
			#	if not val:
			#		operation_type = 'r'
			#		val = "%08X" % Memory.reads[addr][0][1]
			#	operation_count_reads = len( Memory.reads[addr] )
			#	instructions_reads = Memory.reads[addr]
			#	del Memory.reads[addr]

			operation_count_reads = 1
			instructions_reads = [[1,1]]
			operation_type = 'r'
			val = "00000000"

			if val:
				if operation_type == 'w':
					css_color_graient = operation_count_writes * 16 if operation_count_writes < 16 else 255
					css_color_write = "#ff%02x%02x" % (0xff-css_color_graient, 0xff-css_color_graient)
					heap_number = in_heap(addr)
					if heap_number:
						out.write("<td class='heap%(heap_no)d' style='background-color:%(color)s'><div class='byte'>%(value)s</div></td>" % { 'heap_no': heap_number%2, 'color':css_color_write, 'value': val[-2:] })
					else:
						out.write("<td style='background-color:%(color)s'><div class='byte'>%(value)s</div></td>" % { 'color': css_color_write, 'value': val[-2:] })
				elif operation_type == 'r':
					css_color_graient = operation_count_reads * 16 if operation_count_reads < 16 else 255
					css_color_read = "#%02xff%02x" % (0xff-css_color_graient, 0xff-css_color_graient)
					heap_number = in_heap(addr)
					if heap_number:
						out.write("<td class='heap%(heap_no)d' style='background-color:%(color)s'><div class='byte'>%(value)s</div></td>" % { 'heap_no': heap_number%2, 'color':css_color_read, 'value': val[-2:] })
					else:
						out.write("<td style='background-color:%(color)s'><div class='byte'>%(value)s</div></td>" % { 'color': css_color_read, 'value': val[-2:] })
				val = val[:-2]
			else:
				heap_number = in_heap(addr)
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
	for page in Memory.pages.code:
		eip = page
		while True:
			if eip in Memory.code.keys():
				stdout.write("\r[*] code 0x%08x" % eip)
				stdout.flush()
				executions = len( Memory.code[eip] )
				opcode = Memory.code[eip][0]['opcode']
				disas = Memory.code[eip][0]['disas']
				css_color_gradient = executions * 10 if executions * 10 < 255 else 255
				css_color_executions = "#ff%02x%02x" % (0xff-css_color_gradient, 0xff-css_color_gradient)
				if mem_r or mem_w:
					out.write('<tr style="background-color:%(color)s"><td class="states">%(exec_count)d</td><td><a name="code0x%(addr)08x">0x%(addr)08x</a></td><td>%(opcode)s</td><td><a href="#"><code class="instr">%(instr)s</code></a></td></tr>' % { 'color': css_color_executions, 'exec_count': executions, 'addr': eip, 'opcode': opcode.encode('hex'), 'instr': disas })
				else:
					out.write('<tr style="background-color:%(color)s"><td class="states">%(exec_count)d</td><td><a name="code0x%(addr)08x">0x%(addr)08x</a></td><td>%(opcode)s</td><td><code class="instr">%(instr)s</code></td></tr>' % { 'color': css_color_executions, 'exec_count': executions, 'addr':eip, 'opcode': opcode.encode('hex'), 'instr': disas })
				eip += len(opcode)
			else:
				out.write('<tr><td></td><td><a name="code0x%(addr)08x">0x%(addr)08x</a></td><td>**</td><td>**</td></tr>' % { 'addr': eip })
				eip += 1
			if eip >= page + WHITESPACE_PADDING_SIZE:
				break
	out.write("</tbody></table></div>")
	out.close()


create_html()

'''
TODO:
сделать поддержку экспорта символов
*значения памяти и адреса инструкций записывать в базу - т.к. даже для /bin/ls файл получается слишком большой.
*нужен маленький веб-сервер, который будет извлекать значения памяти и адреса инструкций из базы веб-странице.
*сервер можно реализовать прямо в memtrace.py
'''