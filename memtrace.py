#!/usr/bin/python
# -*- coding: utf-8 -*-
from lib.emulate import Trace, StopExecution
from flask import Flask, request, url_for, render_template, Response, stream_with_context
from flask_cors import CORS
import sqlite3
import argparse
import pydot
from sys import stdout
from os import path
import json


HEAP_ALLOCATOR = 0x0808F1B8
WHITESPACE_PADDING_SIZE = 0x50

parser = argparse.ArgumentParser( description='data flow analisys tool' )
parser.add_argument("tracefile", type=str, help="trace.txt")
parser.add_argument("-from_takt", type=int, default=0, help="trace memory only after takt")
parser.add_argument("-to_takt", type=int, default=0, help="trace memory only before takt")
args = parser.parse_args()

c = sqlite3.connect("memory.db", check_same_thread=False)
cc = c.cursor()
code_flow = {}
calls = {}
tree = []

def db_init():
	cc.execute("CREATE TABLE cpu(takt BIGINT, thread_id INTEGER, eax BIGINT, ecx BIGINT, edx BIGINT, ebx BIGINT, esp BIGINT, ebp BIGINT, esi BIGINT, edi BIGINT, eip BIGINT)")
	cc.execute("CREATE TABLE mem(takt BIGINT, addr BIGINT, value BIGINT, access_type CHARACTER(1))")
	cc.execute("CREATE TABLE reg(takt BIGINT, reg CHARACTER(3), value BIGINT, access_type CHARACTER(1))")
	c.commit()

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

class Flow:
	code = {}
	blocks = {}
	functions = []

flow = Flow()

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

def get_node(eip):
	node_id = max(flow.blocks.keys()) + 1
	for node in flow.blocks:
		if eip in flow.blocks[node]['range']:
			node_id = node
			break
	return node_id

def load_trace(tracefile):
	with Trace( open(tracefile) ) as trace:
		after_heap_allocate = None
		node_id = 0
		is_call = False
		is_jump = False
		is_ret = False
		functions = []
		try:
			while True:
				used_registers, used_memory = None, None
				info = trace.instruction()
				if info:
					(used_registers, used_memory) = info

				if args.from_takt and trace.cpu.takt < args.from_takt:
					continue
				if args.to_takt and trace.cpu.takt > args.to_takt:
					break

				if not trace.cpu.eip_before in Memory.code:
					Memory.code[trace.cpu.eip_before] = []
				Memory.code[trace.cpu.eip_before].append( {
					'opcode': trace.cpu.opcode,
					'disas': trace.cpu.disas()
				} )

				# function and basic blocks recognition
				if not trace.cpu.eip_before in flow.code: # uncovered code
					if is_jump:
						flow.blocks[node_id]['to'] = get_node(trace.cpu.eip_before)
						node_id = flow.blocks[node_id]['to']
					elif is_ret:
						node_id = get_node(trace.cpu.eip_before)

					if is_call:
						functions.append({"start": trace.cpu.eip_before, "end": None})
					
					is_call = False
					is_jump = False
					is_ret = False
					if trace.cpu.disas().startswith('call'):
						is_call = True
					elif trace.cpu.disas().startswith('j'):
						is_jump = True
					elif trace.cpu.disas().startswith('ret'):
						is_ret = True
					
					if is_ret:
						if functions:
							function = functions.pop()
							function["end"] = trace.cpu.eip_before
							if not function in flow.functions:
								flow.functions.append(function)

					if not node_id in flow.blocks:
						flow.blocks[node_id] = {'instr': [], 'range': [], 'to': None}
					if not trace.cpu.eip_before in flow.blocks[node_id]['instr']:
						flow.blocks[node_id]['instr'].append(trace.cpu.eip_before)
						flow.blocks[node_id]['range'].extend([trace.cpu.eip_before])
					#flow.blocks[node_id]['range'].extend(range(trace.cpu.eip_before, trace.cpu.eip_before+len(trace.cpu.opcode)/2))
					flow.code[trace.cpu.eip_before] = {'opcode': trace.cpu.opcode, 'disas': trace.cpu.disas()}

				# calls tree collecting
				if not trace.cpu.thread_id in calls.keys():
					calls[trace.cpu.thread_id] = {'called': None, 'deep': 0}
				if not calls[trace.cpu.thread_id]['called']:
					calls[trace.cpu.thread_id]['called'] = trace.cpu.eip_before
					tree.append({"deep": calls[trace.cpu.thread_id]['deep'], "addr": calls[trace.cpu.thread_id]['called'], "takt": trace.cpu.takt})
				if trace.cpu.disas().startswith('call'):
					calls[trace.cpu.thread_id]['called'] = None
					calls[trace.cpu.thread_id]['deep'] += 1
					#print calls[trace.cpu.thread_id]['deep']
				elif trace.cpu.disas().startswith('ret'):
					if calls[trace.cpu.thread_id]['deep'] > 0:
						calls[trace.cpu.thread_id]['deep'] -= 1


				cc.execute("INSERT INTO cpu VALUES(0x%x,0x%x,0x%x,0x%x,0x%x,0x%x,0x%x,0x%x,0x%x,0x%x,0x%x)" % (
					trace.cpu.takt,
					trace.cpu.thread_id,
					trace.cpu.eax_before,
					trace.cpu.ecx_before,
					trace.cpu.edx_before,
					trace.cpu.ebx_before,
					trace.cpu.esp_before,
					trace.cpu.ebp_before,
					trace.cpu.esi_before,
					trace.cpu.edi_before,
					trace.cpu.eip_before
				) )

				page = trace.cpu.esp_before
				page >>= 12
				page <<= 12
				Memory.stack.add(page)
				if not "stack.0x%08x"%page in Memory.modules:
					Memory.modules["stack.0x%08x"%page] = [page, page|0xfff]

				page = trace.cpu.eip_before
				page >>= 12
				page <<= 12
				if not "code.0x%08x"%page in Memory.modules:
					Memory.modules["code.0x%08x"%page] = [page, page|0xfff]

				if used_registers:
					regs_r, regs_w = used_registers
					for reg_r in regs_r:
						cc.execute("INSERT INTO reg VALUES(?,?,?,'r')", (trace.cpu.takt,reg_r,trace.cpu.get(reg_r)))
					for reg_w in regs_w:
						cc.execute("INSERT INTO reg VALUES(?,?,?,'w')", (trace.cpu.takt,reg_w,trace.cpu.get(reg_w)))

				if used_memory:
					mems_r, mems_w = used_memory
					for mem_r in mems_r:
						value = trace.io.ram.get_byte(mem_r)
						if not mem_r in Memory.reads:
							Memory.reads[mem_r] = []
						Memory.reads[mem_r].append( (trace.cpu.eip_before,value) )
						cc.execute("INSERT INTO mem VALUES(?,?,?,'r')", (
							trace.cpu.takt,
							mem_r,
							value
						) )
					for mem_w in mems_w:
						value = trace.io.ram.get_byte(mem_w)
						if not mem_w in Memory.writes:
							Memory.writes[mem_w] = []
						Memory.writes[mem_w].append( (trace.cpu.eip_before,value) )
						cc.execute("INSERT INTO mem VALUES(?,?,?,'w')", (
							trace.cpu.takt,
							mem_w,
							value
						) )

				#if trace.cpu.eip_before == HEAP_ALLOCATOR:
				#	region_size = trace.cpu.ecx_before
				#	after_heap_allocate = trace.cpu.eip_before + len(trace.cpu.opcode)
				#elif trace.cpu.eip_before == after_heap_allocate:
				#	region = trace.cpu.eax_before
				#	Memory.heap.add( (region, region_size) )
				#	print "[+] heap allocate 0x%08x %d bytes" % (region, region_size)
				#	after_heap_allocate == None

		except StopExecution:
			for module in trace.modules:
				Memory.modules[module.name] = (module.start, module.end)
			cc.execute("CREATE INDEX takt_cpu_index ON cpu(takt)")
			cc.execute("CREATE INDEX eip_cpu_index ON cpu(eip)")
			cc.execute("CREATE INDEX takt_mem_index ON mem(takt)")
			cc.execute("CREATE INDEX addr_mem_index ON mem(addr)")
			cc.execute("CREATE INDEX takt_reg_index ON reg(takt)")
			c.commit()

		except Exception as e:
			print str(e)
			print hex(trace.cpu.eip_before)
			import traceback; traceback.print_exc()

	#import ipdb;ipdb.set_trace()
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
		<link rel="stylesheet" href="memtrace/jquery-ui/themes/smoothness/jquery-ui.min.css">
		<link rel="stylesheet" href="memtrace/highlightjs/styles/default.css">
		<script src="memtrace/jquery/dist/jquery.js"></script>
		<script src="memtrace/jquery-ui/jquery-ui.js"></script>
		<script src="memtrace/highlightjs/highlight.pack.js"></script>
		<script src="memtrace/sprintf/sprintf.js"></script>
		<script src="memtrace/script.js?v=0.20"></script>
		<style>
		body { background-color: white; color: black; }
		#trace_position { float: left; width: 95%; }
		#trace_position_value { float: left; width: 4%; }
		#code { float: left; width: 60%; height: 40%; overflow-x: scroll; overflow-y: scroll; border: 1px solid black; padding: 2px; }
		#regs { float: left; width: 39%; height: 40%; overflow-y: scroll; border: 1px solid black; padding: 2px; }
		#hints { float: left; width: 60%; height: 10%; overflow-y: scroll; border: 1px solid black; padding: 2px; }
		#calls { float: left; width: 39%; height: 10%; overflow-y: scroll; border: 1px solid black; padding: 2px; }
		#data { float: left; width: 60%; height: 45%; overflow-y: scroll; border: 1px solid black; padding: 2px; }
		#stack { float: left; width: 39%; height: 45%; overflow-y: scroll; border: 1px solid black; padding: 2px; }
		#code_graph { display: none; }
		#data table, #code table { width: 100%; }
		.heap0 { border: 2px solid blue; }
		.heap1 { border: 2px solid black; }
		.state, .instructionr, .instructionw, .memoryr, .memoryw { font-size: 9pt; }
		.cell, .instr, .takt, .addr { cursor: pointer; }
		.byte_wrote { color: #ffffff; font-weight: bold; font-size: large; }
		.byte_wrote_ago_1 { color: #cccccc; font-weight: bold; }
		.byte_wrote_ago_2 { color: #777777; font-weight: bold; }
		.byte_wrote_ago_3 { color: #333333; }
		.byte_read { color: #00ff00; font-weight: bold; font-size: large; }
		.byte_read_ago_1 { color: #00cc00; font-weight: bold; }
		.byte_read_ago_2 { color: #007700; font-weight: bold; }
		.byte_read_ago_3 { color: #003300; }
		.byte_updated { font-weight: bold; }
		.byte_changed { color: #cccc00; }
		.stack_read { color: #00ff00; }
		.stack_wrote { color: #ff0000; }
		.reg_changed { background-color: #00ffff; }
		.reg_changed_ago_1 { background-color: #aaffff; }
		.reg_changed_ago_2 { background-color: #eeffff; }
		#regs .reg_points_r { color: green; }
		#regs .reg_points_w { color: red; }
		#regs .reg_points_x { color: #aaaa00; }
		.access_read { background-color: green; }
		.access_write { background-color: red; }
		.instruction_current { background-color: #003333; }
		.instruction_exec_ago_1 { background-color: #007777; }
		.instruction_exec_ago_2 { background-color: #00cccc; }
		.instruction_exec_ago_3 { background-color: #00ffff; }
		.call_current { color: green; text-decoration: underline; }
		#progressbar { position: absolute; width: 60%; left: 25%; top: 50%; z-index: 999; }
		#shadow { position: absolute; left: 0; top: 0; width: 100%; height: 100%; display: none; background: black; z-index: 99; }
		.ui-dialog-titlebar { padding: 2px !important; }
		</style>
		<div id="dialog"></div>
		<div id="dialog2"></div>
		<div id="shadow"></div>
	''')

	out.write('<div><input type="range" id="trace_position" min="253000000" max="253005638" step=1 value=253000000><input type="text" id="trace_position_value" value=0></div>')
	
	out.write("<div id='code'><table><tbody>")
	for page in Memory.pages.code:
		#eip = page
		for eip in [eip for eip in Memory.code if page <= eip < page + WHITESPACE_PADDING_SIZE]:
		#while True:
			if eip in Memory.code.keys():
				stdout.write("\r[*] code 0x%08x" % eip)
				stdout.flush()
				executions = len( Memory.code[eip] )
				opcode = Memory.code[eip][0]['opcode']
				disas = Memory.code[eip][0]['disas']
				css_color_gradient = executions * 10 if executions * 10 < 255 else 255
				css_color_executions = "#ffff%02x" % (0xff-css_color_gradient,)
				out.write('<tr id="instr_%(eip)d" style="background-color:%(color)s"><td><a href="#">%(exec_count)d</a></td><td><a href="#" class="instr" eip=%(eip)d>0x%(eip)08x</a></td><td>%(opcode)s</td><td><code>%(instr)s</code></td></tr>' % { 'color': css_color_executions, 'exec_count': executions, 'eip': eip, 'opcode': opcode.encode('hex'), 'instr': disas })
				eip += len(opcode) #!!! DBT trace has wrong opcode
			else:
				out.write('<tr><td></td><td>0x%(eip)08x</td><td>**</td><td>**</td></tr>' % { 'eip': eip })
				eip += 1
			#if eip >= page + WHITESPACE_PADDING_SIZE:
			#	break
	out.write("</tbody></table></div>")
	
	code_flow_graph = pydot.Dot(graph_type='digraph')
	for block_id in flow.blocks:
		block = ""
		for eip in flow.blocks[block_id]['instr']:
			block += hex(eip) + ": " + flow.code[eip]['disas'] + "\n"
		code_flow_graph.add_node( pydot.Node(block_id, label=block, shape='box') )
	for block_id in flow.blocks:
		if flow.blocks[block_id]['to']:
			code_flow_graph.add_edge( pydot.Edge(block_id, flow.blocks[block_id]['to']) )
	code_flow_graph.write_svg('/tmp/code_flow.svg')
	with open('/tmp/code_flow.svg', 'r') as f:
		out.write("<div id='code_graph'>" + f.read() + "</div>")

	out.write('<div id="regs">')
	out.write('<div id="EAX">EAX: <span class="value">00000000</span> <span class="hints"></span></div>')
	out.write('<div id="ECX">ECX: <span class="value">00000000</span> <span class="hints"></span></div>')
	out.write('<div id="EDX">EDX: <span class="value">00000000</span> <span class="hints"></span></div>')
	out.write('<div id="EBX">EBX: <span class="value">00000000</span> <span class="hints"></span></div>')
	out.write('<div id="ESP">ESP: <span class="value">00000000</span> <span class="hints"></span></div>')
	out.write('<div id="EBP">EBP: <span class="value">00000000</span> <span class="hints"></span></div>')
	out.write('<div id="ESI">ESI: <span class="value">00000000</span> <span class="hints"></span></div>')
	out.write('<div id="EDI">EDI: <span class="value">00000000</span> <span class="hints"></span></div>')
	out.write('<div id="EIP">EIP: <span class="value">00000000</span> <span class="hints"></span></div>')
	out.write('</div>')

	out.write('<div id="hints"></div>')
	out.write('<div id="calls"></div>')

	out.write("<div id='data'><table><tbody>")
	for page in Memory.pages.data:
		page_type = get_page_type(page)
		stdout.write("\r[*] data region 0x%08x" % page)
		stdout.flush()
		out.write("<tr><td name=%(page)d>%(type)s.0x%(page)08x:</td>" % { 'page':page, 'type':page_type })
		addr = page
		while True:
			# ===SLOWLY===
			if addr in Memory.writes.keys():
				operation_type = 'w'
				operation_count_writes = len( Memory.writes[addr] )
				val = "%08X" % Memory.writes[addr][0][1]
				instructions_writes = Memory.writes[addr]
				del Memory.writes[addr]
			if addr in Memory.reads.keys():
				if not val:
					operation_type = 'r'
					val = "%08X" % Memory.reads[addr][0][1]
				operation_count_reads = len( Memory.reads[addr] )
				instructions_reads = Memory.reads[addr]
				del Memory.reads[addr]

			#operation_count_reads = 1
			#instructions_reads = [[1,1]]
			#operation_type = 'r'
			#val = "00000000"

			if val:
				if operation_type == 'w':
					css_color_graient = operation_count_writes * 16 if operation_count_writes < 16 else 255
					css_color_write = "#ff%02x%02x" % (0xff-css_color_graient, 0xff-css_color_graient)
					heap_number = in_heap(addr)
					if heap_number:
						out.write("<td class='heap%(heap_no)d' style='background-color:%(color)s'><div id='cell_%(addr)d' addr=%(addr)d class='cell'>%(value)s</div></td>" % { 'heap_no': heap_number%2, 'color':css_color_write, 'addr': addr, 'value': val[-2:] })
					else:
						out.write("<td style='background-color:%(color)s'><div id='cell_%(addr)d' addr=%(addr)d class='cell'>%(value)s</div></td>" % { 'color': css_color_write, 'addr': addr, 'value': val[-2:] })
				elif operation_type == 'r':
					css_color_graient = operation_count_reads * 16 if operation_count_reads < 16 else 255
					css_color_read = "#%02xff%02x" % (0xff-css_color_graient, 0xff-css_color_graient)
					heap_number = in_heap(addr)
					if heap_number:
						out.write("<td class='heap%(heap_no)d' style='background-color:%(color)s'><div id='cell_%(addr)d' addr=%(addr)d class='cell'>%(value)s</div></td>" % { 'heap_no': heap_number%2, 'color':css_color_read, 'addr': addr, 'value': val[-2:] })
					else:
						out.write("<td style='background-color:%(color)s'><div id='cell_%(addr)d' addr=%(addr)d class='cell'>%(value)s</div></td>" % { 'color': css_color_read, 'addr': addr, 'value': val[-2:] })
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
				out.write("<tr><td name=%(addr)d>%(type)s.0x%(addr)08x:</td>" % { 'addr': addr, 'type': page_type })
		out.write("</tr>")
	out.write("</tbody></table></div>")

	out.write("<div id='stack'></div>")

	out.write('<div id="progressbar"></div>')

	out.write("<script>var MemoryMap = {}</script>".format(json.dumps(Memory.modules)))
	out.write("<script>var CallsTree = {}</script>".format(json.dumps(tree)))
	out.write("<script>var Functions = {}</script>".format(json.dumps(flow.functions)))
	out.close()

	print("uniq instructions: ")
	print("uniq memory: ")

if __name__ == '__main__':
	db_init()
	load_trace(args.tracefile)
	create_html()
	www = Flask(__name__)

	@www.route('/data/<int:addr>/accesses')
	def data_goto(addr):
		results = []
		print addr
		for (takt,addr,value,access_type,eip) in cc.execute("SELECT mem.*,cpu.eip FROM mem JOIN cpu ON mem.takt=cpu.takt WHERE mem.addr=?", (addr,)):
			print "takt: %d, eip: 0x%x, value: %X, access_type: %s" % (takt,eip,value,access_type)
			results.append( (takt,eip,value,access_type) )
		return json.dumps(results)

	@www.route('/code/<int:addr>/accesses')
	def code_goto(addr):
		results = []
		print addr
		for (takt,addr,value,access_type) in cc.execute("SELECT mem.* FROM mem JOIN cpu ON mem.takt=cpu.takt WHERE cpu.eip=?", (addr,)):
			print "takt: %d, addr: 0x%x, value: %X, access_type: %s" % (takt,addr,value,access_type)
			results.append( (takt,addr,value,access_type) )
		return json.dumps(results)

	@www.route('/takt/<int:takt>/state')
	def takt_state(takt):
		results = []
		print takt
		for (eax,ecx,edx,ebx,esp,ebp,esi,edi,eip) in cc.execute("SELECT cpu.eax,cpu.ecx,cpu.edx,cpu.ebx,cpu.esp,cpu.ebp,cpu.esi,cpu.edi,cpu.eip FROM cpu WHERE cpu.takt=?", (takt,)):
			print "state: EAX:%08x ECX:%08x EDX:%08x EBX:%08x ESP:%08x EBP:%08x ESI:%08x EDI:%08x EIP:%08x" % (eax,ecx,edx,ebx,esp,ebp,esi,edi,eip)
			results.append((eax,ecx,edx,ebx,esp,ebp,esi,edi,eip))
		return json.dumps(results)

	@www.route('/takt/<int:takt>/reg/access')
	def takt_reg_access(takt):
		results = []
		print takt
		for (takt,reg,value,access_type) in cc.execute("SELECT reg.* FROM reg JOIN cpu ON reg.takt=cpu.takt WHERE cpu.takt=?", (takt,)):
			print "takt: %d, reg: %s, value: %X, access_type: %s" % (takt,reg,value,access_type)
			results.append( (takt,reg,value,access_type) )
		return json.dumps(results)

	@www.route('/takt/<int:takt>/mem/access')
	def takt_mem_access(takt):
		results = []
		print takt
		for (takt,addr,value,access_type) in cc.execute("SELECT mem.* FROM mem JOIN cpu ON mem.takt=cpu.takt WHERE cpu.takt=?", (takt,)):
			print "takt: %d, addr: 0x%x, value: %X, access_type: %s" % (takt,addr,value,access_type)
			results.append( (takt,addr,value,access_type) )
		return json.dumps(results)

	@www.route('/data/<int:addr>/takt/<int:takt>/state')
	def get_memory(addr, takt):
		results = []
		print addr, takt
		for (byte,) in cc.execute("SELECT mem.value FROM mem JOIN cpu ON mem.takt=cpu.takt WHERE mem.addr=? and (cpu.takt<=? or cpu.takt>? and mem.access_type='r') limit 1", (addr,takt,takt)):
			print "byte: %d" % (byte,)
			results.append( (byte,) )
		return json.dumps(results)

	@www.route('/access/before/<int:takt>/takt')
	def find_takt_before(takt):
		results = []
		bpx = map(int, request.args.getlist('bpx[]'))
		bpm = map(int, request.args.getlist('bpm[]'))
		for (takt,) in cc.execute("SELECT cpu.takt FROM mem JOIN cpu ON mem.takt=cpu.takt WHERE cpu.takt < ? and (cpu.eip in (%s) or mem.addr in (%s))" % (','.join('?'*len(bpx)), ','.join('?'*len(bpm))), [takt] + bpx + bpm):
			print "takt: %d" % (takt,)
			results.append( (takt,) )
			break
		return json.dumps(results)

	@www.route('/access/after/<int:takt>/takt')
	def find_takt_after(takt):
		results = []
		bpx = map(int, request.args.getlist('bpx[]'))
		bpm = map(int, request.args.getlist('bpm[]'))
		print "SELECT cpu.takt FROM mem JOIN cpu ON mem.takt=cpu.takt WHERE cpu.takt > ? and (cpu.eip in (%s) or mem.addr in (%s))" % (','.join('?'*len(bpx)), ','.join('?'*len(bpm)))
		print [takt] + bpx + bpm
		for (takt,) in cc.execute("SELECT cpu.takt FROM mem JOIN cpu ON mem.takt=cpu.takt WHERE cpu.takt > ? and (cpu.eip in (%s) or mem.addr in (%s))" % (','.join('?'*len(bpx)), ','.join('?'*len(bpm))), [takt] + bpx + bpm):
			print "takt: %d" % (takt,)
			results.append( (takt,) )
			break
		return json.dumps(results)

	CORS(www)
	www.run(debug=True, use_reloader=False)

'''
/data/<int:addr>/accesses -> [(takt,eip,value,access_type), ...]
/code/<int:addr>/accesses -> [(takt,addr,value,access_type), ...]

/takt/<int:takt>/state -> eax,ecx,edx,ebx,esp,ebp,esi,edi,eip
/takt/<int:takt>/access -> takt,addr,value,access_type

/data/<int:addr>/takt/<int:takt>/state -> byte
/access/before/<int:takt>/takt?bpx=[]&bpm=[] -> takt
/access/after/<int:takt>/takt?bpx=[]&bpm=[] -> takt
'''