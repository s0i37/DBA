from sys import argv, stdout
from capstone import *
from bisect import bisect_left,insort_left
import sqlite3

if len(argv) != 3:
	print "%s trace.txt symbols.db" % argv[0]
	exit()

'''
TODO
need txt output for grep
'''

trace_file = argv[1]
symbols_db = argv[2]
db = sqlite3.connect(symbols_db)
sql = db.cursor()

#heap = set()
stack = set()
memory_writes_addrs = []
memory_reads_addrs = []
memory_writes_values = {}
memory_reads_values = {}
modules = {}
pages = [0]
eips = []
instructions = {}
md = Cs(CS_ARCH_X86, CS_MODE_32)

modules = {}
for info in sql.execute( 'select * from modules' ).fetchall():
	module,start,end = info
	modules.update( { module: [ int(start), int(end) ] } )
symbols = {}
for info in sql.execute( 'select * from symbols' ).fetchall():
	module,symbol,start,end = info
	symbols.update( { symbol: [ int(start), int(end) ] } )

print "modules: %d" % len(modules)
print "symbols: %d" % len(symbols)

execs = 0
with open(trace_file) as f:
	for line in f:
		if line.startswith("w"):
			_, eip, addr, _, value = line.split()
			eip = int( eip[1:11], 16 )
			addr = int( addr.split('(')[0], 16 )
			value = int( value, 16 )
			if eip >= 0x80000000:
				continue
			try:
				memory_writes_values[addr].append( (eip,value) )
			except:
				memory_writes_values[addr] = [ (eip,value) ]
				insort_left(memory_writes_addrs, addr)
		elif line.startswith("r"):
			_, eip, addr, _, value = line.split()
			eip = int( eip[1:11], 16 )
			addr = int( addr.split('(')[0], 16 )
			value = int( value, 16 )
			if eip >= 0x80000000:
				continue
			try:
				memory_reads_values[addr].append( (eip,value) )
			except:
				memory_reads_values[addr] = [ (eip,value) ]
				insort_left(memory_reads_addrs, addr)
		elif line.startswith("x"):
			_, eip, opcodes, REGS = line.split()
			eip = int( eip[1:11], 16 )
			opcodes = opcodes[1:-1].decode('hex')
			if eip >= 0x80000000:
				continue
			eax,ecx,edx,ebx,esp,ebp,esi,edi = map( lambda r:int(r,16), REGS.split(',') )
			index = bisect_left(eips,eip)
			if not index < len(eips) or eips[index] != eip:
				insort_left(eips,eip)
				for inst in md.disasm(opcodes, 0):
					instructions[eip] = {
						'inst': "%s %s" % (inst.mnemonic, inst.op_str),
						'opcode': opcodes[:inst.size].encode('hex'),
						'execs': 1
					}
					break
			else:
				instructions[eip]['execs'] += 1
			stack.add( esp & 0xfffff0 )
		execs += 1
		if execs % 100000 == 0:
			stdout.write( "\rinstructions: %d" % execs )
			stdout.flush()
	stdout.write( "\rinstructions: %d\n" % execs )
	stdout.flush()


addresses = memory_reads_addrs + memory_writes_addrs
addresses.sort()
print "read/write ops: %d" % len(addresses)
for addr in addresses:
	if addr > max(pages)+0x10:
		pages.append( addr & 0xfffffff0 )
pages.pop(0)

#def print_modules():
#	for module,module_range in modules.items():
#		low_address,high_address = module_range
#		print "0x%08x-0x%08x: %s" % (low_address,high_address, module)

#def print_heap_regions():
#	for region in heap:
#		low_address, high_address = region
#		print "region 0x%08x-0x%08x" % (low_address, high_address)

#def print_stack_pages():
#	for page in stack:
#		print "stack: 0x%08x" % page

#def print_memory_pages():
#	global pages
#	for page in pages:
#		print "page 0x%08X" % page

def _in_heap(addr):
	return False
	heap_number = 0
	for region in heap:
		heap_number += 1
		low_address, high_address = region
		if low_address <= addr <= high_address:
			return heap_number
	else:
		return False

def get_page_type(addr):
	for module,module_range in modules.items():
		low_address,high_address = module_range
		if low_address <= addr <= high_address:
			return module.replace("\\","/").split("/").pop()
	for page in stack:
		if page <= addr < page | 0xf:
			return "stack"
	return "unkn"

symbol_names = symbols.keys()
symbol_bounds = symbols.values()
symbol_bounds_len = len(symbol_bounds)
def get_symbol(eip):
	for i in xrange(symbol_bounds_len):
		bounds = symbol_bounds[i]
		if bounds[0] <= eip <= bounds[1]:
			return symbol_names[i],bounds
	return ('',(0,0))


def html_print():
	with open('out.html', 'w') as o:
		val = ""
		operation_count_reads = 0
		o.write( "<style>body {background-color: white; color: black;}\r\ndiv {float:left; width: 49%; height: 100%; overflow-y: scroll;}\r\n.heap0 {border: 2px solid blue;}\r\n.heap1 {border: 2px solid black;}\r\n</style>\n" )

		o.write( "<div><table><tbody>\n" )
		#print "pages count: %d" % len(pages)
		for page in pages:
			page_type = get_page_type(page)
			addr = page
			#print "0x%08x" % page
			while addr < page + 0x10:
				if addr % 0x10 == 0:
					o.write( ( "<tr><td>%s.0x%08x" % (page_type,addr) ) + ": </td>\n" )
				index = bisect_left( memory_writes_addrs, addr )
				if index < len(memory_writes_addrs) and memory_writes_addrs[index] == addr:
					operation_type = 'w'
					operation_count_writes = len( memory_writes_values[addr] )
					val = "%08X" % memory_writes_values[addr][0][1]
					instructions_writes = memory_writes_values[addr]
				index = bisect_left( memory_reads_addrs, addr )
				if index < len(memory_reads_addrs) and memory_reads_addrs[index] == addr:
					if not val:
						operation_type = 'r'
						val = "%08X" % memory_reads_values[addr][0][1]
						operation_count_reads = len( memory_reads_values[addr] )
						instructions_reads = memory_reads_values[addr]

				if val:
					if operation_type == 'w':
						css_color_graient = operation_count_writes * 16 if operation_count_writes < 16 else 255
						css_color_write = "#ff%02x%02x" % (0xff-css_color_graient, 0xff-css_color_graient)
						title_text = "writes: %d\n" % operation_count_writes
						title_text += '\n'.join( map( lambda x: "0x%08x -> 0x%08X" % (x[0], x[1]) , instructions_writes ) )
						if operation_count_reads:
							title_text += "\nreads: %d\n" % operation_count_reads
							title_text += '\n'.join( map( lambda x: "0x%08x <- 0x%08X" % (x[0], x[1]) , instructions_reads ) )
						heap_number = _in_heap(addr)
						title_text = ''
						if heap_number:
							o.write( ( "<td class='heap%d' style='background-color:%s'><abbr title='%s'>%s</abbr></td>\n" % (heap_number%2, css_color_write, title_text, val[-2:]) ) )
						else:
							o.write( ( "<td style='background-color:%s'><abbr title='%s'>%s</abbr></td>\n" % (css_color_write, title_text, val[-2:]) ) )
					elif operation_type == 'r':
						css_color_graient = operation_count_reads * 16 if operation_count_reads < 16 else 255
						css_color_read = "#%02xff%02x" % (0xff-css_color_graient, 0xff-css_color_graient)
						title_text = "reads: %d\n" % operation_count_reads
						title_text += '\n'.join( map( lambda x: "0x%08x <- 0x%08X" % (x[0], x[1]) , instructions_reads ) )
						heap_number = _in_heap(addr)
						title_text = ''
						if heap_number:
							o.write( ( "<td class='heap%d' style='background-color:%s'><abbr title='%s'>%s</abbr></td>\n" % (heap_number%2, css_color_read, title_text, val[-2:]) ) )
						else:
							o.write( ( "<td style='background-color:%s'><abbr title='%s'>%s</abbr></td>\n" % (css_color_read, title_text, val[-2:]) ) )
							
					val = val[:-2]
				else:
					heap_number = _in_heap(addr)
					if heap_number:
						o.write( "<td class='heap%d'>**</td>\n" % (heap_number%2) )
					else:
						o.write( "<td>**</td>\n" )

				addr += 1
				if addr % 0x10 == 0:
					o.write( "</tr>\n" )
			o.write( "</tr>\n" )
		o.write( "</tbody></table></div>\n" )

		o.write( "<div><table><tbody>\n" )
		max_execs = max( map( lambda i:i['execs'], instructions.values() ) )
		print "unique instructions: %d" % len(eips)
		print "max instruction executions: %d" % max_execs
		i = 0
		bounds = (0,0)
		for eip in eips:
			if not bounds[0] <= eip <= bounds[1]:
				(symbol,bounds) = get_symbol(eip)
				if symbol:
					o.write( "<tr><td>%s</td></tr>" % symbol[35:] )
			css_color_graient = float( instructions[eip]['execs'] ) / max_execs * 0xff
			css_color_execs = "#ff%02x%02x" % (0xff-css_color_graient, 0xff-css_color_graient)
			o.write( "<tr style='background-color: %s'><td>0x%08x</td><td>%d</td><td>%s</td><td>%s</td></tr>\n" % ( css_color_execs, eip, instructions[eip]['execs'], instructions[eip]['opcode'], instructions[eip]['inst'] ) )
			i += 1
			if i and i % 1000 == 0:
				stdout.write( "\rinstructions %d" % i )
				stdout.flush()
		stdout.write( "\rinstructions %d\n" % i )
		stdout.flush()
		o.write( "</tbody></table></div>\n" )


html_print()