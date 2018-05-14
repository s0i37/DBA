from sys import argv
import re
import syscalls as SYSCALLS

if len(argv) != 2:
	print "%s trace_file.txt" % argv[0]
	exit()

trace_file = argv[1]
heap = set()
stack = set()
memory_writes = {}
memory_reads = {}
modules = {}
syscalls = []
pages = [0]

with open(trace_file, 'rb') as f:
	for line in f.read().split("\r\n"):
		if line.find("module") != -1:
			m = re.match("[^\s]+ ([^\s]+) ([^\s]+) (.*)", line)
			if m:
				low_address, high_address, module = m.groups()
				low_address = int( low_address[2:10], 16 )
				high_address = int( high_address[2:10], 16 )
				modules[module] = (low_address,high_address)
		elif line.find("alloc") != -1:
			m = re.match('alloc\(([^)]*)\): (.*)', line)
			if m:
				size, region = m.groups()
				size = int( size )
				region = int( region[2:10], 16 )
				if size > 0x10000:
					continue
				heap.add( (region, region+size) )
		elif line.find("<-") != -1:
			m = re.match('^([^:]*): \[([^]]*)\].*<- ([^\s]*).*\(([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+)\)', line)
			if m:
				eip, addr, value, eax,edx,ecx,ebx,esi,edi,ebp,esp = m.groups()
				eip = int( eip[2:10], 16 )
				addr = int( addr[2:10], 16 )
				value = int( value[2:10], 16 )
				try:	memory_writes[addr].append( (eip,value) )
				except:	memory_writes[addr] = [ (eip,value) ]
				stack.add( int( esp[2:10], 16 ) & 0xfffff000 )
		elif line.find("->") != -1:
			m = re.match('^([^:]*): \[([^]]*)\]([^\s]*) ->.*\(([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+)\)', line)
			if m:
				eip, addr, value, eax,edx,ecx,ebx,esi,edi,ebp,esp = m.groups()
				eip = int( eip[2:10], 16 )
				addr = int( addr[2:10], 16 )
				value = int( value[2:10], 16 )
				try:	memory_reads[addr].append( (eip,value) )
				except:	memory_reads[addr] = [ (eip,value) ]
				stack.add( int( esp[2:10], 16 ) & 0xfffff000 )
		elif line.find("!!") != -1:
			m = re.match( "^([^:]*):.*\(([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+)\)", line )
			if m:
				eip, eax,edx,ecx,ebx,esi,edi,ebp,esp = m.groups()
				syscall_number = int( eax[2:10], 16 )
				syscall_stack = int( edx[2:10], 16 )
				syscalls.append( (syscall_number,syscall_stack) )


addresses = memory_writes.keys() + memory_reads.keys()
addresses.sort()
for addr in addresses:
	if addr >= max(pages)+0x1000:
		pages.append( addr & 0xfffff000 )
pages.pop(0)

def print_modules():
	for module,module_range in modules.items():
		low_address,high_address = module_range
		print "0x%08x-0x%08x: %s" % (low_address,high_address, module)

def print_heap_regions():
	for region in heap:
		low_address, high_address = region
		print "region 0x%08x-0x%08x" % (low_address, high_address)

def print_stack_pages():
	for page in stack:
		print "stack: 0x%08x" % page

def print_memory_pages():
	global pages
	for page in pages:
		print "page 0x%08X" % page

def print_syscalls():
	for syscall in syscalls:
		syscall_number, syscall_stack = syscall
		print "syscall: %s 0x%04x 0x%08X" % ( SYSCALLS.NT32_windows_7_sp1[syscall_number], syscall_number, syscall_stack )

def _in_heap(addr):
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
		if page <= addr < page | 0xfff:
			return "stack"
	return "unknown"

def text_print():
	val = ""
	for page in pages:
		print "page 0x%08x" % (page)
		print ("0x%08x" % page) + ": ",
		addr = page
		while addr < page + 0x1000:		
			if addr in memory_writes.keys():
				val = "%08X" % memory_writes[addr]

			if val:
				if _in_heap(addr):
					print ( "(%s)" % val[-2:] ),
				else:
					print val[-2:],
				val = val[:-2]
			else:
				if _in_heap(addr):
					print "(**)",
				else:
					print "**",

			addr += 1
			if not addr % 0x10:
				print ""
				print ("0x%08x" % addr) + ": ",
		print "\n"

def html_print():
	val = ""
	operation_count_reads = 0
	print "<style>body {background-color: white; color: black;}\r\n.heap0 {border: 2px solid blue;}\r\n.heap1 {border: 2px solid black;}</style>"
	print "<table><tbody>"
	for page in pages:
		page_type = get_page_type(page)
		print ( "<tr><td>%s.0x%08x" % (page_type,page) ) + ": </td>"
		addr = page
		while addr < page + 0x1000:
			if addr in memory_writes.keys():
				operation_type = 'w'
				operation_count_writes = len( memory_writes[addr] )
				val = "%08X" % memory_writes[addr][0][1]
				instructions_writes = memory_writes[addr]
				del memory_writes[addr]
			if addr in memory_reads.keys():
				if not val:
					operation_type = 'r'
					val = "%08X" % memory_reads[addr][0][1]
				operation_count_reads = len( memory_reads[addr] )
				instructions_reads = memory_reads[addr]
				del memory_reads[addr]

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
					if heap_number:
						print ( "<td class='heap%d' style='background-color:%s'><abbr title='%s'>%s</abbr></td>" % (heap_number%2, css_color_write, title_text, val[-2:]) )
					else:
						print ( "<td style='background-color:%s'><abbr title='%s'>%s</abbr></td>" % (css_color_write, title_text, val[-2:]) )
				elif operation_type == 'r':
					css_color_graient = operation_count_reads * 16 if operation_count_reads < 16 else 255
					css_color_read = "#%02xff%02x" % (0xff-css_color_graient, 0xff-css_color_graient)
					title_text = "reads: %d\n" % operation_count_reads
					title_text += '\n'.join( map( lambda x: "0x%08x <- 0x%08X" % (x[0], x[1]) , instructions_reads ) )
					heap_number = _in_heap(addr)
					if heap_number:
						print ( "<td class='heap%d' style='background-color:%s'><abbr title='%s'>%s</abbr></td>" % (heap_number%2, css_color_read, title_text, val[-2:]) )
					else:
						print ( "<td style='background-color:%s'><abbr title='%s'>%s</abbr></td>" % (css_color_read, title_text, val[-2:]) )
						
				val = val[:-2]
			else:
				heap_number = _in_heap(addr)
				if heap_number:
					print "<td class='heap%d'>**</td>" % (heap_number%2)
				else:
					print "<td>**</td>"

			addr += 1
			if not addr % 0x10:
				print "</tr>"
				print ( "<tr><td>%s.0x%08x" % (page_type,addr) ) + ": </td>"
		print "</tr>"
	print "</tbody></table>"

print "<pre>"
print_modules()
print_memory_pages()
print_stack_pages()
print_heap_regions()
print_syscalls()
print "</pre>"
html_print()

