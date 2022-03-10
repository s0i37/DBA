import sqlite3
from sys import argv
from os.path import isfile
import re

if len( argv ) != 2:
	print "%s trace_file" % argv[0]
	exit()

trace_file = argv[1]
is_need_init = not isfile("memory.db")
c = sqlite3.connect("memory.db")
cc = c.cursor()

if is_need_init:
	cc.execute("create table memory(id integer, addr integer, val integer, page_id integer)")
	cc.execute("create table instructions(id integer, eip integer, op_type text, memory_id integer, eax integer, edx integer, ecx integer, ebx integer, ebp integer, esp integer, esi integer, edi integer)")
	cc.execute("create table pages(id integer, name text, low_addr integer, high_addr integer)")
	cc.execute("create table heap(id integer, low_addr integer, high_addr integer)")
	cc.execute("create table syscalls(id integer, syscall_no integer)")
	c.commit()

heap_id = 0
memory_id = 0
instruction_id = 0
syscall_id = 0
pages = {}
with open(trace_file, 'rb') as f:
	for line in f.read().split("\r\n"):
		if line.find("module") != -1:
			m = re.match("[^\s]+ ([^\s]+) ([^\s]+) (.*)", line)
			if m:
				low_address, high_address, module = m.groups()
				low_address = int( low_address[2:10], 16 )
				high_address = int( high_address[2:10], 16 )
				for addr in xrange( low_address, high_address, 0x1000 ):
					pages[ addr ] = module
		elif line.find("alloc") != -1:
			m = re.match('alloc\(([^)]*)\): (.*)', line)
			if m:
				heap_id += 1
				size, region = m.groups()
				size = int( size )
				region = int( region[2:10], 16 )
				if size > 0x10000:
					continue
				cc.execute( "insert into heap values( {id}, {low}, {high} )".format( id=heap_id, low=region, high=region+size ) )
				pages[ region & 0xfffff000 ] = "heap"
		elif line.find("<-") != -1:
			m = re.match('^([^:]*): \[([^]]*)\].*<- ([^\s]*).*\(([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+)\)', line)
			if m:
				memory_id += 1
				instruction_id += 1
				eip, addr, value, eax,edx,ecx,ebx,esi,edi,ebp,esp = m.groups()
				eip = int( eip[2:10], 16 )
				eax = int( eax[2:10], 16 )
				edx = int( edx[2:10], 16 )
				ecx = int( ecx[2:10], 16 )
				ebx = int( ebx[2:10], 16 )
				ebp = int( ebp[2:10], 16 )
				esp = int( esp[2:10], 16 )
				esi = int( esi[2:10], 16 )
				edi = int( edi[2:10], 16 )
				addr = int( addr[2:10], 16 )
				value = int( value[2:10], 16 )
				cc.execute( "insert into memory(id,addr,val) values( {id}, {addr}, {val} )".format( id=memory_id, addr=addr, val=value, ) )
				cc.execute( "insert into instructions values( {id}, {eip}, '{op_type}', {memory_id}, {eax},{edx},{ecx},{ebx},{ebp},{esp},{esi},{edi} )".format( id=instruction_id, eip=eip, op_type="w", memory_id=memory_id, eax=eax,edx=edx,ecx=ecx,ebx=ebx,ebp=ebp,esp=esp,esi=esi,edi=edi ) )
				pages[ esp & 0xfffff000 ] = "stack"
		elif line.find("->") != -1:
			m = re.match('^([^:]*): \[([^]]*)\]([^\s]*) ->.*\(([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+)\)', line)
			if m:
				memory_id += 1
				instruction_id += 1
				eip, addr, value, eax,edx,ecx,ebx,esi,edi,ebp,esp = m.groups()
				eip = int( eip[2:10], 16 )
				eax = int( eax[2:10], 16 )
				edx = int( edx[2:10], 16 )
				ecx = int( ecx[2:10], 16 )
				ebx = int( ebx[2:10], 16 )
				ebp = int( ebp[2:10], 16 )
				esp = int( esp[2:10], 16 )
				esi = int( esi[2:10], 16 )
				edi = int( edi[2:10], 16 )
				addr = int( addr[2:10], 16 )
				value = int( value[2:10], 16 )
				cc.execute( "insert into memory(id,addr,val) values( {id}, {addr}, {val} )".format( id=memory_id, addr=addr, val=value ) )
				cc.execute( "insert into instructions values( {id}, {eip}, '{op_type}', {memory_id}, {eax},{edx},{ecx},{ebx},{ebp},{esp},{esi},{edi} )".format( id=instruction_id, eip=eip, op_type="r", memory_id=memory_id, eax=eax,edx=edx,ecx=ecx,ebx=ebx,ebp=ebp,esp=esp,esi=esi,edi=edi ) )
				pages[ esp & 0xfffff000 ] = "stack"
		elif line.find("!!") != -1:
			m = re.match( "^([^:]*):.*\(([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+)\)", line )
			if m:
				syscall_id += 1
				eip, eax,edx,ecx,ebx,esi,edi,ebp,esp = m.groups()
				syscall_number = int( eax[2:10], 16 )
				syscall_stack = int( edx[2:10], 16 )
				cc.execute( "insert into syscalls values( {id}, {syscall_no} )".format( id=syscall_id, syscall_no=syscall_number ) )

		else:
			m = re.match( "^([^:]*):.*\(([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+)\)", line )
			if m:
				instruction_id += 1
				eip, eax,edx,ecx,ebx,esi,edi,ebp,esp = m.groups()
				eip = int( eip[2:10], 16 )
				eax = int( eax[2:10], 16 )
				edx = int( edx[2:10], 16 )
				ecx = int( ecx[2:10], 16 )
				ebx = int( ebx[2:10], 16 )
				ebp = int( ebp[2:10], 16 )
				esp = int( esp[2:10], 16 )
				esi = int( esi[2:10], 16 )
				edi = int( edi[2:10], 16 )
				cc.execute( "insert into instructions(id,eip,eax,edx,ecx,ebx,ebp,esp,esi,edi) values( {id}, {eip}, {eax},{edx},{ecx},{ebx},{ebp},{esp},{esi},{edi} )".format( id=instruction_id, eip=eip, eax=eax,edx=edx,ecx=ecx,ebx=ebx,ebp=ebp,esp=esp,esi=esi,edi=edi ) )
				pages[ esp & 0xfffff000 ] = "stack"
c.commit()

page_id = 0
for addr,name in pages.items():
	page_id += 1
	cc.execute( "insert into pages values( {id}, '{name}', {low_addr}, {high_addr} )".format( id=page_id, name=name, low_addr=addr, high_addr=addr|0xfff ) )
	cc.execute( "update memory set page_id='{page_id}' where addr >= {low} and addr <= {high}".format( page_id=page_id, low=addr, high=addr|0xfff ) )


c.commit()


'''

Dump
select addr,count(val) from memory where addr >= 0x03F3FEE8 group by 1 limit 10;

Code
select eip, count(eip), op_type from instructions where eip>=0x0040a690 and eip <= 0x0040a694 group by 1;

'''