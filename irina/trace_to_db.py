import sqlite3
from sys import argv
from os.path import isfile
import re
import pefile
import capstone

if len( argv ) != 2:
	print "%s trace_file" % argv[0]
	exit()

trace_file = argv[1]
is_need_init = not isfile("memory.db")
c = sqlite3.connect("memory.db")
cc = c.cursor()
dis = capstone.Cs( capstone.CS_ARCH_X86, capstone.CS_MODE_32 )

def disas(opcodes):
	mnem = '??'
	operands = '??'
	opcode = opcodes[:2]
	for instr in dis.disasm( opcodes.decode('hex'), eip ):
		mnem = instr.mnemonic
		operands = instr.op_str
		opcode = str(instr.bytes).encode('hex')
		break
	return opcode, mnem, operands


if is_need_init:
	cc.execute("create table takts(takt integer, thread_id integer, eax integer, ecx integer, edx integer, ebx integer, esp integer, ebp integer, esi integer, edi integer)")
	cc.execute("create table code(takt integer, eip integer, opcode text, mnem text, operands text, page_id integer)")
	cc.execute("create table data(takt integer, addr integer, value integer, access_type text, page_id integer)")
	cc.execute("create table pages(id integer, name text, low_addr integer, high_addr integer, perm_r integer, perm_w integer, perm_x integer)")

	cc.execute("create table modules(id integer, base integer, name text)")
	cc.execute("create table heap(id integer, low_addr integer, high_addr integer)")
	cc.execute("create table syscalls(id integer, syscall_no integer)")
	c.commit()

heap_id = 0
memory_id = 0
instruction_id = 0
syscall_id = 0
pages = {}
modules = {}

PERM_R = 4
PERM_W = 2
PERM_X = 1

with open(trace_file, 'rb') as f:
	for line in f.read().split("\r\n"):
		if line.find("module") != -1:
			m = re.match("[^\s]+ ([^\s]+) ([^\s]+) (.*)", line)
			if m:
				low_address, high_address, module = m.groups()
				low_address = int( low_address[2:10], 16 )
				high_address = int( high_address[2:10], 16 )
				modules[low_address] = module
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
				pages[ region & 0xfffff000 ] = ( "heap", region | 0xfff, PERM_R | PERM_W )
		else:
			m = re.match("^([^:]*): \(([^\)]+)\)\[([^\]]+)\] {([^}]+)}.*\(([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+)\)", line)
			if m:
				eip, takt,threadid, opcodes, eax,edx,ecx,ebx,esi,edi,ebp,esp = m.groups()
				eip = int( eip[2:10], 16 )
				takt = int(takt)
				threadid = int( threadid )
				eax = int( eax[2:10], 16 )
				edx = int( edx[2:10], 16 )
				ecx = int( ecx[2:10], 16 )
				ebx = int( ebx[2:10], 16 )
				ebp = int( ebp[2:10], 16 )
				esp = int( esp[2:10], 16 )
				esi = int( esi[2:10], 16 )
				edi = int( edi[2:10], 16 )
				cc.execute( "insert into takts values(?,?, ?,?,?,?,?,?,?,?)", (takt,threadid, eax,ecx,edx,ebx,esp,ebp,esi,edi) )
				opcode, mnem, operands = disas(opcodes)
				cc.execute( "insert into code(takt,eip,opcode,mnem,operands) values(?,?, ?,?,?)", (takt,eip, opcode,mnem,operands) )
				pages[ eip & 0xfffff000 ] = ( "code", eip | 0xfff, PERM_R | PERM_X )
			if line.find("<-") != -1:
				m = re.match('^([^:]*):.*\[([^]]*)\].*<- ([^\s]*).*\(([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+)\)', line)
				if m:
					eip, addr, value, eax,edx,ecx,ebx,esi,edi,ebp,esp = m.groups()
					eip = int( eip[2:10], 16 )
					addr = int( addr[2:10], 16 )
					value = int( value[2:10], 16 )
					esp = int( esp[2:10], 16 )
					cc.execute( "insert into data(takt,addr,value,access_type) values(?,?,?,?)", ( takt, addr, value & 0xff, 'w' ) )
					cc.execute( "insert into data(takt,addr,value,access_type) values(?,?,?,?)", ( takt, addr+1, value >> 8 & 0xff, 'w' ) )
					cc.execute( "insert into data(takt,addr,value,access_type) values(?,?,?,?)", ( takt, addr+2, value >> 16 & 0xff, 'w' ) )
					cc.execute( "insert into data(takt,addr,value,access_type) values(?,?,?,?)", ( takt, addr+3, value >> 24 & 0xff, 'w' ) )
					pages[ addr & 0xfffff000 ] = ( "data", addr | 0xfff, PERM_R )
			elif line.find("->") != -1:
				m = re.match('^([^:]*):.*\[([^]]*)\]([^\s]*) ->.*\(([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+)\)', line)
				if m:
					eip, addr, value, eax,edx,ecx,ebx,esi,edi,ebp,esp = m.groups()
					eip = int( eip[2:10], 16 )
					addr = int( addr[2:10], 16 )
					value = int( value[2:10], 16 )
					esp = int( esp[2:10], 16 )
					cc.execute( "insert into data(takt,addr,value,access_type) values(?,?,?,?)", ( takt, addr, value & 0xff, 'r' ) )
					cc.execute( "insert into data(takt,addr,value,access_type) values(?,?,?,?)", ( takt, addr+1, value >> 8 & 0xff, 'r' ) )
					cc.execute( "insert into data(takt,addr,value,access_type) values(?,?,?,?)", ( takt, addr+2, value >> 16 & 0xff, 'r' ) )
					cc.execute( "insert into data(takt,addr,value,access_type) values(?,?,?,?)", ( takt, addr+3, value >> 24 & 0xff, 'r' ) )
					pages[ addr & 0xfffff000 ] = ( "data", addr | 0xfff,  PERM_W )
			elif line.find("!!") != -1:
				m = re.match( "^([^:]*):.*\(([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+)\)", line )
				if m:
					eip, eax,edx,ecx,ebx,esi,edi,ebp,esp = m.groups()
					syscall_number = int( eax[2:10], 16 )
					syscall_stack = int( edx[2:10], 16 )
					#cc.execute( "insert into syscalls values( {id}, {syscall_no} )".format( id=syscall_id, syscall_no=syscall_number ) )

cc.execute("create index takts_takt_index on takts(takt)")
cc.execute("create index code_takt_index on code(takt)")
cc.execute("create index code_eip_index on code(eip)")
cc.execute("create index data_takt_index on data(takt)")
c.commit()


page_id = 0
for low_addr,opts in pages.items():
	name, high_address, perms = opts
	res = cc.execute( "select id,perm_r,perm_w,perm_x from pages where low_addr = ?", (low_addr,) ).fetchone()
	if(res):
		page_id, perm_r, perm_w, perm_x = res
		if not perms & perm_r:
			cc.execute( "update pages set perm_r = 1 where id = ?", (page_id,) )
		if not perms & perm_w:
			cc.execute( "update pages set perm_w = 1 where id = ?", (page_id,) )
		if not perms & perm_x:
			cc.execute( "update pages set perm_x = 1 where id = ?", (page_id,) )
	else:
		page_id += 1
		perm_r = (perms&PERM_R)/PERM_R
		perm_w = (perms&PERM_W)/PERM_W
		perm_x = (perms&PERM_X)/PERM_X
		cc.execute( "insert into pages values( ?,?,?,?, ?,?,? )", (page_id, name, low_addr, high_address, perm_r, perm_w, perm_x) )


c.commit()
c.close()

