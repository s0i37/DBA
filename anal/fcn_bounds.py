#!/usr/bin/python
import r2pipe
import sqlite3
import os
from sys import argv
from colorama import Fore

def enum(prefix=''):
	global sql,modulename
	for fcn in r2.cmd('fq').split():
		try:
			r2.cmd('s %s' % fcn)
			start = int( r2.cmd('?v $FB @%s' % fcn), 16 )
			end = int( r2.cmd('?v $FE @%s' % fcn), 16 )
			args = int( r2.cmd('afi~args[1]') or 0 )
			print Fore.LIGHTGREEN_EX + "[+] %s%s 0x%x 0x%x %d" % (prefix, fcn, start, end, args) + Fore.RESET
			sql.execute( "insert into symbols(module,symbol,start,end,args) values(?,?,?,?,?)", (modulename, prefix+fcn, start, end, args) )
		except Exception as e:
			print str(e)

r2 = r2pipe.open()
modulename = r2.cmd('iV~Internal[1]')
if len(argv) > 1:
	modulename = argv[1]

db = sqlite3.connect('symbols.db')
sql = db.cursor()

start = int( '0x'+ os.path.basename( r2.cmd('i~^file').split()[1] ).split('.')[3], 16 )
end = start
for section_size in r2.cmd('iS~[9]').split():
	end += int(section_size)

print Fore.GREEN + "[+] %s 0x%x 0x%x" % (modulename, start, end) + Fore.RESET
sql.execute( "insert into modules(module,start,end) values(?,?,?)", (modulename, start, end) )

r2.cmd('fs functions')
enum('%s!'%modulename)
r2.cmd('fs symbols')
enum()

db.commit()
db.close()