#!/usr/bin/python
import r2pipe
import csv
import os
import json
from sys import argv
from colorama import Fore


def enum(r2):
	global symbols
	modulename = r2.cmd('iV~Internal[1]') if r2.cmd('iV~Internal[1]') else os.path.basename( r2.cmdj("ij")["core"]["file"] )
	for fcn in json.loads( r2.cmd('aflj') or '{}' ):
		try:
			name = fcn['name']
			start = int( fcn['minbound'] ) #% 0x100000000
			end = int( fcn['maxbound'] ) #% 0x100000000
			nargs = int( fcn['nargs'] )
			print Fore.LIGHTGREEN_EX + "[+] %s!%s 0x%x 0x%x %d" % (modulename, name, start, end, nargs) + Fore.RESET
			symbols.writerow( [modulename, name, "0x%08x"%start, "0x%08x"%end, nargs] )
		except Exception as e:
			print str(e)

def anal(filepath, base=None):
	if base:
		r2 = r2pipe.open(filepath, ["-B", base])
	else:
		r2 = r2pipe.open(filepath)
	r2.cmd("af @@ sym.*")
	#r2.cmd("aar")
	#r2.cmd("aac")
	#r2.cmd("aaa")
	#r2.cmd("aaaa")
	enum(r2)

symbols = csv.writer( open('symbols.csv','a'), delimiter=',' )
try:
	if len(argv) >= 2:
		path = argv[1]
		if os.path.isdir(path):
			for binary in os.listdir(path):
				anal( os.path.join(path, binary) )
		elif os.path.isfile(path):
			anal(path, base=argv[2] if len(argv) == 3 else None)
	else:
		r2 = r2pipe.open()
		enum(r2)
except:
	print "%s directory|file [0xBASE]" % argv[0]