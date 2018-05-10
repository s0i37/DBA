#!/usr/bin/python
import r2pipe
import csv
import os
import json
from sys import argv
from colorama import Fore

if len(argv) < 2:
	print "%s directory|file"
	exit()

def enum(r2):
	global symbols
	modulename = r2.cmd('iV~Internal[1]')
	for fcn in json.loads( r2.cmd('aflj') or '{}' ):
		try:
			name = fcn['name']
			start = int( fcn['minbound'] )
			end = int( fcn['maxbound'] )
			nargs = int( fcn['nargs'] )
			print Fore.LIGHTGREEN_EX + "[+] %s!%s 0x%x 0x%x %d" % (modulename, name, start, end, nargs) + Fore.RESET
			symbols.writerow( [modulename, name, start, end, nargs] )
		except Exception as e:
			print str(e)

def anal(filepath):
	r2 = r2pipe.open(filepath)
	r2.cmd("af @@ sym.*")
	#r2.cmd("aar")
	#r2.cmd("aac")
	enum(r2)

symbols = csv.writer( open('symbols.csv','a'), delimiter=',' )
path = argv[1]
if os.path.isdir(path):
	for binary in os.listdir(path):
		anal( os.path.join(path, binary) )
elif os.path.isfile(path):
	anal(path)
