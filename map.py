#!/usr/bin/python
# -*- coding: utf-8 -*-
from PIL import Image, ImageDraw, ImageFont
from random import random
from sys import argv,stdout
import argparse
import os
from colorama import Fore

WIDTH = 4096
HEIGHT = 3072
MARGIN = 10

modules = {}
symbols = {}

eip_min = None
eip_max = None

parser = argparse.ArgumentParser( description='execution trace visualization tool' )
parser.add_argument("output", type=str, default='out.png', help="out.png")

parser.add_argument("-exec", dest="trace_file", type=str, default='', help="trace.txt")
parser.add_argument("-symbols", type=str, default='', help="symbols.txt")

parser.add_argument("-from_addr", type=int, default=0, help="from address")
parser.add_argument("-to_addr", type=int, default=0, help="to address")
parser.add_argument("-module", type=str, default='', help="draw just module")
#parser.add_argument("-symbol", type=str, default='', help="draw just symbol (not implemented)")
parser.add_argument("-from_takt", type=int, default=0, help="from takt")
parser.add_argument("-to_takt", type=int, default=0, help="to takt")
args = parser.parse_args()


# load symbols
if os.path.isfile(args.symbols):
	with open(args.symbols) as f:
		for line in f:
			(symbol, start, end) = line.split()
			start = int(start, 16)
			end = int(end, 16)
			symbols[symbol] = [start, end]
			eip_min = start if start < eip_min else eip_min
			eip_max = start if start > eip_max else eip_max

#		if modules.get(modulename):
#			if start < modules[modulename][0]:
#				modules[modulename][0] = start
#			if end > modules[modulename][1]:
#				modules[modulename][1] = end
#		else:
#			modules[modulename] = [start, end]

for (modulename,_range) in modules.items():
	print Fore.LIGHTBLACK_EX + "%s 0x%08x 0x%08x" % (modulename, _range[0], _range[1]) + Fore.RESET

img = Image.new('RGB', (WIDTH,HEIGHT), "white")
draw = ImageDraw.Draw(img)
pixels = img.load()
        
#for performance reason
last_module = {}
last_symbol = {}

modules_used = {}
symbols_used = {}

def get_module(eip):
	global modules
	for (modulename,_range) in modules.items():
		(start,end) = _range
		if start <= eip <= end:
			return { 'name': modulename, 'start': start, 'end': end }
	return {}

def get_symbol(eip):
	global symbols
	for (symbol,_range) in symbols.items():
		(start,end) = _range
		if start <= eip <= end:
			return { 'name': symbol, 'start': start, 'end': end }
	return {}

def whereis(eip):
	global last_module, last_symbol, modules_used, symbols_used
	if not ( last_module and last_module['start'] <= eip <= last_module['end'] ):
		last_module = get_module(eip)
		if args.module and last_module and not args.module in last_module['name']:
			return ({},{})

		if last_module and not last_module['name'] in modules_used.keys():
			modules_used[ last_module['name'] ] = [ last_module['start'], last_module['end'] ]

	if not last_symbol or last_symbol['start'] > eip or eip > last_symbol['end']:
		last_symbol = get_symbol(eip)
		if last_symbol and not last_symbol['name'] in symbols_used.keys():
			symbols_used[ last_symbol['name'] ] = [ last_symbol['start'], last_symbol['end'] ]
	return (last_module,last_symbol)

eips = []
def save_eip(eip):
	global eips, eip_min, eip_max
	if (args.from_addr == 0 and args.to_addr == 0) or args.from_addr <= eip <= args.to_addr:
		if args.from_takt == 0 or args.from_takt <= takt:
			(module,symbol) = whereis(eip)
			if not args.module or args.module in module.get('name',''):
				eips.append(eip)
				if not eip_min or eip < eip_min:
					eip_min = eip
				if not eip_max or eip > eip_max:
					eip_max = eip
				return True
			else:
				eips.append(None)
	return False

rmems = []
rmem_min = None
rmem_max = None
def save_rmem_ptr(memory):
	global rmems, rmem_min, rmem_max
	if (args.from_addr == 0 and args.to_addr == 0) or args.from_addr <= memory <= args.to_addr:
		if args.from_takt == 0 or args.from_takt <= takt:
			(module,symbol) = whereis(eip)
			if not args.module or args.module in module.get('name',''):
				if memory != None and direction == '->':
					rmems.append(memory)
					if not rmem_min or memory < rmem_min:
						rmem_min = memory
					if not rmem_max or memory > rmem_max:
						rmem_max = memory
					return True
				else:
					rmems.append(None)
			else:
				rmems.append(None)
	return False

wmems = []
wmem_min = None
wmem_max = None
def save_wmem_ptr(memory):
	global wmems, wmem_min, wmem_max
	if (args.from_addr == 0 and args.to_addr == 0) or args.from_addr <= memory <= args.to_addr:
		if args.from_takt == 0 or args.from_takt <= takt:
			(module,symbol) = whereis(eip)
			if not args.module or args.module in module.get('name',''):
				if memory != None and direction == '<-':
					wmems.append(memory)
					if not wmem_min or memory < wmem_min:
						wmem_min = memory
					if not wmem_max or memory > wmem_max:
						wmem_max = memory
					return True
				else:
					wmems.append(None)
			else:
				wmems.append(None)
	return False


stack = []
stack_min = None
stack_max = None
def save_esp(esp):
	global stack, stack_min, stack_max
	if args.from_addr == 0 and args.to_addr == 0 or args.from_addr <= esp <= args.to_addr:
		if args.from_takt == 0 or args.from_takt <= takt:
			stack.append(esp)
			if not stack_min or esp < stack_min:
				stack_min = esp
			if not stack_max or esp > stack_max:
				stack_max = esp
			return True
	return False

heap = []
def save_heap_ptr():
	pass

instr = 0
memop_r = 0
memop_r_covered = 0
memop_w = 0
memop_w_covered = 0

#load trace
if os.path.isfile(args.trace_file):
	with open( args.trace_file ) as f:
		for line in f:
			try:
				#comment found
				if line.startswith('[#]'):
					continue
				#module found
				elif line.startswith('[*] module'):
					(_, _, modulename, start, end) = line.split()
					start = int(start, 16)
					end = int(end, 16)
					modules[modulename] = [start, end]
					print "[*] %s 0x%08x 0x%08x" % (modulename, start, end)
					continue
				#symbol found
				elif line.startswith('[*] function'):
					(_, _, symbol, start, end) = line.split()
					start = int(start, 16)
					end = int(end, 16)
					symbols[symbol] = [start, end]
					continue
				#instruction found
				elif line.find('{') != -1:
					(eip,opcode,regs) = line.split()
					takt = int( eip.split(':')[0] )
					(eip,thread) = map( lambda x: int(x, 16), eip.split(':')[1:] )
					(eax,ecx,edx,ebx,esp,ebp,esi,edi) = map( lambda x: int(x,16), regs.split(',') )
					memory = None
				#memory found
				elif line.find('[') != -1:
					(eip,memory,direction,value) = line.split()
					takt = int( eip.split(':')[0] )
					(eip,thread) = map( lambda x: int(x, 16), eip.split(':')[1:] )
					memory = int( memory[1:-1], 16 )
					value = int( value, 16 )
					opcode = None
					if direction == "->":
						memop_r += 1
					elif direction == "<-":
						memop_w += 1
				#nothing
				else:
					continue
			except Exception as e:
				continue

			if opcode:
				if save_eip(eip):
					instr += 1
				save_esp(esp)
			elif memory != None:
				if direction == "<-" and save_wmem_ptr(memory):
					memop_w_covered += 1
				elif direction == "->" and save_rmem_ptr(memory):
					memop_r_covered += 1
		
			if args.to_takt and takt > args.to_takt:
				break		

			if takt and takt % 10000 == 0:
				stdout.write( "\rx:%d/%d, r:%d/%d, w:%d/%d %s %s" % ( instr, takt, memop_r_covered, memop_r, memop_w_covered, memop_w, last_module.get('name') or '', last_symbol.get('name') or '' ) )
				stdout.flush()

'''if eip_min == None and wmem_min == None and stack_min == None:
	print "no instructions, writed memory and stack usage"
	exit()'''

if args.module:
	for module,ranges in modules.items():
		if args.module in module:
			(min_addr,max_addr) = ranges
			break
else:
	min_addr = min( filter( lambda p: p != None, [eip_min, wmem_min, stack_min] ) )
	max_addr = max( filter( lambda p: p != None, [eip_max, wmem_max, stack_max] ) )

y_scale = float(max_addr - min_addr)/(HEIGHT-MARGIN-MARGIN)
x_scale = float(takt - args.from_takt)/(WIDTH-MARGIN-MARGIN)


for modulename, _range in modules_used.items():
	(start,end) = _range
	low = int( (start-min_addr)/y_scale ) + MARGIN
	high = int( (end-min_addr)/y_scale ) + MARGIN
	draw.rectangle( ( ( 0, low ), ( WIDTH, high ) ), fill=( 0, 200, 200+int(random()*(0xff-200)) ) )
	draw.text( (0, low ), modulename, 'grey', font=ImageFont.truetype("/usr/share/fonts/truetype/freefont/FreeMono.ttf", 12))

if len( modules_used.keys() ) == 1:
	for symbolname, _range in symbols_used.items():
		(start,end) = _range
		low = int( (start-min_addr)/y_scale ) + MARGIN
		high = int( (end-min_addr)/y_scale ) + MARGIN
		draw.rectangle( ( ( 0, low ), ( WIDTH, high ) ), fill=( 0, 200+int(random()*(0xff-200)), 200 ) )
		draw.text( (0, low ), symbolname, 'blue', font=ImageFont.truetype("/usr/share/fonts/truetype/freefont/FreeMono.ttf", 12))

for _takt in xrange( args.from_takt, takt, (takt - args.from_takt)/10 ):
	border = int((_takt-args.from_takt)/x_scale) + MARGIN
	draw.line( ( border, 0, border, HEIGHT ), fill=(212,212,212) )
	draw.text( ( border, 0 ), str(_takt), 'black', font=ImageFont.truetype("/usr/share/fonts/truetype/freefont/FreeMono.ttf", 12))

for _addr in xrange( min_addr, max_addr, (max_addr - min_addr)/10 ):
	border = int((_addr-min_addr)/y_scale) + MARGIN
	draw.line( ( 0, border, WIDTH, border ), fill=(212,212,212) )
	draw.text( ( 0, border ), "0x%08x"%_addr, 'black', font=ImageFont.truetype("/usr/share/fonts/truetype/freefont/FreeMono.ttf", 12))


i = 0
#last_x = None
#last_y = None
for eip in eips:
	i += 1
	if eip == None:
		continue
	try:
		x = int( i / x_scale ) + MARGIN
		y = int( (eip-min_addr) / y_scale ) + MARGIN
		pixels[ x, y ] = (255, 0, 0)
		
		#if last_x and last_y and (last_x == x or last_x+1 == x) and last_y != y:
		#	y1 = min( [y, last_y] )
		#	y2 = max( [y, last_y] )
		
		#	for j in xrange( y1+1, y2-1 ):
		#		pixels[ x, j ] = (255, 248, 248)
		#last_x = x
		#last_y = y
	except Exception as e:
		pass

i = 0
for mem in wmems:
	i += 1
	if mem == None:
		continue
	try:
		x = int( i / x_scale ) + MARGIN
		y = int( (mem-min_addr) / y_scale ) + MARGIN
		pixels[ x, y ] = (0, 255, 0)
	except Exception as e:
		pass

i = 0
for sp in stack:
	i += 1
	if sp == None:
		continue
	try:
		x = int( i / x_scale ) + MARGIN
		y = int( (sp-min_addr) / y_scale ) + MARGIN
		pixels[ x, y ] = (255, 0, 255)
	except Exception as e:
		pass

img.save( args.output )


'''
!the problem:
	eips - узкое место. Если инструкций будет 100М то памяти не хватит
'''