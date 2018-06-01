from PIL import Image, ImageDraw, ImageFont
from random import random
from sys import argv,stdout
import argparse
import os
import csv
from colorama import Fore

WIDTH = 4096
HEIGHT = 3072
MARGIN = 10

modules = {}
symbols = {}

parser = argparse.ArgumentParser( description='execution trace visualization tool' )
parser.add_argument("tracefile", type=str, help="trace.txt")
parser.add_argument("symbols", nargs='?', default='', help="symbols.csv")
parser.add_argument("-from_addr", type=int, default=0, help="from address")
parser.add_argument("-to_addr", type=int, default=0, help="to address")
parser.add_argument("-modules", nargs="+", help="draw only specified modules")
parser.add_argument("-from_takt", type=int, default=0, help="from takt")
parser.add_argument("-to_takt", type=int, default=0, help="to takt")
args = parser.parse_args()

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

if os.path.isfile(args.symbols):
	for (modulename, symbol, start, end, nargs) in csv.reader( open(args.symbols, 'r'), delimiter=',' ):
		start = int(start, 16)
		end = int(end, 16)
		symbols[symbol] = [start, end]
		if modules.get(modulename):
			if start < modules[modulename][0]:
				modules[modulename][0] = start
			if end > modules[modulename][1]:
				modules[modulename][1] = end
		else:
			modules[modulename] = [start, end]

for (modulename,_range) in modules.items():
	print Fore.LIGHTBLACK_EX + "%s 0x%08x 0x%08x" % (modulename, _range[0], _range[1]) + Fore.RESET

img = Image.new( 'RGB', (WIDTH,HEIGHT), "white" )
draw = ImageDraw.Draw(img)
pixels = img.load()
        
eips = []
mems_w = []
stack = []
takt = 0
instr = 0
memop_r = 0
memop_w = 0

modules_used = {}
symbols_used = {}
module = {}
symbol = {}
with open( args.tracefile ) as f:
	for line in f:
		try:
			if line.find('{') != -1:
				(eip,opcode,regs) = line.split()
				(eip,thread) = map( lambda x: int(x, 16), eip.split(':') )
				(eax,ecx,edx,ebx,esp,ebp,esi,edi) = map( lambda x: int(x,16), regs.split(',') )
				memory = None
				takt += 1
			elif line.find('[') != -1:
				(eip,memory,direction,value) = line.split()
				(eip,thread) = map( lambda x: int(x, 16), eip.split(':') )
				memory = int( memory[1:-1], 16 )
				value = int( value, 16 )
				opcode = None
				if direction == "->":
					memop_r += 1
				elif direction == "<-":
					memop_w += 1
			else:
				continue
		except Exception as e:
			continue

		if args.from_addr == 0 and args.to_addr == 0 or args.from_addr <= eip <= args.to_addr:
			if args.from_takt == 0 or args.from_takt <= takt:

				if opcode != None:
					if not ( module and module['start'] <= eip <= module['end'] ):
						module = get_module(eip)
						if args.modules and module and not module['name'] in args.modules:
							continue

						if module and not module['name'] in modules_used.keys():
							modules_used[ module['name'] ] = [ module['start'], module['end'] ]

						if not symbol or symbol['start'] > eip or eip > symbol['end']:
							symbol = get_symbol(eip)
							if symbol and not symbol['name'] in symbols_used.keys():
								symbols_used[ symbol['name'] ] = [ symbol['start'], symbol['end'] ]

					if not args.modules or module.get('name') in args.modules:
						eips.append(eip)
						instr += 1
					else:
						eips.append(None)
				
		if args.from_addr == 0 and args.to_addr == 0 or args.from_addr <= memory <= args.to_addr:
			if args.from_takt == 0 or args.from_takt <= takt:
				if memory != None and direction == '<-':
					mems_w.append(memory)
				else:
					mems_w.append(None)
			else:
				mems_w.append(None)
		else:
			mems_w.append(None)

		if args.from_addr == 0 and args.to_addr == 0 or args.from_addr <= esp <= args.to_addr:
			if args.from_takt == 0 or args.from_takt <= takt:
				stack.append(esp)
			else:
				stack.append(None)
		else:
			stack.append(None)

		if takt and takt % 10000 == 0:
			stdout.write( "\r%d/%d (r:%d, w:%d) %s %s" % ( instr, takt, memop_r, memop_w, module.get('name') or '', symbol.get('name') or '' ) )
			stdout.flush()

		if args.to_takt and takt > args.to_takt:
			break

if not eips:
	print "nothing instructions"
	exit()

if args.modules:
	min_addr = min( map( lambda m: modules[m][0], args.modules) )
	max_addr = max( map( lambda m: modules[m][1], args.modules) )
else:
	min_addr = min( filter( lambda p: p != None, eips + mems_w + stack ) )
	max_addr = max( filter( lambda p: p != None, eips + mems_w + stack ) )

y_scale = float(max_addr - min_addr)/(HEIGHT-MARGIN-MARGIN)
x_scale = float(takt - args.from_takt)/(WIDTH-MARGIN-MARGIN)


for modulename, _range in modules_used.items():
	(start,end) = _range
	low = int( (start-min_addr)/y_scale ) + MARGIN
	high = int( (end-min_addr)/y_scale ) + MARGIN
	draw.rectangle( ( ( 0, low ), ( WIDTH, high ) ), fill=( 0, 200, 200+int(random()*(0xff-200)) ) )
	draw.text( (0, low ), modulename, 'black', font=ImageFont.truetype("/usr/share/fonts/truetype/freefont/FreeMono.ttf", 12))

if 1:#len( modules_used.keys() ) == 1:
	for symbolname, _range in symbols_used.items():
		(start,end) = _range
		low = int( (start-min_addr)/y_scale ) + MARGIN
		high = int( (end-min_addr)/y_scale ) + MARGIN
		draw.rectangle( ( ( 0, low ), ( WIDTH, high ) ), fill=( 0, 200+int(random()*(0xff-200)), 200 ) )
		draw.text( (0, low ), symbolname, 'black', font=ImageFont.truetype("/usr/share/fonts/truetype/freefont/FreeMono.ttf", 12))

for _takt in xrange( args.from_takt, takt, (takt - args.from_takt)/10 ):
	border = int((_takt-args.from_takt)/x_scale) + MARGIN
	draw.line( ( border, 0, border, HEIGHT ), fill=(212,212,212) )
	draw.text( ( border, 0 ), str(_takt), 'black', font=ImageFont.truetype("/usr/share/fonts/truetype/freefont/FreeMono.ttf", 12))

for _addr in xrange( min_addr, max_addr, (max_addr - min_addr)/10 ):
	border = int((_addr-min_addr)/y_scale) + MARGIN
	draw.line( ( 0, border, WIDTH, border ), fill=(212,212,212) )
	draw.text( ( 0, border ), "0x%08x"%_addr, 'black', font=ImageFont.truetype("/usr/share/fonts/truetype/freefont/FreeMono.ttf", 12))


i = 0
#last_x = last_y = None
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
			#print 'gap %d %d' % (y1, y2)
		#	for j in xrange( y1+1, y2-1 ):
		#		pixels[ x, j ] = (255, 248, 248)
		#last_x = x
		#last_y = y
	except Exception as e:
		#print str(e) + " %d %d 0x%x" % (x,y, eip)
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
		#print str(e) + " %d %d [0x%x]" % (x,y, mem)
		pass

i = 0
for mem in mems_w:
	i += 1
	if mem == None:
		continue
	try:
		x = int( i / x_scale ) + MARGIN
		y = int( (mem-min_addr) / y_scale ) + MARGIN
		pixels[ x, y ] = (0, 255, 0)
	except Exception as e:
		#print str(e) + " %d %d [0x%x]" % (x,y, mem)
		pass

#img.show()
img.save('out.png')