from PIL import Image, ImageDraw, ImageFont
from random import random
from sys import argv,stdout
import argparse
import os
import csv
from colorama import Fore

WIDTH = 4096
HEIGHT = 3072

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
takt = 0

modules_used = {}
symbols_used = {}
module = {}
symbol = {}
with open( args.tracefile ) as f:
	for line in f:
		try:
			eip = line.split()[1][1:11]
			eip = int(eip, 16)
		except:
			continue
		takt += 1

		if args.from_addr == 0 and args.to_addr == 0 or args.from_addr <= eip <= args.to_addr:
			if args.from_takt == 0 or args.from_takt <= takt:
				if not ( module and module['start'] <= eip <= module['end'] ):
					module = get_module(eip)
					if module and not module['name'] in modules_used.keys():
						modules_used[ module['name'] ] = [ module['start'], module['end'] ]

					if not ( symbol and symbol['start'] <= eip <= symbol['end'] ):
						symbol = get_symbol(eip)
						if symbol and not symbol['name'] in symbols_used.keys():
							symbols_used[ symbol['name'] ] = [ symbol['start'], symbol['end'] ]

				if args.modules and module and not module['name'] in args.modules:
					pass
				else:
					eips.append(eip)

		if takt and takt % 10000 == 0:
			stdout.write( "\r%d/%d %s %s" % ( len(eips), takt, module.get('name') or '', symbol.get('name') or '' ) )
			stdout.flush()

		if args.to_takt and takt > args.to_takt:
			break

if not eips:
	print "nothing instructions"
	exit()

if args.modules:
	min_eip = min( map( lambda m: modules[m][0], args.modules) )
	max_eip = max( map( lambda m: modules[m][1], args.modules) )
else:
	min_eip = min(eips)
	max_eip = max(eips)

y_scale = float(max_eip - min_eip)/(HEIGHT-1)
x_scale = float(takt - args.from_takt)/(WIDTH-1)


for modulename, _range in modules_used.items():
	(start,end) = _range
	draw.rectangle( ( ( 0, int( (start-min_eip)/y_scale ) ), ( WIDTH, int( (end-min_eip)/y_scale ) ) ), fill=( 0, 200, 200+int(random()*(0xff-200)) ) )
	draw.text( (0, int( (start-min_eip)/y_scale) ), modulename, 'black', font=ImageFont.truetype("/usr/share/fonts/truetype/freefont/FreeMono.ttf", 12))

for symbolname, _range in symbols_used.items():
	(start,end) = _range
	draw.rectangle( ( ( 0, int( (start-min_eip)/y_scale ) ), ( WIDTH, int( (end-min_eip)/y_scale ) ) ), fill=( 0, 200+int(random()*(0xff-200)), 200 ) )
	draw.text( (0, int( (start-min_eip)/y_scale) ), symbolname, 'black', font=ImageFont.truetype("/usr/share/fonts/truetype/freefont/FreeMono.ttf", 12))

for _takt in xrange( args.from_takt, takt, (takt - args.from_takt)/10 ):
	draw.line( ( int((_takt-args.from_takt)/x_scale), 0, int((_takt-args.from_takt)/x_scale), HEIGHT ), fill=(0,0,0) )
	draw.text( ( int((_takt-args.from_takt)/x_scale), 10 ), str(_takt), 'black', font=ImageFont.truetype("/usr/share/fonts/truetype/freefont/FreeMono.ttf", 12))

for _addr in xrange( min_eip, max_eip, (max_eip - min_eip)/10 ):
	draw.line( ( 0, int((_addr-min_eip)/y_scale), WIDTH, int((_addr-min_eip)/y_scale) ), fill=(0,0,0) )
	draw.text( ( 0, int((_addr-min_eip)/y_scale) ), "0x%08x"%_addr, 'black', font=ImageFont.truetype("/usr/share/fonts/truetype/freefont/FreeMono.ttf", 12))


i = 0
last_x = last_y = None
for eip in eips:
	try:
		x = int( i / x_scale )
		y = int( (eip-min_eip) / y_scale )
		pixels[ x, y ] = (255, 0, 0)
		
		#if last_x and last_y and (last_x == x or last_x+1 == x) and last_y != y:
		#	y1 = min( [y, last_y] )
		#	y2 = max( [y, last_y] )
			#print 'gap %d %d' % (y1, y2)
		#	for j in xrange( y1+1, y2-1 ):
		#		pixels[ x, j ] = (255, 248, 248)
		
		last_x = x
		last_y = y
		i += 1
	except Exception as e:
		print str(e) + " %d %d 0x%x" % (x,y, eip)


#img.show()
img.save('out.png')