from PIL import Image, ImageDraw, ImageFont
from random import random
from sys import argv
import sqlite3

WIDTH = 4096
HEIGHT = 3072
min_bound = 0x0
max_bound = 0x80000000

if len(argv) != 3:
	print "%s trace.txt symbols.db" % argv[0]
	exit()

def get_module(eip):
	global modules
	for module,bounds in modules.items():
		if bounds[0] <= eip <= bounds[1]:
			return module

trace_file = argv[1]
symbols_db = argv[2]
db = sqlite3.connect(symbols_db)
sql = db.cursor()

modules = {}
for info in sql.execute( 'select * from modules' ).fetchall():
	module,start,end = info
	modules.update( { module: [ int(start), int(end) ] } )


img = Image.new( 'RGB', (WIDTH,HEIGHT), "white" )
draw = ImageDraw.Draw(img)
pixels = img.load()
        
eips = []
instr_count = 0
function_names = []
functions_regions = []
functions_bounds = {}


#def get_func_bound(addr):
#	func = get_func(addr)
#	if func:
#		return ( func.startEA, func.endEA )
#	else:
#		print hex(addr)
#	return (0,0)

modules_used = []
with open( trace_file ) as f:
	for line in f:
		eip = line.split()[1][1:11]
		eip = int(eip, 16)
		if min_bound <= eip <= max_bound:
			
			#if not eip in functions_regions:
			#	function_name = GetFunctionName(eip)
			#	if not function_name in function_names:
			#		function_names.append(function_name)
			#		function_bounds = get_func_bound(eip)
			#		functions_regions.extend( xrange( *function_bounds ) )
			#		functions_bounds[function_name] = function_bounds

			eips.append(eip)
			module = get_module(eip)
			if module and not module in modules_used:
				modules_used.append(module)
			instr_count += 1
		if instr_count and instr_count % 100000 == 0:
			print instr_count

min_eip = min(eips)
max_eip = max(eips)
y_scale = float(max_eip - min_eip)/(HEIGHT-1)
x_scale = float(instr_count)/(WIDTH-1)


for module in modules_used:
	bounds = modules[module]
	draw.rectangle( ( ( 0, int((bounds[0]-min_eip)/y_scale) ), ( WIDTH, int((bounds[1]-min_eip)/y_scale) ) ), fill=( 0, 200+int(random()*(0xff-200)), 200+int(random()*(0xff-200)) ) )

for module in modules_used:
	bounds = modules[module]
	draw.text( (0, int((bounds[0]-min_eip)/y_scale)), module, 'black', font=ImageFont.truetype("/usr/share/fonts/truetype/freefont/FreeMono.ttf", 12))


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