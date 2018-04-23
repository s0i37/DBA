import sqlite3
from sys import argv
from os.path import isfile
from random import random

if len(argv) != 2:
	print "%s calls_tree.txt" % argv[0]
	exit()

trace_file = argv[1]
is_need_init = not isfile("graph.db")
db = sqlite3.connect('graph.db')
sql = db.cursor()

if is_need_init:
	sql.execute("create table nodes(id text, label text, color text, size int, x int, y int, z int)")
	sql.execute("create table edges(source text, target text, weight int)")
	db.commit()

def _get_random_color():
	random_gradient_red = int( random() * (0xff) )
	random_gradient_green = int( random() * (0xff) )
	random_gradient_blue = int( random() * (0xff) )
	return '#%x%x%x' % (random_gradient_red, random_gradient_green, random_gradient_blue)

def _get_random_location():
	return ( random()*1000, random()*1000, random()*1000 )

colors = {}
def get_color(fcn):
	if fcn.startswith('sym.'):
		module = fcn[4:].split('_')[0]
		if not module in colors:
			colors[module] = _get_random_color()
		return colors[module]
	else:
		return '#000000'

locations = {}
def get_location(fcn):
	if fcn.startswith('sym.'):
		module = fcn[4:].split('_')[0]
		if not module in locations:
			locations[module] = _get_random_location()
		return locations[module]
	else:
		return (0,0,0)

fcns = set()
edges = set()
#calls = {}
fcn_prev = None
lines = 0
with open( trace_file ) as f:
	for line in f:
		try:
			deep, fcn = line.split()
		except:
			line = line.split()[0]
			deep = line[0]
			fcn = line[1:]
		deep = int(deep)
		color = get_color(fcn)
		location = get_location(fcn)
		if not fcn in fcns:
			sql.execute( 'insert into nodes(id, label, color, size, x, y, z) values(?,?,?,1,?,?,?)', ( fcn,fcn,color,location[0],location[1],location[2] ) )
			fcns.add(fcn)
			#calls[fcn] = 1
		#else:
			#calls[fcn] += 1
		if fcn_prev: #and not (fcn_prev,fcn) in edges:
			sql.execute( 'insert into edges(source, target, weight) values(?,?,1)', (fcn_prev,fcn) )
			edges.add( (fcn_prev,fcn) )
		fcn_prev = fcn
		lines += 1
		if lines % 10000 == 0:
			db.commit()
			print lines

#for fcn,count in calls.items():
#	sql.execute( 'update nodes set size = ? where label = ?', (count if count < 10 else 10,fcn) )

db.commit()
db.close()