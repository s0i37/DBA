import pydot
from sys import argv,stdout
from random import random

if len(argv) != 2:
	print "%s trace.txt" % argv[0]
	exit()

trace_file = argv[1]
graph = pydot.Dot(graph_type='graph')

eips = set()
edges = set()
eip_prev = None
lines = 0
with open( trace_file ) as f:
	for line in f:
		if line.find('{') != -1:
			(eip,opcode,regs) = line.split()
			(eip,thread) = map( lambda x: int(x, 16), eip.split(':') )
		else:
			continue
		
		if not eip in eips:
			graph.add_node( pydot.Node( hex(eip), style="filled" ) )
			eips.add(eip)
		if eip_prev and not (eip_prev,eip) in edges:
			graph.add_edge( pydot.Edge( hex(eip_prev), hex(eip) ) )
			edges.add( (eip_prev,eip) )
		eip_prev = eip
		lines += 1
		if lines % 10000 == 0:
			stdout.write( "\r%d" % lines )
			stdout.flush()

graph.write_png('out.png')