#!/usr/bin/python2
import argparse
from lib.emulate import Trace, StopExecution, get_module, get_symbol
from os import path
from json import dumps
from random import random


WWW='''
<head>
  <style> body { margin: 0; } </style>
  <script src="https://unpkg.com/3d-force-graph"></script>
</head>
<body>
  <div id="3d-graph"></div>
  <script>
  	var xrefs = __xrefs__
    const elem = document.getElementById('3d-graph');
    const Graph = ForceGraph3D()(elem)
      .graphData(xrefs)
      .nodeAutoColorBy('color')
      .nodeLabel(node => `${node.module}!${node.name}`)
      .onNodeHover(node => elem.style.cursor = node ? 'pointer' : null)
      .onNodeClick(node => alert(`${node.id}: ${node.name}`));
  </script>
</body>
'''

parser = argparse.ArgumentParser( description='show graph by trace' )
parser.add_argument("tracefile", type=str, help="trace.log")
parser.add_argument("-modules", action='store_true', default=False, help="show modules statistic")
parser.add_argument("-functions", action='store_true', default=False, help="show modules statistic")
args = parser.parse_args()

class Module:
	def __init__(self, addr):
		self.addr = addr
		self.name = None
		self.start = 0
		self.end = 0

	def load_module(self, trace):
		module = get_module(trace, self.addr)
		if module:
			self.name = module.name
			self.start = module.start
			self.end = module.end

class Function:
	def __init__(self, addr):
		self.addr = addr
		self.calls = 0

	def load_symbol(self, trace):
		self.symbol = get_symbol(trace, self.addr)

def find_module(modules, addr):
	for module in modules:
		if module.start <= addr <= module.end:
			return module

def in_module(modules, addr, module_name):
	for module in modules:
		if module.start <= addr <= module.end and module.name.lower() == module_name:
			return True
	return False

colors = {}
def get_color(key=0):
	global colors
	color = colors.get(key)
	if not color:
		color = "#%02X%02X%02X" % (int(random()*255), int(random()*255), int(random()*255))
		colors[key] = color
	return color

current_function = None
current_module = None
modules = []
functions = {}
stack = {}
graph_functions = {'nodes': [], 'links': []}
graph_modules = {'nodes': [], 'links': []}
graph_functions_links = set()
graph_modules_links = set()
with Trace( open(args.tracefile) ) as trace:
	while True:
		try:
			trace.step()
			thr = trace.cpu.thread_id
			if not thr in stack.keys():
				stack[thr] = []

			if not current_module:
				current_module = find_module(trace.modules, trace.cpu.eip_before)

			if not current_function:
				current_function = functions.get(trace.cpu.eip_before)
				if not current_function:
					current_function = Function(trace.cpu.eip_before)
					current_function.load_symbol(trace)
					functions[trace.cpu.eip_before] = current_function
					graph_functions['nodes'].append(
						{
					      "id": current_function.addr,
					      "name": current_function.symbol or hex(current_function.addr),
					      "module": path.basename(current_module.name.replace('\\','/')) if current_module else 'unkn',
					      "color": get_color(current_module.name) if current_module else 'white'
					    }
					)
				if stack[thr] and stack[thr][-1].addr in functions:
					if not (stack[thr][-1].addr,current_function.addr) in graph_functions_links:
						graph_functions['links'].append(
							{
						      "source": stack[thr][-1].addr,
						      "target": current_function.addr,
						      "color": get_color(thr)
						    }
						)
						graph_functions_links.add((stack[thr][-1].addr,current_function.addr))

			if current_module and not current_module.name in modules:
				modules.append(current_module.name)
				graph_modules['nodes'].append(
					{
				      "id": current_module.start,
				      "name": current_module.name or hex(current_module.start),
				      "description": '',
				      "color": 'cyan'
				    }
				)
			if current_module and stack[thr] and not in_module(trace.modules, stack[thr][-1].addr, current_module.name):
				module = get_module(trace, stack[thr][-1].addr)
				if module:
					if not (module.start, current_module.start) in graph_modules_links:
						graph_modules['links'].append(
							{
						      "source": module.start,
						      "target": current_module.start
						    }
						)
						graph_modules_links.add((module.start, current_module.start))

			mnem = trace.cpu.disas()
			if mnem.split()[0] in ('call', ):
				stack[thr].append(current_function)
				current_function = None
				current_module = None
			elif mnem.split()[0] in ('ret', ):
				try:	current_function = stack[thr].pop()
				except:	current_function = Function(0)
		except Exception as e:
			#print str(e)
			continue
		except KeyboardInterrupt:
			break
		except StopExecution:
			break

if args.functions:
	with open('graph.html', 'w') as o:
		o.write( WWW.replace('__xrefs__', dumps(graph_functions)) )
if args.modules:
	with open('graph.html', 'w') as o:
		o.write( WWW.replace('__xrefs__', dumps(graph_modules)) )
