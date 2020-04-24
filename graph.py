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
  <script src="https://unpkg.com/three"></script>
  <script src="https://unpkg.com/three-spritetext"></script>
</head>
<body>
  <div id="3d-graph"></div>
  <script>
var xrefs = __xrefs__
var calls = __calls__
const elem = document.getElementById('3d-graph');
const nodes = {}
xrefs.nodes.forEach(node => {
  nodes[node.id] = node
})
xrefs.links.forEach(link => {
  const a = nodes[link.source];
  const b = nodes[link.target];
  !a.neighbors && (a.neighbors = []);
  !b.neighbors && (b.neighbors = []);
  a.neighbors.push(b);
  b.neighbors.push(a);

  !a.links && (a.links = []);
  !b.links && (b.links = []);
  a.links.push(link);
  b.links.push(link);
});

const highlightNodes = new Set();
const highlightLinks = new Set();
let hoverNode = null;

const Graph = ForceGraph3D()(elem)
  .graphData(xrefs)
  .nodeAutoColorBy('color')
  .nodeLabel(node => `${node.module}!${node.name}`)
  .onNodeClick(node => alert(`${node.id}: ${node.name}`))
  .onNodeDragEnd(node => {
    node.fx = node.x;
    node.fy = node.y;
    node.fz = node.z;
  })
  .nodeThreeObject(node => {
      const obj = new THREE.Mesh(
      new THREE.SphereGeometry(10),
      new THREE.MeshBasicMaterial({ depthWrite: false, transparent: true, opacity: 0 })
    );
    const sprite = new SpriteText(node.module ? `${node.module}!${node.name}` : node.name);
    //const sprite = new SpriteText(node.name);
    sprite.color = node.color;
    sprite.textHeight = 8;
    obj.add(sprite);
    return obj;
  })
  .nodeColor(node => highlightNodes.has(node) ? node === hoverNode ? 'rgb(255,0,0,1)' : 'rgba(255,160,0,0.8)' : 'rgba(0,255,255,0.6)')
  .linkWidth(link => highlightLinks.has(link) ? 4 : 1)
  .linkDirectionalParticles(link => highlightLinks.has(link) ? 4 : 0)
  .linkDirectionalParticleWidth(4)
  .onNodeHover(node => {
    if ((!node && !highlightNodes.size) || (node && hoverNode === node)) return;
    highlightNodes.clear();
    highlightLinks.clear();
    if (node) {
    highlightNodes.add(node);
    node.neighbors.forEach(neighbor => highlightNodes.add(neighbor));
    node.links.forEach(link => highlightLinks.add(link));
    }
    hoverNode = node || null;
    updateHighlight();
    })
  .onLinkHover(link => {
    highlightNodes.clear();
    highlightLinks.clear();
    if (link) {
      highlightLinks.add(link);
      highlightNodes.add(link.source);
      highlightNodes.add(link.target);
    }
    updateHighlight();
    });

function updateHighlight() {
  Graph
    .nodeColor(Graph.nodeColor())
    .linkWidth(Graph.linkWidth())
    .linkDirectionalParticles(Graph.linkDirectionalParticles());
};

//Graph.d3Force('link').distance(1000)
//Graph.numDimensions(3)

Graph.d3Force('charge').strength(-120);

if(calls)
{
	setInterval(function () {
		var edge, i
		highlightLinks.clear()
		edge = calls.shift()
		for(i = 0; i < xrefs.links.length; i++)
		{
			if(xrefs.links[i].source.id == edge[0] && xrefs.links[i].target.id == edge[1])
			{
				highlightLinks.add(xrefs.links[i])
				break
			}
		}
		updateHighlight()
	}, 500)
}
  </script>
</body>
'''
JS='''
var xrefs = __xrefs__
'''

parser = argparse.ArgumentParser( description='show graph by trace' )
parser.add_argument("tracefile", type=str, help="trace.log")
parser.add_argument("-modules", action='store_true', default=False, help="show modules flow")
parser.add_argument("-functions", action='store_true', default=False, help="show functions flow")
parser.add_argument("-animate", action='store_true', default=False, help="animate execution")
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
calls = []
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
					      "module": path.basename(current_module.name.replace('\\','/')) if current_module else '',
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
					if args.animate:
						calls.append((stack[thr][-1].addr, current_function.addr))

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

if args.animate:
	WWW = WWW.replace('__calls__', dumps(calls))
else:
	WWW = WWW.replace('__calls__', '[]')

if args.functions:
	with open('graph.html', 'w') as o:
		o.write( WWW.replace('__xrefs__', dumps(graph_functions)) )
if args.modules:
	with open('graph.html', 'w') as o:
		o.write( WWW.replace('__xrefs__', dumps(graph_modules)) )
