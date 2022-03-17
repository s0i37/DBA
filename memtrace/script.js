function goto_code(addr)
{
	if(!addr)
		return
	var target = document.getElementById('instr_'+addr)
	document.getElementById('code').scrollTop = target.offsetTop - 100
	highlight(target)
	return addr
}
function goto_data(addr)
{
	if(!addr)
		return
	var target = document.getElementById('cell_'+addr)
	document.getElementById('data').scrollTop = target.parentElement.offsetTop - 100
	highlight(target)
	return addr
}
function goto_stack(addr)
{
	if(!addr)
		return
	addr = (addr >> 2) << 2
	var target = document.getElementById('stack_'+addr)
	document.getElementById('stack').scrollTop = target.offsetTop - 10 - document.getElementById('stack') - document.getElementById('calls').offsetTop - 100
	highlight(target)
	return addr
}
function goto_tree(n)
{
	if(!n)
		return
	var call = document.getElementById('call_'+n)
	document.getElementById('calls').scrollTop = call.offsetTop - 20 - document.getElementById('calls').offsetTop
	return n
}

function takt_handler(event) {
	var elem = event.target, takt
	if(elem.id == 'trace_position' || elem.id == 'trace_position_value')
	{
		takt = parseInt(elem.value)
		Memory.load(takt)
		Execution.instruction(takt)
	}
	else if(elem.classList.contains('takt'))
	{
		takt = parseInt($(elem).attr('takt'))
		Memory.load(takt)
		Execution.instruction(takt)
	}
}

$(document).ready( function() {
	$('#data').click( function(event) {
	  $('#dialog').dialog( {
		  	modal: false,
		  	maxHeight: 500,
		  	title: 'changes',
		  	open: function()
		  	{
		  		if(! event.target.classList.contains('cell'))
		  		{
		  			$('#dialog').dialog('close')
		  			return
		  		}
		  		
		  		var out = ''
		  		$.ajax( { url: "http://127.0.0.1:5000/data/" + $(event.target).attr('addr') + "/accesses",
					dataType: 'json',
					async: false } )
				.done( function(results) {
					results.forEach( function(v) {
						//console.log(v)
						var takt = v[0], eip = v[1], val = v[2], access_type = v[3]
						if(access_type == 'w')
							out += '<div class="access_write"><span class="takt" takt=' + takt + '>' + takt + '</span>  <a class="addr" onclick="goto_code(' + eip + ')">0x' + DWORD(eip) + '</a> <- ' + BYTE(val) + '</div>'
						else if(access_type == 'r')
							out += '<div class="access_read"><span class="takt" takt=' + takt + '>' + takt + '</span>  <a class="addr" onclick="goto_code(' + eip + ')">0x' + DWORD(eip) + '</a> -> ' + BYTE(val) + '</div>'
					} )
					$('#dialog').dialog("option", "width", 400);
		  			$('#dialog').html(out)
				} )
		  	},
		  	close: function()
		  	{
		  		$('#dialog').text('loading...')
		  	}
	  	} )

	  $('#dialog').click(takt_handler)
	} )

	$('#code').click( function(event) {
		$('#dialog').dialog( {
		  	modal: false,
		  	maxHeight: 500,
		  	open: function()
		  	{
		  		var elem = event.target
		  		while(1)
		  		{
		  			if(elem.classList.contains('instr'))
		  				break
		  			else if(elem.tagName == 'HTML')
		  			{
		  				$('#dialog').dialog('close')
		  				return
		  			}
		  			else
		  				elem = elem.parentNode
		  		}

				var out = ''		  		
		  		$.ajax( { url: "http://127.0.0.1:5000/code/" + $(elem).attr('eip') + "/accesses",
					dataType: 'json',
					async: false } )
				.done( function(results) {
					results.forEach( function(v) {
						//console.log(v)
						var takt = v[0], addr = v[1], val = v[2], access_type = v[3]
						if(access_type == 'w')
							out += '<div class="access_write"><span class="takt" takt=' + takt + '>' + takt + '</span>  <a class="addr" onclick="goto_data(' + addr + ')">0x' + DWORD(addr) + '</a> <- ' + BYTE(val) + '</div>'
						else if(access_type == 'r')
							out += '<div class="access_read"><span class="takt" takt=' + takt + '>' + takt + '</span>  <a class="addr" onclick="goto_data(' + addr + ')">0x' + DWORD(addr) + '</a> -> ' + BYTE(val) + '</div>'
					} )
					$('#dialog').dialog("option", "width", 400);
		  			$('#dialog').dialog("option", "title", 'memory operations');
		  			$('#dialog').html(out)
				} )		  		
		  	},
		  	close: function()
		  	{
		  		$('#dialog').text('loading...')
		  	}
		} )

		$('#dialog').click(takt_handler)
	} )

	document.getElementById('trace_position').onchange = takt_handler
	document.getElementById('trace_position_value').onchange = takt_handler
	/*
	$('#code code').each(function(i, block) {
    	hljs.highlightBlock(block);
  	})
	*/
	Tree.load(CallsTree)
	//$('#code_graph').dialog({title: 'code graph', width: '50%', height: '50%'})
} )

function telescope(addr)
{
	for(var page in MemoryMap)
		if(MemoryMap[page][0] <= addr && addr < MemoryMap[page][1])
			return page
	return ""
}
function is_stack(addr)
{
	return telescope(addr).indexOf("stack") == 0
}

function BYTE(val)
{
	return sprintf("%02X", val)
}
function WORD(val)
{
	return sprintf("%04X", val)
}
function DWORD(val)
{
	return sprintf("%08X", val)
}

var Memory = {
	bytes: {},
	highlighted: {},
	BYTE: function(addr) { return this.bytes[addr] },
	WORD: function(addr) { return this.bytes[addr] + this.bytes[addr+1] },
	DWORD: function(addr) { return this.bytes[addr] + this.bytes[addr+1] + this.bytes[addr+2] + this.bytes[addr+3] },
	unhighlight: function()
	{
		var cells = document.getElementsByClassName("cell")
		for(i = 0; i < cells.length; i++)
			cells[i].classList.remove("byte_changed")
	},
	access: function(addr)
	{
		$.ajax( { url: "http://127.0.0.1:5000/takt/" + this.takt + "/access",
			dataType: 'json',
			async: false } )
		.done( function(results) {
			results.forEach( function(v) {} )
		} )
	},
	read: function(addr)
	{
		var cell = document.getElementById("cell_"+addr)
		cell.classList.remove("byte_changed")
		cell.classList.add("byte_read")
		if(is_stack(addr))
		{
			Stack.read(addr)
			goto_stack(addr)
		}

		for(var takt in this.highlighted)
		{
			if(takt != Execution.takt && !this.highlighted[Execution.takt])
				for(var _addr in this.highlighted[takt])
				{
					var _cell = document.getElementById("cell_"+_addr)
					_cell.classList.remove( this.highlighted[takt][_addr].pop() )
					var next = this.highlighted[takt][_addr].pop()
					if(next)
					{
						_cell.classList.add(next)
						this.highlighted[takt][_addr].push(next)
					}
				}
		}
		if(! this.highlighted[Execution.takt]) this.highlighted[Execution.takt] = {}
		this.highlighted[Execution.takt][addr] = ["byte_read_ago_3", "byte_read_ago_2", "byte_read_ago_1", "byte_read"]
	},
	write: function(addr,val)
	{
		var cell = document.getElementById("cell_"+addr)
		cell.classList.remove("byte_changed")
		cell.classList.add("byte_wrote")
		cell.innerHTML = BYTE(val)
		this.bytes[addr] = BYTE(val)
		if(is_stack(addr))
		{
			Stack.write(addr)
			goto_stack(addr)
		}

		for(var takt in this.highlighted)
		{
			if(takt != Execution.takt && !this.highlighted[Execution.takt])
				for(var _addr in this.highlighted[takt])
				{
					var _cell = document.getElementById("cell_"+_addr)
					_cell.classList.remove( this.highlighted[takt][_addr].pop() )
					var next = this.highlighted[takt][_addr].pop()
					if(next)
					{
						_cell.classList.add(next)
						this.highlighted[takt][_addr].push(next)
					}
				}
		}
		if(! this.highlighted[Execution.takt]) this.highlighted[Execution.takt] = {}
		this.highlighted[Execution.takt][addr] = ["byte_wrote_ago_3", "byte_wrote_ago_2", "byte_wrote_ago_1", "byte_wrote"]
	},
	load: function(takt)
	{
		var cells, addr, byte, i
		Memory.unhighlight()
		cells = document.getElementsByClassName("cell")
		$('#shadow').show().animate({opacity: 0.5})
		for(i = 0; i < cells.length; i++)
		{
			console.log(i + "/" + cells.length)
			addr = cells[i].getAttribute("addr")
			$.ajax( { url: "http://127.0.0.1:5000/data/" + addr + "/takt/" + Execution.takt + "/state",
				dataType: 'json',
				async: false } )
			.done( function(results) {
				if(results.length)
				{
					byte = results[0][0]
					cells[i].classList.add("byte_updated")
					if(cells[i].innerHTML != BYTE(byte))
						cells[i].classList.add("byte_changed")
					cells[i].innerHTML = BYTE(byte)
					Memory.bytes[addr] = BYTE(byte)
					if(is_stack(addr))
						Stack.set(addr)
				}
			} )
			$("#progressbar").progressbar({value: parseInt(i/cells.length*100)})
		}
		$('#shadow').animate({opacity: 0}).hide()
		$("#progressbar").hide()
	},
	bpx: [],
	bpm: [],
}
var Stack = {
	highlighted: {},
	set: function(addr) //не учитывается заполнение пустот
	{
		addr = (addr >> 2) << 2
		var stack = document.getElementById('stack'), val = Memory.DWORD(addr),
		entry = document.getElementById("stack_"+addr)
		if(! entry)
		{
			entry = document.createElement("div")
			entry.id = "stack_"+addr
			entry.addr = addr
			if(stack.children.length)
			{
				for(var i = 0; i < stack.children.length; i++)
					if(stack.children[i].addr > addr)
						break
				stack.insertBefore(entry, stack.children[i])
			}
			else
				stack.appendChild(entry)
		}
		entry.innerHTML = DWORD(addr) + ": " + val + " " + telescope(val)
	},
	read: function(addr)
	{
		addr = (addr >> 2) << 2
		var entry = document.getElementById("stack_"+addr)
		entry.classList.add("stack_read")
	},
	write: function(addr)
	{
		addr = (addr >> 2) << 2
		var entry = document.getElementById("stack_"+addr), val = Memory.DWORD(addr)
		entry.classList.add("stack_wrote")
		entry.innerHTML = DWORD(addr) + ": " + val + " " + telescope(val)
	}
}
var Registers = {
	highlighted: {},
	regs: {},
	set: function(regs)
	{
		var reg, val, memory
		for(var name in regs)
		{
			reg = document.getElementById(name)
			val = regs[name]
			this.regs[name] = val
			if(reg.getElementsByClassName('value')[0].innerHTML == DWORD(val))
			{
				reg.classList.remove( this.highlighted[name].pop() )
				var next = this.highlighted[name].pop()
				if(next)
				{
					reg.classList.add(next)
					this.highlighted[name].push(next)
				}
			}
			else
			{
				reg.classList.add("reg_changed")
				this.highlighted[name] = ["reg_changed_ago_2", "reg_changed_ago_1", "reg_changed"]
			}
			reg.getElementsByClassName('value')[0].innerHTML = DWORD(val)
			reg.getElementsByClassName('hints')[0].innerHTML = telescope(val)
			//reg.classList.add("reg_points_r")
		}
	},
	get: function(reg)
	{
		return this.regs[reg]
	}
}
var Execution = {
	takt: 0,
	highlighted: {},
	instruction: function(takt)
	{
		var state, access, eip, reg, addr, val, access_type, instr, hints = ''
		this.takt = takt
		$.ajax( { url: "http://127.0.0.1:5000/takt/" + this.takt + "/state",
			dataType: 'json',
			async: false } )
		.done( function(results) {
			state = results[0]
			Registers.set({
				"EAX": state[0],
				"ECX": state[1],
				"EDX": state[2],
				"EBX": state[3],
				"ESP": state[4],
				"EBP": state[5],
				"ESI": state[6],
				"EDI": state[7],
				"EIP": state[8]
			})
			eip = state[8]
		} )

		instr = document.getElementById('instr_'+eip).getElementsByTagName('code')[0]
		instr.classList.add("instruction_current")
		for(var _eip in this.highlighted)
		{
			var _instr = document.getElementById('instr_'+_eip).getElementsByTagName('code')[0]
			_instr.classList.remove( this.highlighted[_eip].pop() )
			var next = this.highlighted[_eip].pop()
			if(next)
			{
				_instr.classList.add(next)
				this.highlighted[_eip].push(next)
			}
		}
		this.highlighted[eip] = ["instruction_exec_ago_3", "instruction_exec_ago_2", "instruction_exec_ago_1", "instruction_current"]
		
		$.ajax( { url: "http://127.0.0.1:5000/takt/" + this.takt + "/mem/access",
			dataType: 'json',
			async: false } )
		.done( function(results) {
			for(var i = 0; i < results.length; i++)
			{
				access = results[i]
				addr = access[1], val = access[2] , access_type = access[3]
				goto_data(addr)
				if(access_type == 'r')
				{
					Memory.read(addr)
					if(! hints) hints = "[" + DWORD(addr) + "] -> "
					hints += BYTE(val)
				}
				else if(access_type == 'w')
				{
					Memory.write(addr,val)
					if(! hints) hints = "[" + DWORD(addr) + "] <- "
					hints += BYTE(val)
				}
			}
			if(hints)
				hints += '<br>'
		} )

		$.ajax( { url: "http://127.0.0.1:5000/takt/" + this.takt + "/reg/access",
			dataType: 'json',
			async: false } )
		.done( function(results) {
			for(var i = 0; i < results.length; i++)
			{
				access = results[i]
				reg = access[1], val = access[2] , access_type = access[3]
				if(access_type == 'r')
					hints += reg + " -> " + DWORD(val)
				else if(access_type == 'w')
					hints += reg + " <- " + DWORD(val)
				hints += '<br>'
			}
		} )

		document.getElementById('trace_position').value = this.takt
		document.getElementById('trace_position_value').value = this.takt
		document.getElementById('hints').innerHTML = hints
		Tree.select(CallsTree, this.takt)
		return eip
	},
	find_state: function(where,access)
	{
		var direction = Object.keys(where)[0], takt
		$.ajax( { url: "http://127.0.0.1:5000/access/" + direction + "/" + where[direction] + "/takt",
			dataType: 'json',
			data: access,
			async: false } )
		.done( function(results) {
			if(results.length)
				takt = parseInt(results[0][0])
		})
		if(takt)
			return this.instruction(takt)
	},
	step: function()
	{
		goto_code( this.instruction(++this.takt) )
	},
	stepover: function()
	{
		var eip = Registers.get("EIP"),
			current_instr = document.getElementById('instr_'+eip),
			next_instr = parseInt(current_instr.nextElementSibling.getElementsByTagName('a')[1].getAttribute('eip'))
		console.log("jump " + DWORD(next_instr))
		Memory.bpx.push(next_instr)
		if( goto_code( this.find_state({after:this.takt}, {bpx:Memory.bpx, bpm:Memory.bpm}) ) )
			Memory.load(this.takt)
		Memory.bpx.pop()
	},
	step_back: function()
	{
		goto_code( this.instruction(--this.takt) )
	},
	cont: function()
	{
		if( goto_code( this.find_state({after:this.takt}, {bpx:Memory.bpx, bpm:Memory.bpm}) ) )
			Memory.load(this.takt)
	},
	cont_back: function()
	{
		if( goto_code( this.find_state({before:this.takt}, {bpx:Memory.bpx, bpm:Memory.bpm}) ) )
			Memory.load(this.takt)
	},
	states: function(addr) { return states },
}
var Tree = {
	prev: null,
	load: function(calls)
	{
		var func_name, out = document.getElementById('calls')
		out.innerHTML=''
		for(var i = 0; i < calls.length; i++)
		{
			//func_name = telescope(calls[i].addr)
			out.innerHTML += '<div id="call_'+i+'">`' + '-'.repeat(calls[i].deep) + "0x" + DWORD(calls[i].addr) + '()</div>'
		}
	},
	select: function(calls, takt)
	{
		for(var i = 0; i < calls.length; i++)
			if(takt < calls[i].takt)
			{
				goto_tree(i)
				if(this.prev)
					document.getElementById('call_'+this.prev).classList.remove('call_current')	
				document.getElementById('call_'+i).classList.add('call_current')
				this.prev = i
				return i
			}
	}
}

function highlight(elem)
{
	$(elem).animate({opacity: 0.2})
	setTimeout(function() {$(elem).animate({opacity: 1})}, 500)
}
function hotkeys(event)
{
	var
	F2 = 113,
	F4 = 115,
	F6 = 117,
	F7 = 118,
	F8 = 119,
	F9 = 120,
	F10 = 121
	switch(event.keyCode)
	{
		case F2:
			//Memory.bpx.push()
			//Memory.bpm.push()
			break
		case F4:
			Execution.cont_back()
			break
		case F6:
			Execution.step_back()
			break
		case F7:
			Execution.step()
			break
		case F8:
			Execution.stepover()
			break
		case F9:
			Execution.cont()
			break
	}
}
$(document).bind('keydown', hotkeys)

/*
Call tree визуализация:
	https://github.com/spiermar/d3-flame-graph
	https://github.com/fzaninotto/CodeFlower
	https://github.com/patorjk/d3-context-menu
	https://github.com/q-m/d3.chart.sankey
	https://gojs.net/latest/samples/tLayout.html
	https://gojs.net/latest/samples/treeView.html
	d3js Sequences sunburst
Bar визуализация:
	https://github.com/flrs/visavail -заточена только под даты
Code graph визуализация:
	https://github.com/dagrejs/dagre-d3/wiki
	https://gojs.net/latest/samples/localView.html
Map визуализация:
	http://bl.ocks.org/ianyfchang/8119685
	https://datascience.stackexchange.com/questions/10484/heatmap-color-and-d3-js
Filament визуализация:
	https://github.com/emeeks/d3.svg.ribbon
All Execution визуализация:
	https://bl.ocks.org/emeeks/b57f4cc89dacd38fcdcd
	https://marmelab.com/EventDrops/
	https://threejs.org/examples/#webgl2_materials_texture3d
	d3js Treemap (like a SpaceSniffer)

https://ialab.it.monash.edu/webcola/
*/