function goto_code(addr)
{
	document.getElementById('code').scrollTop = document.getElementById('instr_'+addr).offsetTop - 100
	return addr
}
function goto_data(addr)
{
	document.getElementById('data').scrollTop = document.getElementById('cell_'+addr).parentElement.offsetTop - 100
	return addr
}
function goto_stack(addr)
{
	return addr
}

function to_hexline(hex)
{
	return (hex+'').slice(0,-1).toLowerCase() + '0'
}

function takt_handler(event) {
	var elem = event.target, takt
	if(elem.classList.contains('takt'))
	{
		takt = $(elem).attr('takt')
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
							out += '<div class="access_write"><span class="takt" takt=' + takt + '>' + takt + '</span>  <a href="#' + eip + '">0x' + eip.toString(16) + '</a> <- ' + BYTE(val) + '</div>'
						else if(access_type == 'r')
							out += '<div class="access_read"><span class="takt" takt=' + takt + '>' + takt + '</span>  <a href="#' + eip + '">0x' + eip.toString(16) + '</a> -> ' + BYTE(val) + '</div>'
					} )
					$('#dialog').dialog( "option", "width", 400 );
		  			$('#dialog').html( out )
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
							out += '<div class="access_write"><span class="takt" takt=' + takt + '>' + takt + '</span>  <a href="#' + ((addr>>4)<<4) + '">0x' + addr.toString(16) + '</a> <- ' + BYTE(val) + '</div>'
						else if(access_type == 'r')
							out += '<div class="access_read"><span class="takt" takt=' + takt + '>' + takt + '</span>  <a href="#' + ((addr>>4)<<4) + '">0x' + addr.toString(16) + '</a> -> ' + BYTE(val) + '</div>'
					} )
					$('#dialog').dialog( "option", "width", 400 );
		  			$('#dialog').dialog( "option", "title", 'memory operations' );
		  			$('#dialog').html( out )
				} )		  		
		  	},
		  	close: function()
		  	{
		  		$('#dialog').text('loading...')
		  	}
		} )

		$('#dialog').click(takt_handler)
	} )

/*
	$('#code code').each(function(i, block) {
    	hljs.highlightBlock(block);
  	})
*/

} )

function get_memory_page_name(addr)
{
	for(var page in MemoryMap)
		if(MemoryMap[page].start <= addr < MemoryMap[page].end)
			return page
}

function telescope(addr)
{
	return ""
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

var Registers = {
	highlighted: {},
	set: function(regs)
	{
		var reg, val, memory
		for(var name in regs)
		{
			reg = document.getElementById(name)
			val = regs[name]
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
}
var Memory = {
	highlighted: {},
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
		cell.classList.add("byte_read")
		if(0)
		for(var _addr in this.highlighted)
		{
			var _cell = document.getElementById("cell_"+_addr)
			_cell.classList.remove( this.highlighted[_addr].pop() )
			var next = this.highlighted[_addr].pop()
			if(next)
			{
				_cell.classList.add(next)
				this.highlighted[_addr].push(next)
			}
		}
		this.highlighted[addr] = ["byte_read_ago_3", "byte_read_ago_2", "byte_read_ago_1", "byte_read"]
	},
	write: function(addr,val)
	{
		var cell = document.getElementById("cell_"+addr)
		cell.classList.add("byte_wrote")
		cell.innerHTML = BYTE(val)
		if(0)
		for(var _addr in this.highlighted)
		{
			var _cell = document.getElementById("cell_"+_addr)
			_cell.classList.remove( this.highlighted[_addr].pop() )
			var next = this.highlighted[_addr].pop()
			if(next)
			{
				_cell.classList.add(next)
				this.highlighted[_addr].push(next)
			}
		}
		this.highlighted[addr] = ["byte_wrote_ago_3", "byte_wrote_ago_2", "byte_wrote_ago_1", "byte_wrote"]
	},
	load: function(takt)
	{
		var cells, byte, i
		cells = document.getElementsByClassName("cell")
		for(i = 0; i < cells.length; i++)
			$.ajax( { url: "http://127.0.0.1:5000/data/" + cells[i].getAttribute("addr") + "/takt/" + Execution.takt + "/state",
				dataType: 'json',
				async: false } )
			.done( function(results) {
				if(results.length)
				{
					byte = results[0][0]
					cells[i].innerHTML = BYTE(byte)
					cells[i].classList.add("byte_updated")
				}
			} )
	},
	//bpx: [],
	//bmp: [],
}
var Execution = {
	takt: 0,
	highlighted: {},
	instruction: function(takt)
	{
		var state, access, eip, addr, val, access_type, instr
		$.ajax( { url: "http://127.0.0.1:5000/takt/" + takt + "/state",
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
		
		$.ajax( { url: "http://127.0.0.1:5000/takt/" + takt + "/access",
			dataType: 'json',
			async: false } )
		.done( function(results) {
			for(var i = 0; i < results.length; i++)
			{
				access = results[i]
				addr = access[1], val = access[2] , access_type = access[3]
				goto_data(addr)
				if(access_type == 'r')
					Memory.read(addr)
				else if(access_type == 'w')
					Memory.write(addr,val)
			}
		} )

		this.takt = takt
		document.getElementById('trace_position').value = this.takt
		document.getElementById('trace_position_value').innerHTML = this.takt
		return eip
	},
	find_state: function(where,access)
	{
		$.ajax( { url: "http://127.0.0.1:5000/access/" + "after" + "/" + this.takt + "/takt",
			dataType: 'json',
			async: false } )
		.done( function(results) {
			this.takt = results[0][0]
		})
		return this.takt
	},
	step: function()
	{
		goto_code( this.instruction(++this.takt) )
	},
	step_back: function()
	{
		goto_code( this.instruction(--this.takt) )
	},
	cont: function()
	{
		goto_code( this.find_state({after:this.takt}, {bpx:Memory.bpx, bpm:Memory.bpm}) )
		Memory.load(this.takt)
	},
	cont_back: function()
	{
		goto_code( this.find_state({before:this.takt}, {bpx:Memory.bpx, bpm:Memory.bpm}) )
		Memory.load(this.takt)
	},
	states: function(addr) { return states },
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
	d3js Sequences sunburst
Bar визуализация:
	https://github.com/flrs/visavail
Code graph визуализация:
	https://github.com/dagrejs/dagre-d3/wiki
Graph визуализация:
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