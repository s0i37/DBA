function Hex()
{
	var content = ''
	this.data_containers = []
	var access_color = function( cell )
	{
		var reads = cell.reads_count(),
			writes = cell.writes_count(), 
			css_color_graient, css_color_read, css_color_write
		css_color_graient = (writes < 16) ? writes * 16 : 255
		css_color_write = sprintf( "#ff%02x%02x", 0xff-css_color_graient, 0xff-css_color_graient )
		css_color_graient = (reads < 16) ? reads * 16 : 255
		css_color_read = sprintf( "#%02xff%02x", 0xff-css_color_graient, 0xff-css_color_graient )
		return (writes) ? css_color_write : css_color_read
	}
	/*var get_memory_rw_eip = function( reads_eip, writes_eip )
	{
		var mem = []
		reads_eip.forEach( function(addr) { mem.push(addr) } )
		writes_eip.forEach( function(addr) { mem.push(addr) } )
		return mem.join(' ')
	}*/
	var get_memory_rw_eip_info = function( reads_eip, writes_eip )
	{
		var text = ''
		if( writes_eip.length )
		{
			text += 'writes (' + writes_eip.length + '):\n'
			writes_eip.forEach( function(eip) { text += sprintf( '0x%08x\n', eip ) } )
		}
		if( reads_eip.length )
		{
			text += 'reads (' + reads_eip.length + '):\n'
			reads_eip.forEach( function(eip) { text += sprintf( '0x%08x\n', eip ) } )
		}
		return text
	}
	this.reset = function()
	{
		content = ''
	}
	this.load = function( data )
	{
		this.data_containers = []
		this.reset()
		this.add( data )
	}
	this.add = function( data_container )
	{
		this.data_containers.push(data_container)
		var cells = data_container.get_cells(), addr
		if(cells.length && cells[0].addr % 0x10)
		{
			addr = cells[0].addr & 0xfffffff0
			content += '<tr><td>0x' + sprintf('%08x', addr) + ':</td>'
			while( addr++ < cells[0].addr )
				content += '<td>**</td>'
		}
		for( var i = 0; i < cells.length; i++ )
		{
			var cell = cells[i]
			addr = cell.addr
			if( addr % 0x10 == 0 )
				content += ((content) ? '</tr>\r\n' : '') + '<tr><td>0x' + sprintf('%08x', addr) + ':</td>'
			var byte = cell.get_byte_after( takt )
			if( byte == undefined )
				content += '<td>**</td>'
			else
				content += '<td style="background-color:' + access_color(cell) + '"><abbr addr=' + addr + ' onclick="javascript:data_xrefs(this)">' + sprintf('%02X', byte.value) + '</abbr></td>'
		}
		if(addr)
		{
			while( ++addr % 0x10 != 0 )
				content += '<td>**</td>'
			content += '</tr>'
		}

		show()
	}
	var show = function()
	{
		$('#data thead').html( '<td>executes</td><td>addr</td><td>opcode</td><td>instruction</td>' )
		$('#data tbody').html( content )
	}
}

function Disas()
{
	var content = ''
	var code_containers = []
	var exec_count_color = function( instruction )
	{
		var reads_operations = instruction.states.filter( function(state) { 
				return (state.accesses.filter( function(access) { return access.type == 'r' } ).length > 0) ? true : false
			} ).length,
			writes_operations = instruction.states.filter( function(state) { 
				return (state.accesses.filter( function(access) { return access.type == 'w' } ).length > 0) ? true : false
			} ).length
		var css_color_graient = (writes_operations < 16) ? writes_operations * 16 : 255
		var css_color_write = sprintf( "#ff%02x%02x", 0xff-css_color_graient, 0xff-css_color_graient )
		css_color_graient = (reads_operations < 16) ? reads_operations * 16 : 255
		var css_color_read = sprintf( "#%02xff%02x", 0xff-css_color_graient, 0xff-css_color_graient )
		return (writes_operations) ? css_color_write : css_color_read
	}
	var self_modification_code_style = function( cell )
	{
		return ( cell.instructions.length > 1 ) ? 'self_modification_code' : ''
	}
	/*var get_memory_operations = function( instruction )
	{
		var mem = []
		instruction.writed.forEach( function(byte) {
			mem.push( byte.addr )
		} )
		instruction.readed.forEach( function(byte) {
			mem.push( byte.addr )
		} )
		return mem.join(' ')
	}*/

	this.reset = function()
	{
		content = ''
	}
	this.load = function( code_container )
	{
		this.code_containers = []
		this.reset()
		this.add( code_container )
	}
	this.add = function( code_container )
	{
		this.code_containers.push(code_container)
		var cells = code_container.get_cells()
		for(var i = 0; i < cells.length; i++)
		{
			var cell = cells[i],
				is_self_modification_code = ( cell.instructions.length > 1 ) ? true : false,
				instruction = cell.instructions[0]
			content += '<tr style="background-color:' + exec_count_color(instruction) + '">\n'
			content += '<td addr="' + cell.addr + '" onclick="code_states(this)">' + instruction.states.length + '</td><td>' + sprintf('0x%08x', cell.addr) + '</td><td style="' + self_modification_code_style(cell) + '">' + instruction.opcode + '</td><td addr="' + cell.addr + '" onclick="code_xrefs(this)">' + instruction.mnem + ' ' + instruction.operands + '</td>'
			content += '</tr>\n'
		}
		show()
	}
	var show = function()
	{
		$('#code tbody').html( content )
	}
}


var Code = {
	Cpu: function(takt)
	{
		this.takt = takt
		this.thread_id = 0
		this.eip = 0
		this.registers = []
		this.accesses = []
	},

	Instruction: function(mnem, operands)
	{
		this.mnem = mnem
		this.operands = operands
		this.opcode = '**'
		this.states = []
	},

	Cell: function(addr)
	{
		this.addr = addr
		this.instructions = []
		this.get_instruction = function(opcode)
		{
			for(var i = 0; i < this.instructions.length; i++)
				if( this.instructions[i].opcode == opcode )
					return this.instructions[i]
		}
	},
	
	Access: function(byte)
	{
		this.byte = byte
		this.addr = 0
		this.type = ''
	},

	Container: function()
	{
		var cells = []
		this.add_cell = function(cell)
		{
			cells.push(cell)
		}
		this.get_cell = function(addr)
		{
			for(var i = 0; i < cells.length; i++)
				if( cells[i].addr == addr )
					return cells[i]
			return null
		}
		this.get_cells = function()
		{
			var addrs = [], cells_sorted = []
			for(var i = 0; i < cells.length; i++)
				addrs.push( cells[i].addr )
			addrs.sort()
			for(i = 0; i < addrs.length; i++)
				cells_sorted.push( cells[i] )
			return cells_sorted
		}
	}
}

var Data = {
	Cpu: function(takt)
	{
		this.takt = takt
		this.thread_id = 0
		this.eip = 0
		this.registers = []
	},

	Byte: function(value)
	{
		this.value = value
	},

	Cell: function(addr)
	{
		this.addr = addr
		this.accesses = []
		this.get_byte_after = function(takt)
		{
			var byte_last
			for(var i = 0; i < this.accesses.length; i++)
			{
				byte_last = this.accesses[i].byte
				if( this.accesses[i].state.takt > takt )
					break
			}
			return byte_last
		}
		this.reads_count = function()
		{
			var reads = 0
			for(var i = 0; i < this.accesses.length; i++)
				if( this.accesses[i].type == 'r' )
					reads++
			return reads
		}
		this.writes_count = function()
		{
			var writes = 0
			for(var i = 0; i < this.accesses.length; i++)
				if( this.accesses[i].type == 'w' )
					writes++
			return writes
		}
	},

	Access: function(byte)
	{
		this.byte = byte
		this.type = ''
		this.state = 0
	},

	Container: function()
	{
		var cells = []
		this.add_cell = function(cell)
		{
			/* !! */
			if(cells.length)
			{
				var addr_ptr = cells[0].addr, i = 0
				while(addr_ptr <= cell.addr)
				{
					if(! cells[i] )
						cells[i] = new Data.Cell(addr_ptr)
					if(cells[i].addr == cell.addr)
						cells[i] = cell
					addr_ptr++
					i++
				}
			}
			else
				cells.push(cell)
		}
		this.get_cell = function(addr)
		{
			for(var i = 0; i < cells.length; i++)
				if( cells[i].addr == addr )
					return cells[i]
			return null
		}
		this.get_cells = function()
		{
			var addrs = [], cells_sorted = []
			for(var i = 0; i < cells.length; i++)
				addrs.push( cells[i].addr )
			addrs.sort()
			for(i = 0; i < addrs.length; i++)
				cells_sorted.push( cells[i] )
			return cells_sorted
		}
	}
}


function Dialog(head)
{
	this.head = head
	this.body = ''
	this.load = function(body)
	{
		for(var i = 0; i < body.length; i++)
		{
			this.body += '<table border=1><tbody><tr>'
			for(var j = 0; j < this.head.length; j++)
				this.body += '<td>' + body[i][j] + '</td>'
			this.body += '</tr></tbody></table>'
		}
		$('#dialog').dialog( {
			title: this.head.join('\t'),
			maxHeight: 500,
		} )
		$('#dialog').html(this.body)
	}
	this.sort = function(col)
	{
		var old_body = this.body, new_body = []
		/*for(var i = 0; i < old_body.length; i++)
			if( old_body[i][col] > )*/

		this.load(new_body)
	}
}


function code_states(elem)
{
	var addr = elem.getAttribute('addr')
	console.error('not implemented')
}
function code_xrefs(elem)
{
	var addr = elem.getAttribute('addr')
	code_window.data( addr )
}
function data_xrefs(elem)
{
	var addr = elem.getAttribute('addr')
	console.log( data_window.code( addr ) )
}

var hex_window = new Hex()
var disas_window = new Disas()
var hex_lines = 0x10, code_lines = 10
var takt = 0


var data_window = {
	LINE: 0x10,
	offset: 0,
	goto: function(addr)
	{
		addr = parseInt(addr)
		data_window.offset = addr
		$.ajax( { url: "/data/" + addr + "?lines=" + hex_lines, dataType: 'json' } )
		.done( function( result )
		{
			var hex_data = new Data.Container()
			result.forEach( function(v)
			{
				var addr = v[0], value = v[1], takt = v[2], access_type = v[3], thread_id = v[4], eip = v[5]
				var access = new Data.Access( new Data.Byte(value) )
				access.state = new Data.Cpu(takt)
				access.state.thread_id = thread_id
				access.state.eip = eip
				access.type = access_type
				var cell = hex_data.get_cell(addr)
				if(cell)
					cell.accesses.push(access)
				else
				{
					cell = new Data.Cell(addr)
					cell.accesses.push(access)
					hex_data.add_cell(cell)
				}
			} )	
			hex_window.load( hex_data )
		} )
	},
	code: function(addr)
	{
		var cell
		if( cell = hex_window.data_containers[0].get_cell(addr) )
		{
			var changes = []
			for(var a = 0; a < cell.accesses.length; a++)
			{
				var takt = cell.accesses[a].state.takt
				var thread_id = cell.accesses[a].state.thread_id
				var eip = cell.accesses[a].state.eip
				var value = cell.accesses[a].byte.value
				changes.push( [takt,thread_id,eip,value] )
			}
			if(changes.length)
			{
				dialog = new Dialog( ["takt","thread_id","eip","value"] )
				dialog.load(changes)
				return dialog
			}
		}
	}
}



var code_window = {
	LINE: 5,
	offset: 0,
	goto: function(addr)
	{
		addr = parseInt(addr)
		code_window.offset = addr
		$.ajax( { url: "/code/" + addr + "?lines=" + code_lines, dataType: 'json' } )
		.done( function(result) {
			var code = new Code.Container(); instructions = {}
			result.forEach( function(v) {
				var eip = v[0], takt = v[1], thread_id = v[2], mnem = v[3], operands = v[4], opcode = v[5], access_type = v[6], addr = v[7], value = v[8]
				var cell = code.get_cell(eip), is_new_cell = false, is_new_instruction = false
				if(! cell)
				{
					cell = new Code.Cell(eip)
					is_new_cell = true
				}
				var instruction = cell.get_instruction(opcode)
				if(! instruction)
				{
					instruction = new Code.Instruction(mnem, operands)
					instruction.opcode = opcode
					is_new_instruction = true
				}
				var state = new Code.Cpu(takt)
				state.thread_id = thread_id
				state.eip = eip
				if(access_type)
				{
					var access = new Code.Access( new Data.Byte(value) )					
					access.addr = addr
					access.type = access_type
					state.accesses.push(access)
				}
				instruction.states.push(state)
				if(is_new_instruction)
					cell.instructions.push(instruction)
				if(is_new_cell)
					code.add_cell( cell )
			} )
			disas_window.load( code )
		} )
	},
	data: function(addr)
	{
		if(cell = disas_window.code_containers[0].get_cell(addr))
		{
			var changes = []
			for(var i = 0; i < cell.instructions.length; i++)
				for(var s = 0; s < cell.instructions[i].states.length; s++)
					for(var a = 0; a < cell.instructions[i].states[s].accesses.length; a++)
					{
						var takt = cell.instructions[i].states[s].takt
						var addr = cell.instructions[i].states[s].accesses[a].addr
						var value = cell.instructions[i].states[s].accesses[a].byte.value
						changes.push( [takt,addr,value] )
					}
			if(changes.length)
			{
				dialog = new Dialog( ["takt","addr","value"] )
				dialog.load(changes)
				return dialog
			}
		}
	}
}

var window_height = 20
function data_keys(event)
{
	var
	PAGE_UP = 33
	PAGE_DOWN = 34
	UP = 38
	DOWN = 40
	switch(event.keyCode)
	{
		case UP:
			data_window.goto( data_window.offset - data_window.LINE * 1 )
			break
		case DOWN:
			data_window.goto( data_window.offset + data_window.LINE * 1 )
			break
		case PAGE_UP:
			data_window.goto( data_window.offset - data_window.LINE * window_height )
			break
		case PAGE_DOWN:
			data_window.goto( data_window.offset + data_window.LINE * window_height )
			break
	}
}
function code_keys(event)
{
	var
	PAGE_UP = 33
	PAGE_DOWN = 34
	UP = 38,
	DOWN = 40
	switch(event.keyCode)
	{
		case UP:
			code_window.goto( code_window.offset - code_window.LINE * 1 )
			break
		case DOWN:
			code_window.goto( code_window.offset + code_window.LINE * 1 )
			break
		case PAGE_UP:
			code_window.goto( code_window.offset - code_window.LINE * window_height )
			break
		case PAGE_DOWN:
			code_window.goto( code_window.offset + code_window.LINE * window_height )
			break
		
	}
}

function Context_bar()
{
	var elem = document.getElementById("context_bar"),
		ctx = elem.getContext('2d'),
		width = elem.offsetWidth,
		height = elem.offsetHeight

	this.min_eip = 0
	this.max_eip = 0
	this.min_takt = 0
	this.max_takt = 0
	this.pixel = [0xff, 0 ,0, 0xff]
	this.draw_point = function(eip, takt)
	{
		var pixels = ctx.getImageData(0, 0, width, height),
			point = ( (0xffffffff - eip)/(this.max_eip/height) ) * width + ( this.takt / (this.max_takt/width) )
		pixels.data[ point + 0 ] = this.pixel[0]
		pixels.data[ point + 1 ] = this.pixel[1]
		pixels.data[ point + 2 ] = this.pixel[2]
		pixels.data[ point + 3 ] = this.pixel[3]
		ctx.putImageData(pixels, 0, 0)
	}
	this.execution_flows = function(thread_id)
	{
		var that = this
		$.ajax( { url: "/code/eips/" + thread_id, dataType: 'json' } )
		.done( function(results) {
			results.forEach( function(v) {
				var eip = v[0], takt = v[1]
				that.draw_point(eip, takt)
			} )
		} )
	}
	this.init = function()
	{
		var that = this
		$.ajax( { url: "/code/takts/min" } )
		.done( function(result) {
			var min_takt = result
			if(min_takt)
				that.min_takt = min_takt
		} )
		$.ajax( { url: "/code/takts/max" } )
		.done( function(result) {
			var max_takt = result
			if(max_takt)
				that.max_takt = max_takt
		} )
		$.ajax( { url: "/code/eips/min" } )
		.done( function(result) {
			var min_eip = result
			if(min_eip)
				that.min_eip = min_eip
		} )
		$.ajax( { url: "/code/eips/max" } )
		.done( function(result) {
			var max_eip = result
			if(max_eip)
				that.max_eip = max_eip
		} )
		$.ajax( { url: "/code/threads", dataType: 'json' } )
		.done( function (results) {
			results.forEach( function(thread_id) {
				that.execution_flows( thread_id )
			} )
		} )
	}
}

function Data_bar()
{
	this.zoom = 200
	this.addr_max = 0x80000000

	var elem = document.getElementById("data_bar"),
		bar_scale = ( this.addr_max / elem.offsetHeight ) / this.zoom,
		bar_width = elem.offsetWidth,
		ctx = elem.getContext('2d')
	var view_cache = {}

	this.reset = function()
	{
		bar_scale = ( this.addr_max / elem.offsetHeight ) / this.zoom
		ctx.fillStyle = '#ccc'
		for(var i = 0; i < elem.clientHeight; i++)
			ctx.fillRect(0, i, bar_width, 1)
	}

	this.byte = function(addr, reads, writes)
	{
		var changes = (writes)
		? ( ( writes < 16 ) ? writes : 16 )
		: ( ( reads < 16 ) ? reads : 16 ),
			y1 = parseInt( addr/bar_scale ) || 1
		
		if( typeof view_cache[this.zoom] == 'undefined' )
			view_cache[this.zoom] = {}
		if( typeof view_cache[this.zoom][this.addr_max] == 'undefined' )
			view_cache[this.zoom][this.addr_max] = {}

		if( typeof view_cache[this.zoom][this.addr_max][y1] == 'undefined' )
		{
			view_cache[this.zoom][this.addr_max][y1] = changes
		}
		if( typeof view_cache[this.zoom][this.addr_max][y1] == 'number' && view_cache[this.zoom][this.addr_max][y1] < changes )
		{
			ctx.fillStyle = (writes) ? sprintf('#%x00', changes) : sprintf('#0%x0', changes)
			ctx.fillRect(0, y1, bar_width, 1)
		}
		//console.log(0, y1, bar_width, 1)
	}
	
	this.bytes = function()
	{
		var that = this
		$.ajax( { url: "/data/bytes/", dataType: 'json' } )
		.done( function(results) {
			results.forEach( function(v) {
				var addr = v[0], reads = v[1], writes = v[2]
				that.byte(addr, reads, writes)
			} )
		} )
	}
	
	this.pages = function()
	{
		ctx.fillStyle = '#333'
		$.ajax( { url: "/data/pages/", dataType: 'json' } )
		.done( function(results) {
			results.forEach( function(v) {
				var module = v[0], low_addr = v[1], high_addr = v[2]
				var y1 = parseInt(low_addr/bar_scale), y2 = parseInt( (high_addr-low_addr)/bar_scale )
				ctx.fillRect( 0, y1, bar_width, (y2==0) ? 1 : y2 )
			} )
		} )
	}

	this.click = function(event)
	{
		var offset = parseInt( event.clientY * bar_scale )
		$('#data_goto_addr').val( sprintf( '0x%08x', offset ) )
		data_window.goto( offset )
		console.log( 'goto ' + sprintf( '0x%08x', offset ) )
	}

}

function shortcuts(event)
{
	var key = event.keyCode
	//console.log(key)
	switch(key)
	{
		case 107: 	data_bar.zoom *= 2
					data_bar.reset()
					data_bar.bytes()
					break
		case 109: 	data_bar.zoom /= 2
					data_bar.reset()
					data_bar.bytes()
					break
		case 104: 	data_bar.addr_max -= 0x100000
					data_bar.reset()
					data_bar.bytes()
					alert( sprintf( '0x%08x', data_bar.addr_max) )
					break
		case 98: 	data_bar.addr_max += 0x100000
					data_bar.reset()
					data_bar.bytes()
					alert( sprintf( '0x%08x', data_bar.addr_max) )
					break		
	}
}

var data_bar
function init()
{
	/*data_bar = new Data_bar()
	data_bar.reset()
	data_bar.pages()
	data_bar.bytes()*/
	//code_window.goto( 0x00f21000 )
	new Context_bar().init()
	window.addEventListener('keydown', shortcuts, false)
	console.log("v0.14")
}