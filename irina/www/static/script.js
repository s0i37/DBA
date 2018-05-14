BYTE = 1
WORD = 2
DWORD = 4
QWORD = 8

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
		this.data_containers = []
	}
	this.load = function( data )
	{
		this.reset()
		this.add( data )
	}
	this.add = function( data_container )
	{
		this.data_containers.push(data_container)
		this.update()
	}
	this.update = function()
	{
		content = ''
		for( var c = 0; c < this.data_containers.length; c++ )
		{
			var data_container = this.data_containers[c],
				cells = data_container.get_cells(), addr
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
				var byte = cell.get_byte_after( current_takt )
				if( byte == undefined )
					content += '<td>**</td>'
				else
					content += '<td style="background-color:' + access_color(cell) + '"><abbr addr=' + addr + '>' + sprintf('%02X', byte.value) + '</abbr></td>'
			}
			if(addr)
			{
				while( ++addr % 0x10 != 0 )
					content += '<td>**</td>'
				content += '</tr>'
			}
		}
		show(this.elem_selector)
	}
	this.reset_selected = function()
	{
		var that = this
		$(that.elem_selector + ' td').each( function() {
			if( $(this).hasClass("selected") )
				$(this).removeClass("selected")
		} )
	}
	this.select = function(addr, size)
	{
		var that = this
		this.reset_selected()
		$(that.elem_selector + ' td').each( function() {
			if( this.children.length && this.children[0].getAttribute('addr') >= addr && this.children[0].getAttribute('addr') < addr + size )
				$(this).addClass("selected")
		} )
	}
	this.reset_highlighted = function()
	{
		var that = this
		$(that.elem_selector + ' td').each( function() {
			if( $(this).hasClass("highlighted") )
				$(this).removeClass("highlighted")
		} )
	}
	this.highlight = function(addr, size)
	{
		var that = this
		this.reset_highlighted()
		$(that.elem_selector + ' td').each( function() {
			if( this.children.length && this.children[0].getAttribute('addr') >= addr && this.children[0].getAttribute('addr') < addr + size )
				$(this).addClass("highlighted")
		} )
	}
	var show = function(elem_selector)
	{
		$(elem_selector + ' thead').html( '<td>executes</td><td>addr</td><td>opcode</td><td>instruction</td>' )
		$(elem_selector + ' tbody').html( content )
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
			content += '<td addr="' + cell.addr + '">' + instruction.states.length + '</td><td>' + sprintf('0x%08x', cell.addr) + '</td><td style="' + self_modification_code_style(cell) + '">' + instruction.opcode + '</td><td><code addr="' + cell.addr + '">' + instruction.mnem + ' ' + instruction.operands + '</code></td>'
			content += '</tr>\n'
		}
		show(this.elem_selector)
	}
	var show = function(elem_selector)
	{
		$(elem_selector + ' tbody').html( content )
		$(elem_selector + ' code').each(function(i, block) {
			hljs.highlightBlock(block);
		})
	}
}


function Exec()
{
	var content = ''
	var exec_containers = []
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

	this.reset = function()
	{
		content = ''
	}
	this.load = function( code_container )
	{
		this.exec_containers = []
		this.reset()
		this.add( code_container )
	}
	this.add = function( code_container )
	{
		this.exec_containers.push(code_container)
		var states = code_container.get_states()
		for(var i = 0; i < states.length; i++)
		{
			var state = states[i],
				instruction = state.instruction
			content += '<tr>\n'
			content += '<td>' + sprintf('0x%08x', state.eip) + '</td><td>' + instruction.opcode + '</td><td takt="' + state.takt + '"><code addr="' + state.eip + '">' + instruction.mnem + ' ' + instruction.operands + '</code></td>'
			content += '</tr>\n'
		}
		show(this.elem_selector)
	}
	this.reset_selected = function()
	{
		var that = this
		$(that.elem_selector + ' td').each( function() {
			if( $(this).hasClass('selected') )
				$(this).removeClass('selected')
		} )
	}
	this.select = function(takt)
	{
		console.log("selected " + takt)
		this.reset_selected()
		var that = this
		$(that.elem_selector + ' td').each( function() {
			if( this.getAttribute('takt') == takt )
				$(this).addClass('selected')
		} )
	}
	var show = function(elem_selector)
	{
		$(elem_selector + ' tbody').html( content )
		$(elem_selector + ' code').each(function(i, block) {
			hljs.highlightBlock(block);
		})
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

var Execute = {
	Cpu: function(takt)
	{
		this.takt = takt
		this.thread_id = 0
		this.eip = 0
		this.registers = []
		this.accesses = []
		this.instruction = 0
	},

	Instruction: function(mnem, operands)
	{
		this.mnem = mnem
		this.operands = operands
		this.opcode = '**'
	},
	
	Access: function(byte)
	{
		this.byte = byte
		this.addr = 0
		this.type = ''
	},

	Container: function()
	{
		var states = []
		this.add_state = function(state)
		{
			states.push(state)
		}
		this.get_state = function(takt)
		{
			for(var i = 0; i < states.length; i++)
				if( states[i].takt == takt )
					return states[i]
			return null
		}
		this.get_states = function()
		{
			/*var addrs = [], cells_sorted = []
			for(var i = 0; i < cells.length; i++)
				addrs.push( cells[i].addr )
			addrs.sort()
			for(i = 0; i < addrs.length; i++)
				cells_sorted.push( cells[i] )
			return cells_sorted*/
			return states
		}
	}
}



var hex_lines = 0x10, code_lines = 10
var current_takt = 0



/*
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
*/

function Context_bar(elem_selector)
{
	var elem = $(elem_selector)[0],
		ctx = elem.getContext('2d'),
		width = elem.offsetWidth,
		height = elem.offsetHeight,
		layers = [],
		current_layer = 0,
		eips_per_pixel = 0,
		takts_per_pixel = 0,
		threads = [], threads_colors = [],
		points = [],
		comments = []

	this.min_eip = 0
	this.max_eip = 0
	this.min_takt = 0
	this.max_takt = 0
	this.pixel = [0, 0, 0, 0x77]

	ctx.font = "10px Arial"

	var get_random_colors = function()
	{
		var rgba = []
		for( var i = 0; i < 3; i++ )
			rgba.push( parseInt( Math.random() * 0xff ) )
		rgba.push(0xff) // alpha
		return rgba
	}
	var get_prev_layer = function(layer)
	{
		for( var i = layer; i >= 0; i-- )
			if( layers[i] != undefined )
				return layers[i]
	}
	var clear_layer = function(layer)
	{
		if( layers[layer] != undefined )
			layers[layer] = get_prev_layer(layer)
	}
	var set_pixel = function(xy, rgba)
	{
		var point = 0
		if( typeof(xy) == 'number' )
			point = xy * 4
		else
			point = xy[0] * 4 + width * xy[1] * 4
		if( layers[current_layer] == undefined )
			layers[current_layer] = get_prev_layer(current_layer)	// clone prev layer
		for(var i = 0; i < 4; i++)
			layers[current_layer].data[point + i] = rgba[i]
	}
	var get_pixel = function(xy)
	{
		var point = ( xy[0] + xy[1] * width ) * 4,
			rgba = []
		if( layers[current_layer] )
			for( var i = 0; i < 4; i++ )
				rgba.push( layers[current_layer].data[point+i] )
		return rgba
	}
	var set_text = function(xy, text)
	{
		comments.push( {xy:xy, text:text} )
	}

	this.grid = function()
	{
		current_layer = 1
		if(comments.length || !(this.max_eip && this.min_eip && this.max_takt && this.min_takt) )
			return
		var delta_grid_x = parseInt( (this.max_takt-this.min_takt)/takts_per_pixel/10 ),
			delta_grid_takt = parseInt( (this.max_takt-this.min_takt)/10 ),
			delta_grid_y = parseInt( (this.max_eip-this.min_eip)/eips_per_pixel/5 ),
			delta_grid_eip = parseInt( (this.max_eip-this.min_eip)/5 ),
			eip = this.min_eip,
			takt = this.min_takt
		for( var x = delta_grid_x; x < width; x += delta_grid_x )
		{
			for( var y = 0; y < height; y += 4 )
				set_pixel( [x,y], [0x00,0x00,0x00,0xff] )
			takt += delta_grid_takt
			set_text( [x,10], sprintf("%d", takt) )
		}
		for( var y = delta_grid_y; y < height; y += delta_grid_y )
		{
			for( var x = 0; x < width; x += 4 )
				set_pixel( [x,y], [0x00,0x00,0x00,0xff] )
			eip += delta_grid_eip
			set_text( [1,y], sprintf("0x%08x", eip) )
		}
	}
	this.point = function(eip, takt)
	{
		current_layer = 0
		var	x = parseInt( (takt - this.min_takt) / takts_per_pixel ),
			y = parseInt( (this.max_eip - eip) / eips_per_pixel )
		//	is_intersect = ( get_pixel( [x,y] ) == this.pixel ) /* !! */
		//if( is_intersect )
		//	set_pixel( [x,y], [0xff,0,0,0xff] )
		//else
			set_pixel( [x,y], this.pixel )
	}
	this.execution_flows = function(thread_id)
	{
		var that = this
		$.ajax( { url: "/code/eips/" + thread_id + 
			'?min_eip=' + this.min_eip + 
			'&max_eip=' + this.max_eip + 
			'&min_takt=' + this.min_takt + 
			'&max_takt=' + this.max_takt,
			dataType: 'json' } )
		.done( function(results) {
			results.forEach( function(v) {
				var eip = v[0], takt = v[1]
				that.point(eip, takt)
			} )
			that.draw()
		} )
	}

	this.update = function()
	{
		this.reset()
		this.load()
	}
	this.reset = function()
	{
		ctx.clearRect(0, 0, width, height)
		layers = [ ctx.getImageData(0, 0, width, height) ]
		this.pages = []
		points = []
		comments = []
	}
	this.load = function()
	{
		var that = this
		if(! threads.length)
			$.ajax( { url: "/code/threads", dataType: 'json' } )
			.done( function (results) {
				results.forEach( function(thread_id) {
					threads.push(thread_id)
					that.pixel = get_random_colors()
					threads_colors.push(that.pixel)
					that.execution_flows( thread_id )
				} )
			} )
		else
			for(var i = 0; i < threads.length; i++)
			{
				this.pixel = threads_colors[i]
				this.execution_flows( threads[i] )
			}
	}
	this.init = function()
	{
		var that = this
		this.reset()
		if(! this.min_takt)
			$.ajax( { url: "/code/takts/min" } )
			.done( function(result) {
				if(result)
				{
					that.min_takt = parseInt(result)
					takts_per_pixel = Math.abs( (that.max_takt-that.min_takt) / width )
					that.grid()
				}
			} )
		if(! this.max_takt)
			$.ajax( { url: "/code/takts/max" } )
			.done( function(result) {
				if(result)
				{
					that.max_takt = parseInt(result)
					takts_per_pixel = Math.abs( (that.max_takt-that.min_takt) / width )
					that.grid()
				}
			} )
		if(! this.min_eip)
			$.ajax( { url: "/code/eips/min" } )
			.done( function(result) {
				if(result)
				{
					that.min_eip = parseInt(result)
					eips_per_pixel = Math.abs( (that.max_eip-that.min_eip) / height )
					that.grid()
				}
			} )
		if(! this.max_eip)
			$.ajax( { url: "/code/eips/max" } )
			.done( function(result) {
				if(result)
				{
					that.max_eip = parseInt(result)
					eips_per_pixel = Math.abs( (that.max_eip-that.min_eip) / height )
					that.grid()
				}
			} )
		this.load()
	}
	this.select = function(x_from, x_to, y_from, y_to)
	{
		current_layer = 2
		for( var y = y_from; y < y_to; y++ )
			for( var x = x_from; x < x_to; x++ )
				set_pixel( [x,y], [0x77,0x77,0x77,0xff] )
		this.draw()
	}
	this.show_popup = function(xy, text)
	{
		this.draw()
		ctx.fillText( text, xy[0], xy[1] )
	}
	this.goto = function(takt)
	{
		var x = this.get_x(takt),
			eip = this.find_eip(takt),
			y = this.get_y(eip)
		console.log( sprintf('goto: takt=%d, eip=0x%08x', takt, eip) )
		points = [ { xy: [x,y], radius: 3 } ]
		this.draw()
	}
	this.draw = function()
	{
		for( var i = 0; i < layers.length; i++ )
			if( layers[i] != undefined )
				ctx.putImageData( layers[i], 0, 0 )
		for( var i = 0; i < comments.length; i++ )	
			ctx.fillText( comments[i].text, comments[i].xy[0], comments[i].xy[1] )
		ctx.beginPath()
		for( var i = 0; i < points.length; i++ )
			ctx.arc( points[i].xy[0], points[i].xy[1], points[i].radius, 0*Math.PI, 2*Math.PI)
		ctx.stroke()
	}

	this.get_x = function(takt)
	{
		return parseInt( takt / takts_per_pixel - this.min_takt )
	}
	this.get_y = function(eip)
	{
		return parseInt( eip / eips_per_pixel - this.min_eip )
	}
	this.get_takt = function(x)
	{
		return parseInt( this.min_takt + takts_per_pixel * x )
	}
	this.get_eip = function(y)
	{
		return parseInt( this.min_eip + eips_per_pixel * y )
	}
	this.find_eip = function(takt)
	{
		current_layer = 0
		var x = this.get_x(takt)
		for(var y = 0; y < height; y++)
			if( get_pixel( [x,y] ) != [] )
				return this.get_eip(y)
		return 0
	}
}


function Data_bar(elem_selector)
{
	var elem = $(elem_selector)[0],
		ctx = elem.getContext('2d'),
		width = elem.offsetWidth,
		height = elem.offsetHeight,
		layers = [],
		current_layer = 0,
		addrs_per_pixel = 0,
		points = [],
		comments = []
		
	this.pages = []
	this.min_addr = 0
	this.max_addr = 0

	ctx.font = "10px Arial"

	var get_prev_layer = function(layer)
	{
		for( var i = layer; i >= 0; i-- )
			if( layers[i] != undefined )
				return layers[i]
	}
	var clear_layer = function(layer)
	{
		if( layers[layer] != undefined )
			layers[layer] = get_prev_layer(layer)
	}
	var set_pixel = function(xy, rgba)
	{
		var point = 0
		if( typeof(xy) == 'number' )
			point = xy * 4
		else
			point = xy[0] * 4 + width * xy[1] * 4
		if( layers[current_layer] == undefined )
			layers[current_layer] = get_prev_layer(current_layer)	// clone prev layer
		for(var i = 0; i < 4; i++)
			layers[current_layer].data[point + i] = rgba[i]
	}
	var set_text = function(xy, text)
	{
		comments.push( {xy:xy, text:text} )
	}

	this.grid = function()
	{
		current_layer = 1
		comments = []
		var delta_grid_y = parseInt( (this.max_addr-this.min_addr)/addrs_per_pixel/width/10 ),
			delta_grid_addr = parseInt( (this.max_addr-this.min_addr)/10 ),
			addr = this.min_addr
		for( var y = delta_grid_y; y < height; y += delta_grid_y )
		{
			for( var x = 0; x < width; x += 4 )
				set_pixel( [x,y], [0x00,0x00,0x00,0xff] )
			addr += delta_grid_addr
			set_text( [1,y], sprintf("0x%08x", addr) )
		}
	}
	this.byte = function(addr, count)
	{
		current_layer = 0
		var point = this.get_point(addr),
			gradient = 0x77 + count * 2
		gradient = ( gradient < 0x100 ) ? gradient : 0xff
		if(addrs_per_pixel >= 1)
			set_pixel( point, [gradient, 0x00, 0x00, gradient] )
		else
		{
			for(var i = 0; i < parseInt(1/addrs_per_pixel); i++)
				set_pixel( point+i, [gradient, 0x00, 0x00, gradient] )
		}
	}
	this.load_page = function(low_addr, high_addr)
	{
		var that = this
		$.ajax( { url: '/data/accesses/' + low_addr + '/' + high_addr, dataType: 'json' } )
		.done( function(result) {
			result.forEach( function(v) {
				var addr = parseInt( v[0] ), accesses = v[1]
				that.byte(addr, accesses)
			} )
			that.draw()
		} )
	}
	this.update = function()
	{
		this.reset()
		this.load()
	}
	this.reset = function()
	{
		ctx.clearRect(0, 0, width, height)
		layers = [ ctx.getImageData(0, 0, width, height) ]
		this.pages = []
	}
	this.load = function()
	{
		for( var i = 0; i < this.pages.length; i++ )
			this.load_page( this.pages[i].low_addr, this.pages[i].high_addr )
		this.grid()
		this.set_title( sprintf( "scale 1px=%.03fBytes", addrs_per_pixel ) )
		points = []
	}
	this.init = function()
	{
		this.reset()
		var that = this, addrs = []
		$.ajax( { url: '/data/pages/' + ((this.max_addr) ? '?min_addr=' + this.min_addr + '&max_addr=' + this.max_addr : ''), dataType: 'json' } )
		.done( function(result) {
			result.forEach( function(v) {
				var name = v[0], low_addr = v[1], high_addr = v[2]
				that.pages.push( { low_addr: low_addr, high_addr: high_addr } )
				addrs.push(low_addr)
				addrs.push(high_addr)
			} )
			if(! addrs.length)
				addrs = [0]
			that.min_addr = Math.min.apply(null, addrs)
			that.max_addr = Math.max.apply(null, addrs)
			addrs_per_pixel = (that.max_addr-that.min_addr) / (width * height)
			that.load()
		} )
	}

	this.select = function(y_from, y_to)
	{
		current_layer = 2
		for( var y = y_from; y < y_to; y++ )
			for( var x = 0; x < width; x++ )
				set_pixel( [x,y], [0x77,0x77,0x77,0xff] )
		this.draw()
	}
	this.show_popup = function(xy, text)
	{
		this.draw()
		ctx.fillText( text, xy[0], xy[1] )
	}
	this.goto = function(addr)
	{
		points = [ { xy: this.get_xy(addr), radius: 3 } ]
		this.draw()
	}
	this.draw = function()
	{
		for( var i = 0; i < layers.length; i++ )
			if( layers[i] != undefined )
				ctx.putImageData( layers[i], 0, 0 )
		for( var i = 0; i < comments.length; i++ )	
			ctx.fillText( comments[i].text, comments[i].xy[0], comments[i].xy[1] )
		ctx.beginPath()
		for( var i = 0; i < points.length; i++ )
			ctx.arc( points[i].xy[0], points[i].xy[1], points[i].radius, 0*Math.PI, 2*Math.PI)
		ctx.stroke()
	}
	this.get_addr = function(x,y)
	{
		return parseInt( this.min_addr + addrs_per_pixel * ( (y-1) * width + x ) )
	}
	this.get_point = function(addr)
	{
		return parseInt( (addr - this.min_addr) / addrs_per_pixel )
	}
	this.get_xy = function(addr)
	{
		var y = parseInt( this.get_point(addr)/width ),
			x = this.get_point(addr) % width
		return [x,y]
	}
}

function Code_bar(elem_selector)
{
	var elem = $(elem_selector)[0]
		ctx = elem.getContext('2d'),
		width = elem.offsetWidth,
		height = elem.offsetHeight,
		layers = [],
		current_layer = 0,
		eips_per_pixel = 0,
		comments = [],
		points = []
		
	this.pages = []
	this.min_eip = 0
	this.max_eip = 0

	ctx.font = "10px Arial"

	var get_prev_layer = function(layer)
	{
		for( var i = layer; i >= 0; i-- )
			if( layers[i] != undefined )
				return layers[i]
	}
	var clear_layer = function(layer)
	{
		if( layers[layer] != undefined )
			layers[layer] = get_prev_layer(layer)
	}
	var set_pixel = function(xy, rgba)
	{
		var point = 0
		if( typeof(xy) == 'number' )
			point = xy * 4
		else
			point = xy[0] * 4 + width * xy[1] * 4
		if( layers[current_layer] == undefined )
			layers[current_layer] = get_prev_layer(current_layer)	// clone prev layer
		for(var i = 0; i < 4; i++)
			layers[current_layer].data[point + i] = rgba[i]
	}
	var set_text = function(xy, text)
	{
		comments.push( {xy:xy, text:text} )
	}

	this.grid = function()
	{
		current_layer = 1
		comments = []
		var delta_grid_y = parseInt( (this.max_eip-this.min_eip)/eips_per_pixel/width/10 ),
			delta_grid_eip = parseInt( (this.max_eip-this.min_eip)/10 ),
			eip = this.min_eip
		for( var y = delta_grid_y; y < height; y += delta_grid_y )
		{
			for( var x = 0; x < width; x += 4 )
				set_pixel( [x,y], [0x00,0x00,0x00,0xff] )
			eip += delta_grid_eip
			set_text( [1,y], sprintf("0x%08x", eip) )
		}
	}
	this.intruction = function(eip, count)
	{
		current_layer = 0
		var point = this.get_point(eip),
			gradient = 0x77 + count * 2
		gradient = ( gradient < 0x100 ) ? gradient : 0xff
		if(eips_per_pixel >= 1)
			set_pixel( point, [gradient, 0x00, 0x00, gradient] )
		else
		{
			for(var i = 0; i < parseInt(1/eips_per_pixel); i++)
				set_pixel( point+i, [gradient, 0x00, 0x00, gradient] )
		}
	}
	this.load_page = function(low_eip, high_eip)
	{
		var that = this
		$.ajax( { url: '/code/exec/' + low_eip + '/' + high_eip, dataType: 'json' } )
		.done( function(result) {
			result.forEach( function(v) {
				var eip = parseInt( v[0] ), count = v[1]
				that.intruction(eip, count)
			} )
			that.draw()
		} )
	}
	this.update = function()
	{
		this.reset()
		this.load()
	}
	this.reset = function()
	{
		ctx.clearRect(0, 0, width, height)
		layers = [ ctx.getImageData(0, 0, width, height) ]
		this.pages = []
	}
	this.load = function()
	{
		for( var i = 0; i < this.pages.length; i++ )
			this.load_page( this.pages[i].low_eip, this.pages[i].high_eip )
		this.grid()
		this.set_title( sprintf( "scale 1px=%.03fBytes", eips_per_pixel ) )
		points = []
	}
	this.init = function()
	{
		this.reset()
		var that = this, eips = []
		$.ajax( { url: '/code/pages/' + ((this.max_eip) ? '?min_eip=' + this.min_eip + '&max_eip=' + this.max_eip : ''), dataType: 'json' } )
		.done( function(result) {
			result.forEach( function(v) {
				var name = v[0], low_eip = v[1], high_eip = v[2]
				that.pages.push( { low_eip: low_eip, high_eip: high_eip } )
				eips.push(low_eip)
				eips.push(high_eip)
			} )
			if(! eips.length)
				eips = [0]
			that.min_eip = Math.min.apply(null, eips)
			that.max_eip = Math.max.apply(null, eips)
			eips_per_pixel = (that.max_eip-that.min_eip) / (width * height)
			that.load()
		} )
	}
	this.select = function(y_from, y_to)
	{
		current_layer = 2
		for( var y = y_from; y < y_to; y++ )
			for( var x = 0; x < width; x++ )
				set_pixel( [x,y], [0x77,0x77,0x77,0xff] )
		this.draw()
	}
	this.show_popup = function(xy, text)
	{
		this.draw()
		ctx.fillText( text, xy[0], xy[1] )
	}
	this.goto = function(eip)
	{
		points = [ { xy: this.get_xy(eip), radius: 3 } ]
		this.draw()
	}
	this.draw = function()
	{
		for( var i = 0; i < layers.length; i++ )
			if( layers[i] != undefined )
				ctx.putImageData( layers[i], 0, 0 )
		for( var i = 0; i < comments.length; i++ )	
			ctx.fillText( comments[i].text, comments[i].xy[0], comments[i].xy[1] )
		ctx.beginPath()
		for( var i = 0; i < points.length; i++ )
			ctx.arc( points[i].xy[0], points[i].xy[1], points[i].radius, 0*Math.PI, 2*Math.PI)
		ctx.stroke()
	}
	this.get_eip = function(x,y)
	{
		return parseInt( this.min_eip + eips_per_pixel * ( (y-1) * width + x ) )
	}
	this.get_point = function(eip)
	{
		return parseInt( (eip - this.min_eip) / eips_per_pixel )
	}
	this.get_xy = function(eip)
	{
		var y = parseInt( this.get_point(eip)/width ),
			x = this.get_point(eip) % width
		return [x,y]
	}
}

var KEYS = {
	PLUS: 107,
	MINUS: 109,
	UP: 38,
	DOWN: 40,
	RIGHT: 39,
	LEFT: 37,
	F8: 119,
	F10: 121
}


var Windows = {
	pool: [],
	num: 0,
	get_code_window_last: function()
	{
		for(var i = Windows.pool.length-1; i >= 0 ; i--)
			if( Windows.pool[i].indexOf('code_window') != -1 )
				return $( Windows.pool[i] )[0].obj
	},
	get_data_window_last: function()
	{
		for(var i = Windows.pool.length-1; i >= 0 ; i--)
			if( Windows.pool[i].indexOf('data_window') != -1 )
				return $( Windows.pool[i] )[0].obj
	},
	get_exec_window_last: function()
	{
		for(var i = Windows.pool.length-1; i >= 0 ; i--)
			if( Windows.pool[i].indexOf('exec_window') != -1 )
				return $( Windows.pool[i] )[0].obj
	}
}


function Dialog_window(head)
{
	this.id = Windows.num++
	this.elem_selector = '#dialog' + this.id
	this.head = head
	this.body = ''

	function create(that)
	{
		$('#windows').append( '<div id="dialog' + that.id + '"></div>' )
		$(that.elem_selector).dialog( {
			title: that.head.join('\t'),
			maxHeight: 500,
			minWidth: 310
		} )
		$(that.elem_selector)[0].obj = that

		Windows.pool.push( that.elem_selector )
	}
	create(this)

	this.load = function(body)
	{
		var that = this
		for(var i = 0; i < body.length; i++)
		{
			this.body += '<table border=1><tbody><tr>'
			for(var j = 0; j < this.head.length; j++)
				this.body += '<td>' + sprintf( "%X", body[i][j] ) + '</td>'
			this.body += '</tr></tbody></table>'
		}
		$(that.elem_selector).html(that.body)
	}
	this.sort = function(col)
	{
		var old_body = this.body, new_body = []
		/*for(var i = 0; i < old_body.length; i++)
			if( old_body[i][col] > )*/

		this.load(new_body)
	}
}

function Hex_window()
{
	this.id = Windows.num++
	this.elem_selector = '#data_window' + this.id
	this.head = 'HEX'
	this.body = '\
		<div id="data_window' + this.id + '">\
			goto: <input class="goto" />\
			find: <input class="find" />\
			<table class="content" width="100%" tabindex="1" onkeypress="data_keys(event)">\
				<tbody>\
				</tbody>\
			</table>\
		</div>\
	'
	Hex.apply(this)

	function create(that)
	{
		$('#windows').append( that.body )
		$(that.elem_selector).dialog( {
			title: that.head,
			minWidth: 600,
			minHeight: 300,
		} )

		$(that.elem_selector + ' .goto').bind('change', function() { that.goto(this.value) })
		$(that.elem_selector + ' .find').bind('change', function() { that.search(this.value) })
		$(that.elem_selector + ' .content').bind('click', function(event) { that.data_xref(event) } )
		$(that.elem_selector)[0].obj = that

		Windows.pool.push( that.elem_selector )
	}
	create(this)


	this.set_title = function(title)
	{
		$(this.elem_selector).dialog('option', 'title', title)
	}


	this.offset = 0
	this.goto = function(addr)
	{
		console.log('this.goto()' + addr)
		addr = parseInt(addr)
		this.offset = addr
		var that = this
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
			that.load( hex_data )
			that.select(addr, DWORD)
		} )
	}

	this.code = function(addr)
	{
		var cell
		if( cell = this.data_containers[0].get_cell(addr) )
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
				dialog = new Dialog_window( ["takt","thread_id","eip","value"] )
				dialog.load(changes)
				return dialog
			}
		}
	}

	this.search = function(pattern)
	{
		var hex_string = ''
		console.log(pattern)
		if( pattern.indexOf('0x') == 0 )
			hex_string = pattern.slice(2)
		else
			for( var i = 0; i < pattern.length; i++ )
				hex_string += pattern.charCodeAt(i).toString(16)
		console.log(hex_string)
		var that = this
		$.ajax( { url: '/data/search/' + hex_string + '?takt=' + current_takt } )
		.done( function(addr) {
			if(addr)
				that.goto(addr)
		} )
	}

	this.data_xref = function(event)
	{
		var addr = event.target.getAttribute('addr')
		this.code( addr )
	}
}

function Disas_window()
{
	this.id = Windows.num++
	this.elem_selector = '#code_window' + this.id
	this.head = 'Disasm'
	this.body = '\
		<div id="code_window' + this.id + '">\
			goto: <input class="goto" />\
			find: <input class="find" />\
			<table class="content" tabindex="1" onkeypress="code_keys(event)">\
				<thead>\
				</thead>\
				<tbody>\
				</tbody>\
			</table>\
		</div>\
	'
	Disas.apply(this)

	function create(that)
	{
		$('#windows').append( that.body )
		$(that.elem_selector).dialog( {
			title: that.head,
			minWidth: 600,
			minHeight: 300,
		} )

		$(that.elem_selector + ' .goto').bind('change', function() { that.goto(this.value) })
		$(that.elem_selector + ' .find').bind('change', function() { that.search(this.value) })
		$(that.elem_selector + ' .content').bind('click', function(event) { that.code_xrefs(event) })
		$(that.elem_selector)[0].obj = that

		Windows.pool.push( that.elem_selector )
	}
	create(this)

	this.set_title = function(title)
	{
		$(this.elem_selector).dialog('option', 'title', title)
	}

	this.offset = 0
	this.goto = function(addr)
	{
		addr = parseInt(addr)
		this.offset = addr
		var that = this
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
			that.load( code )
		} )
	}

	this.data = function(addr)
	{
		if(cell = this.code_containers[0].get_cell(addr))
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
				dialog = new Dialog_window( ["takt","addr","value"] )
				dialog.load(changes)
				return dialog
			}
		}
	},
	this.search = function(instruction)
	{
		var that = this
		$.ajax( { url: '/code/search/' + instruction } )
		.done( function(eip) {
			if(eip)
				that.goto(eip)
		} )
	}

	this.code_xrefs = function(event)
	{
		var addr = event.target.getAttribute('addr')
		this.data( addr )
	}

}


function Exec_window()
{
	this.id = Windows.num++
	this.elem_selector = '#exec_window' + this.id
	this.head = 'Execute'
	this.body = '\
		<div id="exec_window' + this.id + '">\
			goto: <input class="goto" />\
			find: <input class="find" />\
			<div class="regs"></div>\
			<table class="content" tabindex="1" onkeypress="code_keys(event)">\
				<thead>\
				</thead>\
				<tbody>\
				</tbody>\
			</table>\
		</div>\
	'
	this.takt = 0
	this.next_takt = 0
	this.prev_takt = 0

	this.eip = 0
	this.eax = 0
	this.ecx = 0
	this.edx = 0
	this.ebx = 0
	this.esp = 0
	this.ebp = 0
	this.esi = 0
	this.edi = 0

	Exec.apply(this)

	function create(that)
	{
		$('#windows').append( that.body )
		$(that.elem_selector).dialog( {
			title: that.head,
			minWidth: 700,
			minHeight: 300,
		} )

		$(that.elem_selector + ' .goto').bind('change', function() { that.goto(this.value) })
		$(that.elem_selector + ' .find').bind('change', function() { that.search(this.value) })
		$(that.elem_selector).bind('keydown', function(event) { that.key(event) })
		$(that.elem_selector + ' .content').bind('click', function(event) { that.code_xrefs(event) })
		$(that.elem_selector)[0].obj = that

		Windows.pool.push( that.elem_selector )
	}
	create(this)

	this.key = function(event)
	{
		var key = event.keyCode
		console.log(key)
		switch(key)
		{
			case KEYS.F8:
				this.step()
				break
			case KEYS.F10:
				this.step_back()
				break
		}
	}
	this.update = function()
	{
		var that = this
		$(that.elem_selector).html(that.body)
	}
	this.set_title = function(title)
	{
		$(this.elem_selector).dialog('option', 'title', title)
	}
	this.set_registers = function( registers=[0,0,0,0,0,0,0,0] )
	{
		var reg_names = ['EAX', 'ECX', 'EDX', 'EBX', 'ESP', 'EBP', 'ESI', 'EDI'],
			old_val = [this.eax, this.ecx, this.edx, this.ebx, this.esp, this.ebp, this.esi, this.edi],
			content = []
		for(var i = 0; i < registers.length; i++)
			content.push( sprintf('<td class="%s">%s:0x%08X</td>', ( ( registers[i] != old_val[i] ) ? 'reg_modified' : 'reg_const' ), reg_names[i], registers[i] ) )
		var that = this
		$(that.elem_selector + ' .regs').html( '<table><tbody><tr>' + content.slice(0,4).join('') + '</tr><tr>' + content.slice(4,8).join('') + '</tr></tbody></table>')
		this.eax = registers[0]
		this.ecx = registers[1]
		this.edx = registers[2]
		this.ebx = registers[3]
		this.esp = registers[4]
		this.ebp = registers[5]
		this.esi = registers[6]
		this.edi = registers[7]
	}

	this.goto = function(takt)
	{
		takt = parseInt(takt)
		current_takt = takt
		this.takt = takt
		this.next_takt = 0
		this.prev_takt = 0
		var that = this
		$.ajax( { url: "/exec/" + takt + "?lines=" + code_lines, dataType: 'json' } )
		.done( function(result) {
			var executes = new Execute.Container()
			result.forEach( function(v) {
				var takt = v[0], thread_id = v[1], eip = v[2], opcode = v[3], mnem = v[4], operands = v[5],
					eax = v[6], ecx = v[7], edx = v[8], ebx = v[9], esp = v[10], ebp = v[11], esi = v[12], edi = v[13],
					addr = v[14], value = v[15], access_type = v[16]								
				var state = executes.get_state(takt), is_new_state = false
				if( takt < that.takt )
					that.prev_takt = takt
				else if(! that.next_takt && takt > that.takt)
					that.next_takt = takt
				if(! state)
				{
					state = new Execute.Cpu(takt)
					state.thread_id = thread_id
					state.eip = eip
					state.registers = [eax,ecx,edx,ebx,esp,ebp,esi,edi]
					state.instruction = new Execute.Instruction(mnem, operands)
					state.instruction.opcode = opcode
					is_new_state = true
				}

				if(access_type)
				{
					var access = new Execute.Access( new Data.Byte(value) )					
					access.addr = parseInt(addr)
					access.type = access_type
					state.accesses.push(access)
				}
				if(is_new_state)
					executes.add_state( state )
			} )
			that.load( executes )
			that.select(takt)
			var current_state = executes.get_state(that.takt),
				mem_access = (current_state.accesses.length) ? current_state.accesses[0].addr : 0
			that.eip = current_state.eip
			that.set_title( sprintf("execute [thread: %04x] [0x%08x] (mem: 0x%08x)", current_state.thread_id, that.eip, mem_access) )
			that.set_registers( current_state.registers )

			var data_window = Windows.get_data_window_last()
			data_window.update()
			if(mem_access)
				data_window.highlight( mem_access, DWORD )
		} )
	}

	this.data = function(takt)
	{
		if( state = this.state_containers[0].get_state(takt) )
		{
			/*
			var changes = []
			for(var i = 0; i < state.instructions.length; i++)
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
				dialog = new Dialog_window( ["takt","addr","value"] )
				dialog.load(changes)
				return dialog
			}
			*/
		}
	}
	this.step = function()
	{
		this.goto( this.next_takt )
	}
	this.step_back = function()
	{
		this.goto( this.prev_takt )	
	}
	this.search = function(register_value)
	{
		var that = this
		$.ajax( { url: '/exec/search/' + register_value } )
		.done( function(takt) {
			if(takt)
				that.goto(takt)
		} )
	}

	this.code_xrefs = function(event)
	{
		var addr = event.target.getAttribute('addr')
		this.data( addr )
	}

}



function Code_bar_window()
{
	this.id = Windows.num++
	this.elem_selector = '#code_bar' + this.id
	this.is_select_mode = false
	this.head = 'code coverage'
	this.body = '\
		<canvas id="code_bar' + this.id + '" class="bars" height="700" width="250"></canvas>\
	'
	var y_from = 0, y_to = 0,
		min_eip = 0, max_eip = 0

	function create(that)
	{
		$('#windows').append( that.body )
		$(that.elem_selector).dialog( {
			title: that.head,
			minWidth: 250,
			minHeight: 700,
		} )

		$(that.elem_selector).bind('mousedown', function(event) { that.click(event) })
		$(that.elem_selector).bind('mouseup', function(event) { that.unclick(event) })
		$(that.elem_selector).bind('mousemove', function(event) { that.popup(event) })
		$(that.elem_selector)[0].obj = that

		Windows.pool.push( that.elem_selector )
	}
	create(this)

	Code_bar.apply(this, [this.elem_selector])
	this.init()

	this.set_title = function(title)
	{
		$(this.elem_selector).dialog('option', 'title', title)
	}
	this.click = function(event)
	{
		var that = this
		$(that.elem_selector).bind('mousemove', function(event) { that.drag(event) })
		this.is_select_mode = false
	}
	this.drag = function(event)
	{
		this.is_select_mode = true
		var y = parseInt( event.clientY - event.target.getBoundingClientRect().top )
		if(! y_from)
			y_from = y
		y_to = y
		this.select( (y_from < y_to) ? y_from : y_to, (y_from < y_to) ? y_to : y_from )
		min_eip = this.get_eip(0, y_from)
		max_eip = this.get_eip(0, y_to)
	}
	this.popup = function(event)
	{
		var x = parseInt( event.clientX - event.target.getBoundingClientRect().left ),
			y = parseInt( event.clientY - event.target.getBoundingClientRect().top )
		this.show_popup( [x,y], sprintf( "0x%08x", this.get_eip(x,y) ) )
	}
	this.unclick = function(event)
	{
		var x = parseInt( event.clientX - event.target.getBoundingClientRect().left ),
			y = parseInt( event.clientY - event.target.getBoundingClientRect().top ),
			that = this
		y_from = y_to = 0
		$(that.elem_selector).unbind('mousemove')
		$(that.elem_selector).bind('mousemove', function(event) { that.popup(event) })
		if( this.is_select_mode)
		{
			this.min_eip = min_eip
			this.max_eip = max_eip
			this.init()
		}
		else
			this.disas_goto( this.get_eip(x,y) )
	}
	this.disas_goto = function(eip)
	{
		var code_window = Windows.get_code_window_last()
		code_window.set_title( sprintf( 'disas [0x%08x]', eip) )
		code_window.goto(eip)
		console.log( "eip: " + sprintf("0x%08x", eip) )
	}
}


function Data_bar_window()
{
	this.id = Windows.num++
	this.elem_selector = '#data_bar' + this.id
	this.is_select_mode = false
	this.head = 'data usage'
	this.body = '\
		<canvas id="data_bar' + this.id + '" class="bars" height="700" width="250"></canvas>\
	'

	var y_from = 0, y_to = 0,
		min_addr = 0, max_addr = 0

	function create(that)
	{
		$('#windows').append( that.body )
		$(that.elem_selector).dialog( {
			title: that.head,
			minWidth: 250,
			minHeight: 700,
		} )

		$(that.elem_selector).bind('mousedown', function(event) { that.click(event) })
		$(that.elem_selector).bind('mouseup', function(event) { that.unclick(event) })
		$(that.elem_selector).bind('mousemove', function(event) { that.popup(event) })
		$(that.elem_selector)[0].obj = that

		Windows.pool.push( that.elem_selector )
	}
	create(this)

	Data_bar.apply(this, [this.elem_selector])
	this.init()

	this.set_title = function(title)
	{
		$(this.elem_selector).dialog('option', 'title', title)
	}
	this.click = function(event)
	{
		var that = this
		$(that.elem_selector).bind('mousemove', function(event) { that.drag(event) })
		this.is_select_mode = false
	}
	this.drag = function(event)
	{
		this.is_select_mode = true
		var y = parseInt( event.clientY - event.target.getBoundingClientRect().top )
		if(! y_from)
			y_from = y
		y_to = y
		this.select( (y_from < y_to) ? y_from : y_to, (y_from < y_to) ? y_to : y_from )
		min_addr = this.get_addr( 0, y_from )
		max_addr = this.get_addr( 0, y_to )
	}
	this.popup = function(event)
	{
		var x = parseInt( event.clientX - event.target.getBoundingClientRect().left ),
			y = parseInt( event.clientY - event.target.getBoundingClientRect().top )
		this.show_popup( [x,y], sprintf( "0x%08x", this.get_addr(x,y) ) )
	}
	this.unclick = function(event)
	{
		var x = parseInt( event.clientX - event.target.getBoundingClientRect().left ),
			y = parseInt( event.clientY - event.target.getBoundingClientRect().top ),
			that = this
		y_from = y_to = 0
		$(that.elem_selector).unbind('mousemove')
		$(that.elem_selector).bind('mousemove', function(event) { that.popup(event) })
		if( this.is_select_mode)
		{
			this.min_addr = min_addr
			this.max_addr = max_addr
			this.init()
		}
		else
			this.hex_goto( this.get_addr(x,y) )
	}
	this.hex_goto = function(addr)
	{
		var data_window = Windows.get_data_window_last()
		data_window.set_title( sprintf('hex [0x%08x]', addr) )
		data_window.goto(addr)
	}
}


function Context_bar_window()
{
	this.id = Windows.num++
	this.elem_selector = '#context_bar' + this.id
	this.is_select_mode = false
	this.head = 'contexts'
	this.body = '\
		<canvas id="context_bar' + this.id + '" class="bars" height="120" width="1200"></canvas>\
	'

	var x_from = 0, x_to = 0, y_from = 0, y_to = 0,
		min_takt = 0, max_takt = 0, min_eip = 0, max_eip = 0
	function create(that)
	{
		$('#windows').append( that.body )
		$(that.elem_selector).dialog( {
			title: that.head,
			minWidth: 1200,
			minHeight: 120,
		} )

		$(that.elem_selector).bind('mousedown', function(event) { that.click(event) })
		$(that.elem_selector).bind('mouseup', function(event) { that.unclick(event) })
		$(that.elem_selector).bind('mousemove', function(event) { that.popup(event) })
		$(that.elem_selector)[0].obj = that

		Windows.pool.push( that.elem_selector )
	}
	create(this)

	Context_bar.apply(this, [this.elem_selector])
	this.init()

	this.set_title = function(title)
	{
		$(this.elem_selector).dialog('option', 'title', title)
	}
	this.click = function(event)
	{
		var that = this
		$(that.elem_selector).bind('mousemove', function(event) { that.drag(event) })
		this.is_select_mode = false
	}
	this.drag = function(event)
	{
		this.is_select_mode = true
		var x = parseInt( event.clientX - event.target.getBoundingClientRect().left ),
			y = parseInt( event.clientY - event.target.getBoundingClientRect().top )
		if(! x_from)
			x_from = x
		if(! y_from)
			y_from = y
		x_to = x
		y_to = y
		this.select( (x_from < x_to) ? x_from : x_to, (x_from < x_to) ? x_to : x_from, (y_from < y_to) ? y_from : y_to, (y_from < y_to) ? y_to : y_from )
		min_takt = this.get_takt( x_from )
		max_takt = this.get_takt( x_to )
		min_eip = this.get_eip( y_from )
		max_eip = this.get_eip( y_to )
	}
	this.popup = function(event)
	{
		var x = parseInt( event.clientX - event.target.getBoundingClientRect().left ),
			y = parseInt( event.clientY - event.target.getBoundingClientRect().top )
		this.show_popup( [x,y], sprintf( "%d: 0x%08x", this.get_takt(x), this.get_eip(y) ) )
	}
	this.unclick = function(event)
	{
		var x = parseInt( event.clientX - event.target.getBoundingClientRect().left ),
			y = parseInt( event.clientY - event.target.getBoundingClientRect().top ),
			that = this
		y_from = y_to = 0
		$(that.elem_selector).unbind('mousemove')
		$(that.elem_selector).bind('mousemove', function(event) { that.popup(event) })
		if( this.is_select_mode)
		{
			this.min_eip = min_eip
			this.max_eip = max_eip
			this.min_takt = min_takt
			this.max_takt = max_takt
			this.init()
		}
		else
			this.takt_goto( this.get_takt(x) )
	}
	this.takt_goto = function(takt)
	{
		console.log('goto takt=' + takt)
		var exec_window = Windows.get_exec_window_last()
		exec_window.set_title( sprintf('takt [%d]', takt) )
		exec_window.goto(takt)
	}
}



var code_bar, data_bar, ctx_bar,
	data_window, code_window, exec_window
function init()
{
	code_bar = new Code_bar_window()
	ctx_bar = new Context_bar_window()
	data_bar = new Data_bar_window()
	
	data_window = new Hex_window()
	code_window = new Disas_window()
	exec_window = new Exec_window()
	console.log("v0.23.36")
}