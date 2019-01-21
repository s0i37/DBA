function get_mem_rw_ops(elem)
{
	var reads = $(elem).attr('r'),
		writes = $(elem).attr('w'),
		out = '',
		to_hexline = function(hex) { return hex.slice(0,-1).toLowerCase() + '0' }
		if(writes)
		{
			out += '<div class="instructionw">writes:<br>'
			writes.split(';').forEach( function(i) { out += "<a href='#data" + to_hexline( i.split(':')[0] ) + "'>" + i.split(':')[0] + "</a> <- " + i.split(':')[1] + "<br>" } )
			out += '</div>'
		}
		if(reads)
		{
			out += '<div class="instructionr">reads:<br>'
			reads.split(';').forEach( function(i) { out += "<a href='#data" + to_hexline( i.split(':')[0] ) + "'>" + i.split(':')[0] + "</a> -> " + i.split(':')[1] + "<br>" } )
			out += '</div>'
		}
		return out
}

function get_states(elem)
{
	var states = $(elem).attr('states'),
		out = '<table class="state"><tbody>',
		to_hexline = function(hex) { return hex.slice(0,-1).toLowerCase() + '0' }
	if(states)
	{
		out += '<tr><td>takt</td><td>threadId</td><td>EAX</td><td>ECX</td><td>EDX</td><td>EBX</td><td>ESI</td><td>EDI</td><td>EBP</td><td>ESP</td></tr>'
		states.split(';').forEach( function(s) {
			var number = s.split(':')[0],
				threadid = s.split(':')[1],
				regs = s.split(':')[2].split(',')
			out += '<tr><td>' + number + '</td><td>' + threadid + '</td><td><a href="#data' + to_hexline( regs[0] ) + '">' + regs[0] + '</a></td><td><a href="#data' + to_hexline( regs[1] ) + '">' + regs[1] + '</a></td><td><a href="#data' + to_hexline( regs[2] ) + '">' + regs[2] + '</a></td><td><a href="#data' + to_hexline( regs[3] ) + '">' + regs[3] + '</a></td><td><a href="#data' + to_hexline( regs[4] ) + '">' + regs[4] + '</a></td><td><a href="#data' + to_hexline( regs[5] ) + '">' + regs[5] + '</a></td><td><a href="#data' + to_hexline( regs[6] ) + '">' + regs[6] + '</a></td><td><a href="#data' + to_hexline( regs[7] ) + '">' + regs[7] + '</a></td></tr>'
		} )
	}
	out += '</tbody></table>'
	return out
}

$(document).ready( function() {
	$('#data').click( function(event) {
	  $('#dialog').dialog( {
		  	modal: false,
		  	maxHeight: 500,
		  	title: 'changes',
		  	open: function()
		  	{
		  		$.ajax( { url: "http://127.0.0.1:5000/data/" + 0x8000000,
					dataType: 'json' } )
				.done( function(results) {
					results.forEach( function(v) {
						console.log(v)
					} )
				} )

		  		if(event.target.className != 'byte')
		  		{
		  			$('#dialog').dialog('close')
		  			return
		  		}
		  		var reads = $(event.target).attr('r'),
		  			writes = $(event.target).attr('w'),
		  			out = ''
		  		if(writes)
		  		{
		  			out += '<div class="memoryw">writes:<br>'
		  			writes.split(';').forEach( function(i) { out += "<a href='#code" + i.split(':')[0] + "'>" + i.split(':')[0] + "</a> <- " + i.split(':')[1] + "<br>" } )
		  			out += '</div>'
		  		}
		  		if(reads)
		  		{
		  			out += '<div class="memoryr">reads:<br>'
		  			reads.split(';').forEach( function(i) { out += "<a href='#code" + i.split(':')[0] + "'>" + i.split(':')[0] + "</a> -> " + i.split(':')[1] + "<br>" } )
		  			out += '</div>'
		  		}
		  		$('#dialog').dialog( "option", "width", 250 );
		  		$('#dialog').html( out )
		  	},
		  	close: function()
		  	{
		  		$('#dialog').text('loading...')
		  	}
	  	} )
	} )

	$('#code').click( function(event) {
		$('#dialog').dialog( {
		  	modal: false,
		  	maxHeight: 500,
		  	open: function()
		  	{
		  		$.ajax( { url: "http://127.0.0.1:5000/code/" + 0x41414141,
					dataType: 'json' } )
				.done( function(results) {
					results.forEach( function(v) {
						console.log(v)
					} )
				} )

		  		var elem = event.target
		  		while(1)
		  		{
		  			if(elem.className == 'instr')
		  				break
		  			else if(elem.className == 'states')
		  				break
		  			else if(elem.tagName == 'HTML')
		  			{
		  				$('#dialog').dialog('close')
		  				return
		  			}
		  			else
		  				elem = elem.parentNode
		  		}
		  		var out = 'error'
		  		if(elem.className == 'instr')
		  		{
		  			out = get_mem_rw_ops(elem)
		  			$('#dialog').dialog( "option", "width", 250 );
		  			$('#dialog').dialog( "option", "title", 'memory operations' );
		  		}
		  		else if(elem.className == 'states')
		  		{
		  			out = get_states(elem)
		  			$('#dialog').dialog( "option", "width", 800 );
		  			$('#dialog').dialog( "option", "title", 'states' );
		  		}
		  		$('#dialog').html( out )
		  	},
		  	close: function()
		  	{
		  		$('#dialog').text('loading...')
		  	}
		} )
	} )

	$('#code code').each(function(i, block) {
    	hljs.highlightBlock(block);
  	})
} )