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
		  		if(event.target.className != 'byte')
		  		{
		  			$('#dialog').dialog('close')
		  			return
		  		}
		  		
		  		var out = ''
		  		$.ajax( { url: "http://127.0.0.1:5000/data/" + $(event.target).attr('addr'),
					dataType: 'json' } )
				.done( function(results) {
					results.forEach( function(v) {
						console.log(v)
						var takt = v[0], eip = v[1], val = v[2], access_type = v[3]
						if(access_type == 'w')
							out += '<div><a href="#" takt=' + takt + '>' + takt + '</a>  <a href="#' + eip + '">0x' + eip.toString(16) + '</a> <- ' + val.toString(16).toUpperCase() + '</div>'
						else if(access_type == 'r')
							out += '<div><a href="#" takt=' + takt + '>' + takt + '</a>  <a href="#' + eip + '">0x' + eip.toString(16) + '</a> -> ' + val.toString(16).toUpperCase() + '</div>'
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
		  			if(elem.className == 'instr')
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
		  		$.ajax( { url: "http://127.0.0.1:5000/code/" + $(elem).attr('eip'),
					dataType: 'json' } )
				.done( function(results) {
					results.forEach( function(v) {
						console.log(v)
						var takt = v[0], addr = v[1], val = v[2], access_type = v[3]
						if(access_type == 'w')
							out += '<div><a href="#" takt=' + takt + '>' + takt + '</a>  <a href="#' + ((addr>>4)<<4) + '">0x' + addr.toString(16) + '</a> <- ' + val.toString(16).toUpperCase() + '</div>'
						else if(access_type == 'r')
							out += '<div><a href="#" takt=' + takt + '>' + takt + '</a>  <a href="#' + ((addr>>4)<<4) + '">0x' + addr.toString(16) + '</a> -> ' + val.toString(16).toUpperCase() + '</div>'
					} )
					$('#dialog').dialog( "option", "width", 400 );
		  			$('#dialog').dialog( "option", "title", 'memory operations' );
		  			$('#dialog').html( out )
				} )

		  		/*
		  		if(elem.className == 'states')
		  		{
		  			out = get_states(elem)
		  			$('#dialog').dialog( "option", "width", 800 );
		  			$('#dialog').dialog( "option", "title", 'states' );
		  			$('#dialog').html( out )
		  		}
		  		*/
		  		
		  	},
		  	close: function()
		  	{
		  		$('#dialog').text('loading...')
		  	}
		} )
	} )

/*
	$('#code code').each(function(i, block) {
    	hljs.highlightBlock(block);
  	})
*/

} )