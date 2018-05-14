from flask import Flask, request, url_for, render_template, Response, stream_with_context
import sqlite3
import json

DB_FILE = "../memory.db"
app = Flask(__name__)
db = sqlite3.connect(DB_FILE, check_same_thread=False)
c = db.cursor()


def _int(a):
	return int(a[2:], 16) if a.find('0x')==0 else int(a)


@app.route( '/test', methods=['GET', 'POST'] )
def test():
	if request.method == 'POST':
		return str( request.form )
	else:
		return "test: " + str( request.args )


@app.route('/old')
def old():
	return render_template('index.html')

@app.route('/')
def index():
	return render_template('index2.html')


class Data:
	@app.route('/data/<int:addr>')
	def data_goto(addr):
		results = []
		lines = int( request.args.get("lines") or 1 )
		#print "select d.addr,d.value,d.takt,d.access_type,t.thread_id,c.eip from data d inner join takts t on d.takt=t.takt inner join code c on d.takt=c.takt where d.addr >= %d and d.addr <= %d order by d.addr" % (addr, addr+lines*0x10)
		for addr,val,takt,access_type,thread_id,eip in c.execute( "select d.addr,d.value,d.takt,d.access_type,t.thread_id,c.eip from data d inner join takts t on d.takt=t.takt inner join code c on d.takt=c.takt where d.addr >= ? and d.addr <= ? order by d.addr", (addr, addr+lines*0x10) ):
			#print addr,val,takt,access_type,thread_id,eip
			results.append( (addr,val,takt,access_type,thread_id,eip) )
		return json.dumps(results)

	@app.route('/data/code/<addr>')
	def data_instructions(addr):
		results = []
		for takt,thread_id,eip,value in c.execute( "select c.takt,t.thread_id,c.eip,d.value from code c inner join data d on c.takt=d.takt inner join c.takt=t.takt where d.addr=?", int(addr) ):
			results.append( (takt,thread_id,eip,value) )
		return json.dumps(results)

	@app.route('/data/pages/')
	def data_pages():
		min_addr = int( request.args.get("min_addr") or 0 )
		max_addr = int( request.args.get("max_addr") or 0 )
		results = []
		if max_addr:
			for name, low_addr, high_addr in c.execute( "select name, low_addr, high_addr from pages where perm_x != 1 and high_addr >= ? and low_addr <= ? order by low_addr", (min_addr, max_addr) ):
				results.append( (name, low_addr, high_addr) )	
		else:
			for name, low_addr, high_addr in c.execute( "select name, low_addr, high_addr from pages where perm_x != 1 order by low_addr" ):
				results.append( (name, low_addr, high_addr) )
		return json.dumps(results)

	@app.route('/data/accesses/<int:low_addr>/<int:high_addr>')
	def accesses(low_addr, high_addr):
		results = []
		for addr,accesses in c.execute( "select d.addr,count(d.value) from data d where d.addr >= ? and d.addr <= ? group by addr", (low_addr,high_addr) ):
			results.append( (addr,accesses) )
		return json.dumps(results)

	@app.route('/data/search/<hex_string>')
	def search(hex_string):
		takt = int( request.args.get("takt") or 0 )
		bytes = bytearray( hex_string.decode('hex') )
		
		def ascii_string(bytes):
			addrs = []
			byte = bytes.pop(0)
			result = c.execute( "select d.addr from data d where d.value = ? and d.takt >= ? order by 1 limit 1", (byte,takt) ).fetchone()
			if result:
				addr = result[0]
				addrs.append(addr)
				for byte in bytes:
					addr += 1
					result = c.execute( "select d.addr from data d where d.value = ? and d.addr = ? and d.takt >= ? order by 1 limit 1", (byte,addr,takt) ).fetchone()
					if result:
						addr = result[0]
						addrs.append(addr)
					else:
						return
				return addrs
		
		addrs = ascii_string(bytes)
		if addrs:
			return str( addrs[0] )
		else:
			return str()

class Code:
	@app.route('/code/<int:addr>')
	def code_goto(addr):
		results = []
		lines = int( request.args.get("lines") or 10 )
		eips = [ x for x, in c.execute( "select eip from (select c.eip from code c where c.eip >= ? group by 1 order by 1 limit ?)", ( addr, lines ) ).fetchall() ]
		max_eip = max(eips)
		#if min(eips) == addr:
		for eip, takt, thread_id, mnem, operands, opcode, access_type, addr, value in c.execute( "select c.eip, t.takt, t.thread_id, c.mnem, c.operands, c.opcode, d.access_type, d.addr, d.value from code c left outer join data d on c.takt=d.takt inner join takts t on c.takt=t.takt where c.eip > ? and c.eip <= ? order by 1", ( addr, max_eip ) ):
			results.append( (eip, takt, thread_id, mnem, operands, opcode, access_type, addr, value) )
		return json.dumps(results)

	@app.route('/code/data/<addr>')
	def code_memory(addr):
		results = []
		for addr,val,op_type,eip in c.execute( "select m.addr,m.val,i.op_type,i.eip from memory m join instructions i on m.id = i.memory_id where i.eip = {ADDR};".format( ADDR=_int(addr) ) ):
			results.append( (addr, val, op_type, eip) )
		return json.dumps(results)

	@app.route('/code/search/<instruction>')
	def code_search(instruction):
		mnem = instruction.split(' ')[0]
		operands = ' '.join( instruction.split(' ')[1:] )
		if mnem and operands:
			print 2
			result = c.execute( "select c.eip from code c where c.mnem = ? and c.operands = ? order by 1 limit 1", (mnem,operands) ).fetchone()
		elif mnem:
			print 1
			result = c.execute( "select c.eip from code c where c.mnem = ? order by 1 limit 1", (mnem,) ).fetchone()
		elif operands:
			print 0
			result = c.execute( "select c.eip from code c where c.operands = ? order by 1 limit 1", (operands,) ).fetchone()
		if result:
			eip = result[0]
			return str( eip )
		else:
			return str()

	@app.route('/code/threads')
	def code_threads():
		results = []
		for thread_id,_ in c.execute( "select t.thread_id,1 from takts t group by t.thread_id" ):
			results.append(thread_id)
		return json.dumps( results )

	@app.route('/code/eips/<int:thread_id>')
	def code_eips(thread_id):
		min_eip = int( request.args.get("min_eip") or 0 )
		max_eip = int( request.args.get("max_eip") or 0 )
		min_takt = int( request.args.get("min_takt") or 0 )
		max_takt = int( request.args.get("max_takt") or 0 )
		results = []
		for eip,takt in c.execute( "select c.eip,t.takt from code c inner join takts t on c.takt=t.takt where t.thread_id=? and c.eip > ? and c.eip < ? and t.takt > ? and t.takt < ?", (thread_id, min_eip, max_eip, min_takt, max_takt) ):
			results.append( (eip, takt) )
		return json.dumps(results)

	@app.route('/code/exec/<int:min_eip>/<int:max_eip>')
	def code_exec(min_eip, max_eip):
		results = []
		for eip,count in c.execute( "select eip, count(eip) from code c where c.eip >= ? and c.eip <= ? group by eip", (min_eip, max_eip) ):
			results.append( (eip,count) )
		return json.dumps(results)

	@app.route('/code/eips/min')
	def code_eips_min():
		min_eip,_ = c.execute("select min(c.eip),1 from code c").fetchone()
		return str(min_eip)

	@app.route('/code/eips/max')
	def code_eips_max():
		max_eip,_ = c.execute("select max(c.eip),1 from code c").fetchone()
		return str(max_eip)

	@app.route('/code/takts/min')
	def code_takt_min():
		min_takt,_ = c.execute("select min(t.takt),1 from takts t").fetchone()
		return str(min_takt)

	@app.route('/code/takts/max')
	def code_takt_max():
		max_takt,_ = c.execute("select max(t.takt),1 from takts t").fetchone()
		return str(max_takt)

	@app.route('/code/pages/')
	def code_pages():
		min_eip = int( request.args.get("min_eip") or 0 )
		max_eip = int( request.args.get("max_eip") or 0 )
		results = []
		if max_eip:
			for name, low_addr, high_addr in c.execute( "select name, low_addr, high_addr from pages where perm_x = 1 and high_addr >= ? and low_addr <= ? order by low_addr", (min_eip, max_eip) ):
				results.append( (name, low_addr, high_addr) )
		else:
			for name, low_addr, high_addr in c.execute( "select name, low_addr, high_addr from pages where perm_x = 1 order by low_addr" ):
				results.append( (name, low_addr, high_addr) )
		return json.dumps(results)


class Exec:
	@app.route('/exec/<int:takt>')
	def exec_takts(takt):
		results = []
		lines = int( request.args.get("lines") or 10 ) / 2
		min_takt,_ = c.execute( "select min(takt),1 from (select t.takt from takts t where takt < ? order by takt desc limit ?)", (takt,lines) ).fetchone()
		max_takt,_ = c.execute( "select max(takt),1 from (select t.takt from takts t where takt >= ? order by takt asc limit ?)", (takt,lines) ).fetchone()
		for takt,thread_id, eip,opcode,mnem,operands, eax,ecx,edx,ebx,esp,ebp,esi,edi, addr,value,access_type in c.execute("select t.takt, t.thread_id, c.eip, c.opcode, c.mnem, c.operands, t.eax, t.ecx, t.edx, t.ebx, t.esp, t.ebp, t.esi, t.edi, d.addr,d.value,d.access_type from takts t join code c on t.takt = c.takt left outer join data d on c.takt=d.takt where t.takt >= ? and t.takt <= ? order by t.takt", (min_takt,max_takt) ):
			results.append( (takt,thread_id, eip,opcode,mnem,operands, eax,ecx,edx,ebx,esp,ebp,esi,edi, addr,value,access_type) )
		return json.dumps(results)

	@app.route('/exec/search/<regs>')
	def exec_search(eip):
		results = []
		return json.dumps(results)



if __name__ == '__main__':
	app.debug = True
	app.run()