import colorama

__version__ = '0.12'

class SEVERITY:
	HIGH = colorama.Back.RED
	MIDDLE = colorama.Back.YELLOW

def report(error_class, cpu, severity, info=''):
	print "\n" + severity + "[+] " + error_class.__name__ + " %d:0x%08x: %s" % (cpu.takt, cpu.eip_before, cpu.disas()),
	if info:
		print "; " + info
	print colorama.Back.RESET


class MemoryLeak():
	"""removing pointers after use, dont free"""
	good = False
	def __init__(self, malloc_ptr, free_ptr):
		self.malloc_ptr = malloc_ptr
		self.free_ptr = free_ptr
		self._in_malloc = False
		self._in_free = False
		self.tainted_regs = {}
		self.tainted_mems = {}
		self.is_taint = False

	def __call__(self, cpu, used_registers, used_memory):
		if cpu.exception:
			return

		if cpu.eip_after == self.malloc_ptr:
			self._in_malloc = True
			self._malloc_size = cpu.cache.get_dword(cpu.esp_before)
			self._ret_addr = cpu.cache.get_dword(cpu.esp_after)
		elif cpu.eip_after == self.free_ptr:
			self._in_free = True
			heap_addr = cpu.cache.get_dword(cpu.esp_before)
			self._ret_addr = cpu.cache.get_dword(cpu.esp_after)
			self.tainted_regs[cpu.thread_id] = []
			self.tainted_mems[cpu.thread_id] = []
			self.is_taint = False

		if self._in_malloc and cpu.eip_before == self._ret_addr:
			self._in_malloc = False
			self.tainted_regs[cpu.thread_id] = ['eax']
			self.tainted_mems[cpu.thread_id] = []
			self.is_taint = True
		elif self._in_free and cpu.eip_before == self._ret_addr:
			self._in_free = False
	

		used_regs_r, used_regs_w = used_registers
		used_mems_r, used_mems_w = used_memory

		if self.is_taint:
			is_spread = False
			#print cpu.disas()
			#print used_registers
			for used_reg in used_regs_r:
				used_reg = cpu.get_full_register(used_reg)
				if used_reg and used_reg in self.tainted_regs[cpu.thread_id]:
					is_spread = True
					print colorama.Fore.GREEN + "\n[+] use tainted register: %s" % (used_reg,) + colorama.Fore.RESET,

			for used_memory_cell in used_mems_r:
				if used_memory_cell in self.tainted_mems[cpu.thread_id]:
					is_spread = True
					print colorama.Fore.GREEN + "\n[+] use tainted memory: 0x%08x" % (used_memory_cell,) + colorama.Fore.RESET,

			if is_spread:
				print 'spread'
				for used_reg in used_regs_w:
					used_reg = cpu.get_full_register(used_reg)
					if not used_reg in self.tainted_regs[cpu.thread_id]:
						print colorama.Fore.GREEN + "\n[+] taint register %s" % (used_reg,) + colorama.Fore.RESET,
						self.tainted_regs[cpu.thread_id].add(used_reg)
				for used_memory_cell in used_mems_w:
					print colorama.Fore.GREEN + "\n[+] taint memory 0x%08x" % (used_memory_cell,) + colorama.Fore.RESET,
					if not used_memory_cell in self.tainted_mems[cpu.thread_id]:
						self.tainted_mems[cpu.thread_id].add(used_memory_cell)
			else:
				for used_reg in used_regs_w:
					used_reg = cpu.get_full_register(used_reg)
					if used_reg in self.tainted_regs[cpu.thread_id]:
						self.tainted_regs[cpu.thread_id].remove(used_reg)
				for used_memory_cell in used_mems_w:
					#print colorama.Fore.RED + "\n[-] free memory 0x%08x" % (used_memory_cell,) + colorama.Fore.RESET,
					if used_memory_cell in self.tainted_mems[cpu.thread_id]:
						self.tainted_mems[cpu.thread_id].remove(used_memory_cell)


			if not self.tainted_regs[cpu.thread_id] and not self.tainted_mems[cpu.thread_id]:
				report(self.__class__, cpu, SEVERITY.MIDDLE)
				self.is_taint = False

class UWC():
	"""UWC - Use Without Check from heap"""
	need_malloc = True
	good = True
	slow = True
	def __init__(self, malloc_ptr, free_ptr):
		self.malloc_ptr = malloc_ptr
		self.free_ptr = free_ptr
		self.heap = []
		self._in_malloc = False
		self._in_free = False
		self._malloc_size = 0

	def __call__(self, cpu, used_registers, used_memory):
		if cpu.eip_before == cpu.eip_after: # error emulation
			return

		if cpu.eip_after == self.malloc_ptr:
			self._in_malloc = True
			self._malloc_size = cpu.cache.get_dword(cpu.esp_before)
			self._ret_addr = cpu.cache.get_dword(cpu.esp_after)
		elif cpu.eip_after == self.free_ptr:
			self._in_free = True
			heap_addr = cpu.cache.get_dword(cpu.esp_before)
			self._ret_addr = cpu.cache.get_dword(cpu.esp_after)
			for heap in self.heap:
				if heap_addr in heap['range']:
					self.heap.remove(heap)

		if self._in_malloc and cpu.eip_before == self._ret_addr:
			self._in_malloc = False
			is_new_heap = True
			for heap in self.heap:
				if cpu.eax_before == heap['range'][0]:
					heap['is_checked'] = False
					is_new_heap = False
			if is_new_heap:
				self.heap.append( {'range': range(cpu.eax_before, cpu.eax_before + self._malloc_size), 'is_checked': False} )

		elif self._in_free and cpu.eip_before == self._ret_addr:
			self._in_free = False

		(used_registers_read, used_registers_write) = used_registers
		(used_memory_read, used_memory_write) = used_memory
		if cpu.disas().find('test') != -1 or cpu.disas().find('cmp') != -1:
			for heap in self.heap:
				for register_read in used_registers_read:
					if cpu.get(register_read) in heap['range']:
						heap['is_checked'] = True
				for memory in used_memory_read:
					if cpu.cache.get(memory) in heap['range']:
						heap['is_checked'] = True

		for memory in list(used_memory_read) + list(used_memory_write):
			for heap in self.heap:
				if memory in heap['range'] and not heap['is_checked']:
					report(self.__class__, cpu, SEVERITY.MIDDLE)

class UMR_stack():
	"""UMR - Uninitialized Memory Read in stack"""
	good = False
	def __init__(self):
		self.stack_initialized = set()

	def __call__(self, cpu, used_registers, used_memory):
		if cpu.disas().find('call') != -1:
			for addr in list(self.stack_initialized):
				if addr < cpu.esp_after:	# dead scope of function
					self.stack_initialized.remove(addr)

		(used_memory_read, used_memory_write) = used_memory
		for memory in used_memory_read:
			if (cpu.esp_before & 0xffff0000) <= memory <= (cpu.esp_before | 0xffff): # if in stack region
				if not memory in self.stack_initialized:
					report(self.__class__, cpu, SEVERITY.MIDDLE)
					break # once report, not for every memory cell

		for memory in used_memory_write:
			if (cpu.esp_before & 0xffff0000) <= memory <= (cpu.esp_before | 0xffff):
				self.stack_initialized.add(memory)
				
class UMR_heap():
	"""UMR - Uninitialized Memory Read in heap"""
	need_malloc = True
	good = True
	slow = True
	def __init__(self, malloc_ptr, free_ptr):
		self.malloc_ptr = malloc_ptr
		self.free_ptr = free_ptr
		self.heap = []
		self.heap_uninitialized = []
		self._in_malloc = False
		self._in_free = False
		self._malloc_size = 0

	def __call__(self, cpu, used_registers, used_memory):
		if cpu.eip_before == cpu.eip_after: # error emulation
			return

		if cpu.eip_after == self.malloc_ptr:
			self._in_malloc = True
			self._malloc_size = cpu.cache.get_dword(cpu.esp_before)
			self._ret_addr = cpu.cache.get_dword(cpu.esp_after)
		elif cpu.eip_after == self.free_ptr:
			self._in_free = True
			heap_addr = cpu.cache.get_dword(cpu.esp_before)
			self._ret_addr = cpu.cache.get_dword(cpu.esp_after)
			for heap in list(self.heap):
				if heap_addr in heap:
					for addr in heap:
						if addr in self.heap_uninitialized:
							self.heap_uninitialized.remove(addr)
				self.heap.remove(heap)

		if self._in_malloc and cpu.eip_before == self._ret_addr:
			self._in_malloc = False
			is_new_heap = True
			for heap in self.heap:
				if cpu.eax_before == heap[0]:
					is_new_heap = False
			if is_new_heap:
				self.heap.append( range(cpu.eax_before, cpu.eax_before + self._malloc_size) )
				self.heap_uninitialized.extend( range(cpu.eax_before, cpu.eax_before + self._malloc_size) )

		elif self._in_free and cpu.eip_before == self._ret_addr:
			self._in_free = False

		(used_memory_read, used_memory_write) = used_memory
		for memory in used_memory_write:
			if memory in self.heap_uninitialized:
				self.heap_uninitialized.remove(memory)

		for memory in used_memory_read:
			if memory in self.heap_uninitialized:
				report(self.__class__, cpu, SEVERITY.MIDDLE)


class DoubleFree():
	need_malloc = True
	not_verified = True
	def __init__(self, malloc_ptr, free_ptr):
		self.malloc_ptr = malloc_ptr
		self.free_ptr = free_ptr
		self.heap = []
		self._in_malloc = False
		self._in_free = False
		self._malloc_size = 0

	def __call__(self, cpu, used_registers, used_memory):
		if cpu.eip_before == cpu.eip_after: # error emulation
			return

		if cpu.eip_after == self.malloc_ptr:
			self._in_malloc = True
			self._malloc_size = cpu.cache.get_dword(cpu.esp_before)
			self._ret_addr = cpu.cache.get_dword(cpu.esp_after)
		elif cpu.eip_after == self.free_ptr:
			self._in_free = True
			heap_addr = cpu.cache.get_dword(cpu.esp_before)
			self._ret_addr = cpu.cache.get_dword(cpu.esp_after)
			for heap in self.heap:
				if heap_addr in heap['range']:
					if heap['is_free']:
						report(self.__class__, cpu, SEVERITY.MIDDLE)
					else:
						heap['is_free'] = True

		if self._in_malloc and cpu.eip_before == self._ret_addr:
			self._in_malloc = False
			is_new_heap = True
			for heap in self.heap:
				if cpu.eax_before == heap['range'][0]:
					heap['is_free'] = False
					is_new_heap = False
			if is_new_heap:
				self.heap.append( {'range': range(cpu.eax_before, cpu.eax_before + self._malloc_size), 'is_free': False} )

		elif self._in_free and cpu.eip_before == self._ret_addr:
			self._in_free = False


class UAF():
	"""dangling pointer"""
	need_malloc = True
	good = True
	slow = True
	def __init__(self, malloc_ptr, free_ptr):
		self.malloc_ptr = malloc_ptr
		self.free_ptr = free_ptr
		self.heap = []
		self._in_malloc = False
		self._in_free = False
		self._malloc_size = 0

	def __call__(self, cpu, used_registers, used_memory):
		if cpu.eip_before == cpu.eip_after: # error emulation
			return

		if cpu.eip_after == self.malloc_ptr:
			self._in_malloc = True
			self._malloc_size = cpu.cache.get_dword(cpu.esp_before)
			self._ret_addr = cpu.cache.get_dword(cpu.esp_after)
		elif cpu.eip_after == self.free_ptr:
			self._in_free = True
			heap_addr = cpu.cache.get_dword(cpu.esp_before)
			self._ret_addr = cpu.cache.get_dword(cpu.esp_after)
			for heap in self.heap:
				if heap_addr in heap['range']:
					heap['is_free'] = True

		if self._in_malloc and cpu.eip_before == self._ret_addr:
			self._in_malloc = False
			is_new_heap = True
			for heap in self.heap:
				if cpu.eax_before == heap['range'][0]:
					heap['is_free'] = False
					is_new_heap = False
			if is_new_heap:
				self.heap.append( {'range': range(cpu.eax_before, cpu.eax_before + self._malloc_size), 'is_free': False} )

		elif self._in_free and cpu.eip_before == self._ret_addr:
			self._in_free = False

		(used_memory_read, used_memory_write) = used_memory
		for memory in list(used_memory_read) + list(used_memory_write):
			for heap in self.heap:
				if memory in heap['range'] and heap['is_free']:
					report(self.__class__, cpu, SEVERITY.HIGH)


class UAR():
	"""UAS/UAR - Use After Scope/Return"""
	good = True
	def __call__(self, cpu, used_registers, used_memory):
		(used_memory_read, used_memory_write) = used_memory
		for memory in list(used_memory_read) + list(used_memory_write):
			if (cpu.esp_before & 0xfffff000) <= memory <= (cpu.esp_before | 0xfff):
				if memory < cpu.esp_before-4:  # its not for every time true
					report(self.__class__, cpu, SEVERITY.MIDDLE)

class OOB_read_heap():
	"""OOB - Out Of Bounds read heap"""
	need_malloc = True
	good = True
	def __init__(self, malloc_ptr, free_ptr):
		self.malloc_ptr = malloc_ptr
		self.free_ptr = free_ptr
		self.heap_chunks = []
		self._in_malloc = False
		self._in_free = False
		self._malloc_size = 0

	def __call__(self, cpu, used_registers, used_memory):
		if cpu.eip_before == cpu.eip_after: # error emulation
			return

		if cpu.eip_after == self.malloc_ptr:
			self._in_malloc = True
			self._malloc_size = cpu.cache.get_dword(cpu.esp_before)
			self._ret_addr = cpu.cache.get_dword(cpu.esp_after)
		elif cpu.eip_after == self.free_ptr:
			self._in_free = True
			heap_up_chunk = cpu.cache.get_dword(cpu.esp_before) - 4
			self._ret_addr = cpu.cache.get_dword(cpu.esp_after)
			if heap_up_chunk in self.heap_chunks:
				heap_down_chunk = self.heap_chunks[ self.heap_chunks.index(heap_up_chunk) + 1 ]
				self.heap_chunks.remove(heap_down_chunk)
				self.heap_chunks.remove(heap_up_chunk)

		if self._in_malloc and cpu.eip_before == self._ret_addr:
			self._in_malloc = False
			self.heap_chunks.extend( [cpu.eax_before-4, cpu.eax_before+self._malloc_size+4] )
		elif self._in_free and cpu.eip_before == self._ret_addr:
			self._in_free = False

		(used_memory_read, used_memory_write) = used_memory
		for memory in used_memory_read:
			if memory in self.heap_chunks:
				report(self.__class__, cpu, SEVERITY.MIDDLE)

class OOB_write_heap():
	"""OOB - Out Of Bounds write heap"""
	need_malloc = True
	good = True
	def __init__(self, malloc_ptr, free_ptr):
		self.malloc_ptr = malloc_ptr
		self.free_ptr = free_ptr
		self.heap_chunks = []
		self._in_malloc = False
		self._in_free = False
		self._malloc_size = 0

	def __call__(self, cpu, used_registers, used_memory):
		if cpu.eip_before == cpu.eip_after: # error emulation
			return

		if cpu.eip_after == self.malloc_ptr:
			self._in_malloc = True
			self._malloc_size = cpu.cache.get_dword(cpu.esp_before)
			self._ret_addr = cpu.cache.get_dword(cpu.esp_after)
		elif cpu.eip_after == self.free_ptr:
			self._in_free = True
			heap_up_chunk = cpu.cache.get_dword(cpu.esp_before) - 4
			self._ret_addr = cpu.cache.get_dword(cpu.esp_after)
			if heap_up_chunk in self.heap_chunks:
				heap_down_chunk = self.heap_chunks[ self.heap_chunks.index(heap_up_chunk) + 1 ]
				self.heap_chunks.remove(heap_down_chunk)
				self.heap_chunks.remove(heap_up_chunk)

		if self._in_malloc and cpu.eip_before == self._ret_addr:
			self._in_malloc = False
			self.heap_chunks.extend( [cpu.eax_before-4, cpu.eax_before+self._malloc_size+4] )
		elif self._in_free and cpu.eip_before == self._ret_addr:
			self._in_free = False

		(used_memory_read, used_memory_write) = used_memory
		for memory in used_memory_write:
			if memory in self.heap_chunks:
				report(self.__class__, cpu, SEVERITY.HIGH)

class OOB_read_stack():
	"""OOB - Out Of Bounds read stack"""
	good = False # Has many falsepositives in libc
	def __init__(self):
		self.stack_frame = {}
		self.vars = {}
		self.var_access = {}
		self.deep = 0

	def __call__(self, cpu, used_registers, used_memory):
		"""
		VSA - each instruction has own manipulate data type of local_vars.
		Each instruction works this your own local_var
		If some instruction read/write more than one local_var - its potential OOB
		"""

		if cpu.disas().find('call') != -1:
			self.deep += 1
			self.stack_frame[self.deep] = cpu.esp_after
			self.vars[self.deep] = {}
			self.var_access[self.deep] = {}
		elif cpu.disas().find('ret') != -1:
			if self.deep in self.stack_frame:
				del self.stack_frame[self.deep]
				del self.vars[self.deep]
				del self.var_access[self.deep]
			if self.deep > 0:
				self.deep -= 1

		if not self.deep in self.stack_frame:
			return

		(used_memory_read, used_memory_write) = used_memory
		for memory in used_memory_read:
			if (self.stack_frame[self.deep] & 0xffff0000) <= memory <= (self.stack_frame[self.deep] | 0xffff): # in stack
				try: self.vars[self.deep][memory].add(cpu.eip_before)
				except: self.vars[self.deep][memory] = set([cpu.eip_before])
				
				if not cpu.eip_before in self.var_access[self.deep]:
					self.var_access[self.deep][cpu.eip_before] = memory

				if memory != self.var_access[self.deep][cpu.eip_before] and len(self.vars[self.deep][memory]) > 1:
					report(self.__class__, cpu, SEVERITY.MIDDLE)
				break # only first byte


class OOB_write_stack():
	"""OOB - Out Of Bounds write stack"""
	good = False # Has many falsepositives in libc
	def __init__(self):
		self.stack_frame = {}
		self.vars = {}
		self.var_access = {}
		self.deep = 0

	def __call__(self, cpu, used_registers, used_memory):
		"""
		VSA - each instruction has own manipulate data type of local_vars.
		Each instruction works this your own local_var
		If some instruction read/write more than one local_var - its potential OOB
		"""

		if cpu.disas().find('call') != -1:
			self.deep += 1
			self.stack_frame[self.deep] = cpu.esp_after
			self.vars[self.deep] = {}
			self.var_access[self.deep] = {}
		elif cpu.disas().find('ret') != -1:
			if self.deep in self.stack_frame:
				del self.stack_frame[self.deep]
				del self.vars[self.deep]
				del self.var_access[self.deep]
			if self.deep > 0:
				self.deep -= 1

		if not self.deep in self.stack_frame:
			return

		(used_memory_read, used_memory_write) = used_memory
		for memory in used_memory_read:
			if (self.stack_frame[self.deep] & 0xffff0000) <= memory <= (self.stack_frame[self.deep] | 0xffff): # in stack
				try: self.vars[self.deep][memory].add(cpu.eip_before)
				except: self.vars[self.deep][memory] = set([cpu.eip_before])
				
				if not cpu.eip_before in self.var_access[self.deep]:
					self.var_access[self.deep][cpu.eip_before] = memory
				break

		for memory in used_memory_write:
			if (self.stack_frame[self.deep] & 0xffff0000) <= memory <= (self.stack_frame[self.deep] | 0xffff): # in stack
				try: self.vars[self.deep][memory].add(cpu.eip_before)
				except: self.vars[self.deep][memory] = set([cpu.eip_before])
				
				if not cpu.eip_before in self.var_access[self.deep]:
					self.var_access[self.deep][cpu.eip_before] = memory

				if memory != self.var_access[self.deep][cpu.eip_before] and len(self.vars[self.deep][memory]) > 1:
					report(self.__class__, cpu, SEVERITY.HIGH)
				break # only first byte

class HoF():
	"""HOF - Heap Overflow (useless)"""
	'''
	If malloc(<10 MB) -> 0
	'''
	need_malloc = True
	pass

class SoF():
	'''
	detect near SoF state
	If full stack deep >  x MB
	'''
	def __init__(self):
		self.has_moved_to_another_page = False
		self.next_ip = {}
		self.prev_ip = {}

	def __call__(self, cpu, used_registers, used_memory):
		if cpu.exception:
			if self.has_moved_to_another_page and cpu.eip_before != self.next_ip[cpu.thread_id]:
				report(self.__class__, cpu, SEVERITY.MIDDLE)
			
			if cpu.esp_before & 0xfffff000 != cpu.esp_after & 0xfffff000: # moving to another stack memory page
				self.prev_ip[cpu.thread_id] = (cpu.eip_before, cpu.disas())
				self.next_ip[cpu.thread_id] = cpu.eip_after
				self.has_moved_to_another_page = True
			else:
				self.has_moved_to_another_page = False
		else:
			self.prev_ip[cpu.thread_id] = None
			self.next_ip[cpu.thread_id] = None
			self.has_moved_to_another_page = False

class IoF():
	"""IOF - Integer overflow (UBSAN)"""
	'''
	If computed value (IR) != real value unicorn
	'''
	pass

class Race_condition():
	'''
	if two or more threads write the same memory (without WaitForSingleObjects)
	'''
	pass

class Format_string():
	'''
	impossible
	'''
	pass

class Exceptions():
	good = False
	def __init__(self):
		self.next_ip = {}
		self.prev_ip = {}

	def __call__(self, cpu, used_registers, used_memory):
		if cpu.exception:
			if not cpu.disas().split()[0] in ("jmp","call","ret"): # we dont provide EFLAGS through a trace, so cpu.eip_after will wrong predicted
				used = ''
				for reg in used_registers[0] & used_registers[1]:
					used += " %s=0x%08x," % ( reg, cpu.get( cpu.get_full_register(reg) ) )
				for mem_r in used_memory[0]:
					used += " 0x%08x -> 0x%08x," % ( mem_r, cpu.cache.get_dword(mem_r) )
				for mem_w in used_memory[1]:
					used += " 0x%08x -> 0x%08x," % ( mem_w, cpu.cache.get_dword(mem_w) )
				used += ' ' + cpu.exception
				report(self.__class__, cpu, SEVERITY.HIGH, info=used)
