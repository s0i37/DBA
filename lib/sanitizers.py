import colorama

__version__ = '0.10'

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
			self._malloc_size = cpu.cache[cpu.esp_before]
			self._ret_addr = cpu.cache[cpu.esp_after]
		elif cpu.eip_after == self.free_ptr:
			self._in_free = True
			heap_addr = cpu.cache[cpu.esp_before]
			self._ret_addr = cpu.cache[cpu.esp_after]
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
			#print cpu.instruction
			#print used_registers
			for used_reg in used_regs_r:
				used_reg = cpu.get_full_register(used_reg)
				if used_reg and used_reg in self.tainted_regs[cpu.thread_id]:
					is_spread = True
					print colorama.Fore.GREEN + "[+] use tainted register: %s" % (used_reg,) + colorama.Fore.RESET

			for used_memory_cell in used_mems_r:
				if used_memory_cell in self.tainted_mems[cpu.thread_id]:
					is_spread = True
					print colorama.Fore.GREEN + "[+] use tainted memory: 0x%08x" % (used_memory_cell,) + colorama.Fore.RESET

			if is_spread:
				print 'spread'
				for used_reg in used_regs_w:
					used_reg = cpu.get_full_register(used_reg)
					if not used_reg in self.tainted_regs[cpu.thread_id]:
						print colorama.Fore.GREEN + "[+] taint register %s" % (used_reg,) + colorama.Fore.RESET
						self.tainted_regs[cpu.thread_id].add(used_reg)
				for used_memory_cell in used_mems_w:
					print colorama.Fore.GREEN + "[+] taint memory 0x%08x" % (used_memory_cell,) + colorama.Fore.RESET
					if not used_memory_cell in self.tainted_mems[cpu.thread_id]:
						self.tainted_mems[cpu.thread_id].add(used_memory_cell)
			else:
				for used_reg in used_regs_w:
					used_reg = cpu.get_full_register(used_reg)
					if used_reg in self.tainted_regs[cpu.thread_id]:
						self.tainted_regs[cpu.thread_id].remove(used_reg)
				for used_memory_cell in used_mems_w:
					#print colorama.Fore.RED + "[-] free memory 0x%08x" % (used_memory_cell,) + colorama.Fore.RESET
					if used_memory_cell in self.tainted_mems[cpu.thread_id]:
						self.tainted_mems[cpu.thread_id].remove(used_memory_cell)


			if not self.tainted_regs[cpu.thread_id] and not self.tainted_mems[cpu.thread_id]:
				print colorama.Back.RED + self.__class__.__name__ + " 0x%08x: %s" % (cpu.eip_before, cpu.instruction) + colorama.Back.RESET
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
			self._malloc_size = cpu.cache[cpu.esp_before]
			self._ret_addr = cpu.cache[cpu.esp_after]
		elif cpu.eip_after == self.free_ptr:
			self._in_free = True
			heap_addr = cpu.cache[cpu.esp_before]
			self._ret_addr = cpu.cache[cpu.esp_after]
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
		if cpu.instruction.find('test') != -1 or cpu.instruction.find('cmp') != -1:
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
					print colorama.Back.RED + self.__class__.__name__ + " %d 0x%08x: %s" % (cpu.ins_count, cpu.eip_before, cpu.instruction) + colorama.Back.RESET

class UMR_stack():
	"""UMR - Uninitialized Memory Read in stack"""
	good = False
	def __init__(self):
		self.stack_initialized = set()

	def __call__(self, cpu, used_registers, used_memory):
		if cpu.instruction.find('call') != -1:
			for addr in list(self.stack_initialized):
				if addr < cpu.esp_after:	# dead scope of function
					self.stack_initialized.remove(addr)

		(used_memory_read, used_memory_write) = used_memory
		for memory in used_memory_read:
			if (cpu.esp_before & 0xfffff000) <= memory <= (cpu.esp_before | 0xfff):
				if not memory in self.stack_initialized:
					print colorama.Back.RED + self.__class__.__name__ + " 0x%08x: %s" % (cpu.eip_before, cpu.instruction) + colorama.Back.RESET

		for memory in used_memory_write:
			if (cpu.esp_before & 0xfffff000) <= memory <= (cpu.esp_before | 0xfff):
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
			self._malloc_size = cpu.cache[cpu.esp_before]
			self._ret_addr = cpu.cache[cpu.esp_after]
		elif cpu.eip_after == self.free_ptr:
			self._in_free = True
			heap_addr = cpu.cache[cpu.esp_before]
			self._ret_addr = cpu.cache[cpu.esp_after]
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
				print colorama.Back.RED + self.__class__.__name__ + " 0x%08x: %s" % (cpu.eip_before, cpu.instruction) + colorama.Back.RESET


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
			self._malloc_size = cpu.cache[cpu.esp_before]
			self._ret_addr = cpu.cache[cpu.esp_after]
		elif cpu.eip_after == self.free_ptr:
			self._in_free = True
			heap_addr = cpu.cache[cpu.esp_before]
			self._ret_addr = cpu.cache[cpu.esp_after]
			for heap in self.heap:
				if heap_addr in heap['range']:
					if heap['is_free']:
						print colorama.Back.RED + self.__class__.__name__ + " 0x%08x: %s" % (cpu.eip_before, cpu.instruction) + colorama.Back.RESET
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
			self._malloc_size = cpu.cache[cpu.esp_before]
			self._ret_addr = cpu.cache[cpu.esp_after]
		elif cpu.eip_after == self.free_ptr:
			self._in_free = True
			heap_addr = cpu.cache[cpu.esp_before]
			self._ret_addr = cpu.cache[cpu.esp_after]
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
					print colorama.Back.RED + self.__class__.__name__ + " 0x%08x: %s" % (cpu.eip_before, cpu.instruction) + colorama.Back.RESET


class UAR():
	"""UAS/UAR - Use After Scope/Return"""
	good = True
	def __call__(self, cpu, used_registers, used_memory):
		(used_memory_read, used_memory_write) = used_memory
		for memory in list(used_memory_read) + list(used_memory_write):
			if (cpu.esp_before & 0xfffff000) <= memory <= (cpu.esp_before | 0xfff):
				if memory < cpu.esp_before-4:  # its not for every time true
					print colorama.Back.RED + self.__class__.__name__ + " 0x%08x: %s" % (cpu.eip_before, cpu.instruction) + colorama.Back.RESET

class IoF():
	"""IOF - Integer overflow (UBSAN)"""
	pass

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
			self._malloc_size = cpu.cache[cpu.esp_before]
			self._ret_addr = cpu.cache[cpu.esp_after]
		elif cpu.eip_after == self.free_ptr:
			self._in_free = True
			heap_up_chunk = cpu.cache[cpu.esp_before] - 4
			self._ret_addr = cpu.cache[cpu.esp_after]
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
				print colorama.Back.RED + self.__class__.__name__ + " 0x%08x: %s" % (cpu.eip_before, cpu.instruction) + colorama.Back.RESET

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
			self._malloc_size = cpu.cache[cpu.esp_before]
			self._ret_addr = cpu.cache[cpu.esp_after]
		elif cpu.eip_after == self.free_ptr:
			self._in_free = True
			heap_up_chunk = cpu.cache[cpu.esp_before] - 4
			self._ret_addr = cpu.cache[cpu.esp_after]
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
				print colorama.Back.RED + self.__class__.__name__ + " 0x%08x: %s" % (cpu.eip_before, cpu.instruction) + colorama.Back.RESET

class OOB_read_stack():
	"""OOB - Out Of Bounds read stack"""
	good = False
	def __init__(self):
		self.stack_frame_chunks = {}
		self._is_new_function = False
		self._deep = 0

	def __call__(self, cpu, used_registers, used_memory):
		"""
		VSA - each instruction has own manipulate data type of local_vars.
		?If some instruction read/write more than one local_var - its potential OOB? (SBA only)
		"""
		return 
		if cpu.instruction.find('call') != -1:
			self._is_new_function = True
			self._deep += 1
		elif cpu.instruction.find('ret') != -1:
			self._is_new_function = False
			if self._deep in self.stack_frame_chunks.keys():
				del self.stack_frame_chunks[self._deep]
			if self._deep > 0:
				self._deep -= 1
		elif self._is_new_function and cpu.instruction.find('sub esp') != -1:
			self.stack_frame_chunks[self._deep] = (cpu.esp_before, cpu.ebp_before)

		(used_memory_read, used_memory_write) = used_memory
		for memory in used_memory_read:
			if (cpu.esp_before & 0xfffff000) <= memory <= (cpu.esp_before | 0xfff):
				if self._deep in self.stack_frame_chunks.keys() and memory in self.stack_frame_chunks[self._deep]:
					print colorama.Back.RED + self.__class__.__name__ + " 0x%08x: %s" % (cpu.eip_before, cpu.instruction) + colorama.Back.RESET


class OOB_write_stack():
	"""OOB - Out Of Bounds write stack"""
	pass

class HoF():
	"""HOF - Heap Overflow"""
	need_malloc = True
	pass

class SoF():
	def __init__(self):
		self.has_moved_to_another_page = False
		self.next_ip = {}
		self.prev_ip = {}

	def __call__(self, cpu, used_registers, used_memory):
		if cpu.exception:
			if self.has_moved_to_another_page and cpu.eip_before != self.next_ip[cpu.thread_id]:
				print colorama.Back.RED + self.__class__.__name__ + " 0x%08x: %s" % ( self.prev_ip[cpu.thread_id][0], self.prev_ip[cpu.thread_id][1] ) + colorama.Back.RESET
			
			if cpu.esp_before & 0xfffff000 != cpu.esp_after & 0xfffff000: # moving to another stack memory page
				self.prev_ip[cpu.thread_id] = (cpu.eip_before, cpu.instruction)
				self.next_ip[cpu.thread_id] = cpu.eip_after
				self.has_moved_to_another_page = True
			else:
				self.has_moved_to_another_page = False
		else:
			self.prev_ip[cpu.thread_id] = None
			self.next_ip[cpu.thread_id] = None
			self.has_moved_to_another_page = False

class Format_string():
	pass

class Exceptions():
	good = True
	def __init__(self):
		self.next_ip = {}
		self.prev_ip = {}

	def __call__(self, cpu, used_registers, used_memory):
		if cpu.exception:
			if self.next_ip.get(cpu.thread_id) and cpu.eip_before != self.next_ip[cpu.thread_id]:
				if not self.prev_ip[cpu.thread_id][2].startswith('j'): # we dont provide EFLAGS through a trace, so cpu.eip_after will wrong predicted
					print colorama.Back.RED + "[+] " + self.__class__.__name__ + " %d:0x%08x: %s ; %s" % ( self.prev_ip[cpu.thread_id][0], self.prev_ip[cpu.thread_id][1], self.prev_ip[cpu.thread_id][2], self.prev_ip[cpu.thread_id][3] ) + colorama.Back.RESET
			
			used = ''
			for reg in used_registers[0] ^ used_registers[1]:
				used += " %s=0x%08x," % ( reg, cpu.get( cpu.get_full_register(reg) ) )
			#for mem_r in used_memory[0]:
			#	used += " 0x%08x -> 0x%08x," % ( mem_r, cpu.cache.get_dword(mem_r) )
			#for mem_w in used_memory[1]:
			#	used += " 0x%08x -> 0x%08x," % ( mem_w, cpu.cache.get_dword(mem_w) )

			self.prev_ip[cpu.thread_id] = (cpu.takt, cpu.eip_before, cpu.instruction, used)
			self.next_ip[cpu.thread_id] = cpu.eip_after
		else:
			self.prev_ip[cpu.thread_id] = None
			self.next_ip[cpu.thread_id] = None