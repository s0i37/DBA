#!/usr/bin/python
from lib.emulate import Trace, StopExecution
from lib.sanitizers import MemoryLeak, UMR_stack, UAR, OOB_read_stack, OOB_read_heap, OOB_write_heap, UAF, DoubleFree, UMR_heap, UMR_stack, UWC, Exceptions, SoF
import sys

MALLOC = 0xf770f880
FREE = 0xf770f900

'''
TODO:
	malloc(arg0)/HeapAlloc(arg2)
	x86/x64
'''

memoryleak = MemoryLeak(malloc_ptr=MALLOC, free_ptr=FREE)
oob_read_heap = OOB_read_heap(malloc_ptr=MALLOC, free_ptr=FREE)
oob_write_heap = OOB_write_heap(malloc_ptr=MALLOC, free_ptr=FREE)
uaf = UAF(malloc_ptr=MALLOC, free_ptr=FREE)
doublefree = DoubleFree(malloc_ptr=MALLOC, free_ptr=FREE)
umr_heap = UMR_heap(malloc_ptr=MALLOC, free_ptr=FREE)
uwc = UWC(malloc_ptr=MALLOC, free_ptr=FREE)

#sanitizers_work = [ UAR() ]
sanitizers_impl = [ umr_heap, uwc, uaf, oob_read_heap, oob_write_heap, doublefree, SoF() ]
#sanitizers_heap = [ oob_read_heap, oob_write_heap, uaf, doublefree, umr_heap, uwc ]
#sanitizers_bad = [ UMR_stack(), OOB_read_stack(), Exceptions() ]
#sanitizers_not_impl = [ MemoryLeak(), OOB_write_stack(), IoF() ]
trace_file = sys.argv[1]

with Trace( open(trace_file) ) as trace:
	trace.breakpoints.add(MALLOC)
	while True:
		try:
			result = trace.execute()
			if result:
				(used_registers, used_memory) = result
				for sanitizer in sanitizers_impl:
					sanitizer(trace.cpu, used_registers, used_memory)
		except StopExecution:
			break

# Exceptions - cmp dword ptr gs:[0xc], 0