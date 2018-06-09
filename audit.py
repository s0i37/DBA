#!/usr/bin/python
from lib.emulate import execute
from lib.sanitizers import MemoryLeak, UMR_stack, UAR, OOB_read_stack, OOB_read_heap, OOB_write_heap, UAF, DoubleFree, UMR_heap, UMR_stack, UWC, Exceptions, SoF
import sys

MALLOC = 0x00403f94
FREE = 0x56580490

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
urm_heap = UMR_heap(malloc_ptr=MALLOC, free_ptr=FREE)
uwc = UWC(malloc_ptr=MALLOC, free_ptr=FREE)

sanitizers = [ Exceptions() ]
#sanitizers_impl = [ UAR(), oob_read_heap, oob_write_heap, uaf, doublefree, urm_heap, uwc, Exceptions(), SoF() ]
#sanitizers_non_heap = [ UAR(), SoF() ]
#sanitizers_heap = [ oob_read_heap, oob_write_heap, uaf, doublefree, urm_heap, uwc ]
#sanitizers_not_impl = [ memoryleak ]
#sanitizers_bad = [ UMR_stack(), OOB_read_stack(), Exceptions() ]
#sanitizers_not_impl = [ MemoryLeak(), OOB_write_stack() ]
trace_file = sys.argv[1]

with open(trace_file) as trace:
	trace.seek(0,2)
	eof = trace.tell()
	trace.seek(0)
	while True:
		try:
			result = execute(trace)
			if not result:	
				for sanitizer in sanitizers:
					sanitizer(*result)
		except Exceptions as e:
			print str(e)
		
		if trace.tell() == eof:
			break