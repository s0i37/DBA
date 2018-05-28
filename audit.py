from sanlib.emulate import execute
from sanlib.sanitizers import MemoryLeak, UMR_stack, UAR, OOB_read_stack, OOB_read_heap, OOB_write_heap, UAF, DoubleFree, UMR_heap, UMR_stack, UWC, Exceptions, SoF
import sys

MALLOC = 0x080483a0
FREE = 0x08048380

memoryleak = MemoryLeak(malloc_ptr=MALLOC, free_ptr=FREE)
oob_read_heap = OOB_read_heap(malloc_ptr=MALLOC, free_ptr=FREE)
oob_write_heap = OOB_write_heap(malloc_ptr=MALLOC, free_ptr=FREE)
uaf = UAF(malloc_ptr=MALLOC, free_ptr=FREE)
doublefree = DoubleFree(malloc_ptr=MALLOC, free_ptr=FREE)
urm_heap = UMR_heap(malloc_ptr=MALLOC, free_ptr=FREE)
uwc = UWC(malloc_ptr=MALLOC, free_ptr=FREE)

#sanitizers = [ UAR(), oob_read_heap, oob_write_heap, uaf, doublefree, urm_heap, uwc, Exceptions(), SoF() ]
sanitizers = [ memoryleak ]
#sanitizers_bad = [UMR_stack(), OOB_read_stack()]
#sanitizers_not_impl = [MemoryLeak(), OOB_write_stack()]
trace_file = sys.argv[1]

with open(trace_file) as trace:
	for line in trace:
		result = execute(line)
		if result:
			for sanitizer in sanitizers:
				sanitizer(*result)