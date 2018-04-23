#!/bin/bash
for dll in *.dll
do
	radare2 -qc 'aa;#!pipe /root/src/trace_analyse/anal/fcn_bounds.py' $dll
done
