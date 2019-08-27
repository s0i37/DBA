- Dumping all physical memory:

`qemu -panda memsavep,file=memory.dmp`

- Getting address spaces info:

`qemu -panda asidstory`

or

`vol -f memory.dmp psscan`

- Extracting all executable modules:

`vol -f memory.dmp dlldump -p 1234 -D modules/`

- Analyzing symbols:

```
./anal/symbols.py /path/to/modules/

./anal/symbols.py /path/to/module
```

or into radare2:

```
radare2 module
>aaa
>#!pipe bash
>./anal/symbols.py
```

- Extract full trace of something process:

```qemu -panda trace:cr3=$((0x12340000)),out=trace.txt```

- Simple getting all executed instructions:

```grep '{' trace.txt```

all reads:

```grep '->' trace.txt```

and all writes:

```grep '<-' trace.txt```

- Execution visualization:

```
./map.py trace.txt

./map.py trace.txt symbols.csv

./map.py -modules somemodule.exe trace.txt symbols.csv

./map.py -from_addr=$((0xFROM)) -to_addr=$((0xTO)) -from_takt=1000 -to_takt=1000000 trace.txt

feh out.png
```

- Executed functions statistics:

```
./calls.py trace.txt

./calls.py trace.txt symbols.csv
```

- Calls tree:

```
./tree.py trace.txt

./tree.py trace.txt symbols.csv
```

- Taint:

```
./taint.py -taint_addr 95071:0xffc54324:4 tests/trace.txt       # taint 4 bytes in 0xffc54324 from 95071 takt

./taint.py -taint_data testtest trace.txt                       # search and taint 'testtest' buffer
```

- Audit:

```
./audit.py trace.txt        # implemented: umr_heap, uwc, uaf, oob_read_heap, oob_write_heap, doublefree
```

- Prototypes:

TODO

- Qira:

TODO
