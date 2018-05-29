qemu -panda asidstory

qemu -panda memsavep,file=memory.dmp

vol -f memory.dmp dlldump -p 1234 -D .

./anal/functions.py /path/to/dir/with/dlls/

qemu -panda trace:cr3=$((0x1234)),out=trace.txt
