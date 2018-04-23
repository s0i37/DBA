qemu -panda asidstory

qemu -panda memsavep,file=memory.dmp
vol -f memory.dmp dlldump -p 1234 -D .
./anal/create_symbols_db.sh

qemu -panda memtrace,cr3=0x1234,out=trace.txt