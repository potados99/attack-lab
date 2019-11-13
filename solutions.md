# Solutions for Attack-Lab.


## Get Ready

### Disassemble Targets

`objdump -d ctarget > dumps/ctarget.txt`

`objdump -d rtarget > dump/rtarget.txt`

### Compile and Disassemble farm.c

`gcc -c farm.c -Og`

`objdump -d farm.o > dumps/farm.txt`
