# Solutions for Attack-Lab.


## Get Ready

### Disassemble Targets

~~~
objdump -d ctarget > dumps/ctarget.txt
~~~

~~~
objdump -d rtarget > dump/rtarget.txt
~~~

### Compile and Disassemble farm.c

~~~
gcc -c farm.c -Og
~~~

~~~
objdump -d farm.o > dumps/farm.txt
~~~


## Solve: ctarget

`ctarget` has some code-injection vulnerabilities.

It consists of three phases: touch1, touch2 and touch2.

We need to call them with right parameters by replacing return address stored in stack.

# Touch1



## Solve: rtarget

`rtarget` has some return-oriented-programming vulnerabilities.
