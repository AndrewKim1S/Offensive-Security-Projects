#!/usr/bin/env python3

from pwn import *

elf = ELF("./re-alloc_patched")

#p = gdb.debug('./death_note', gdbscript='''
#	b main
#	continue
#''')
#p = process('./death_note')
#p = remote('chall.pwnable.tw', 10201)

