#!/usr/bin/env python3

from pwn import *

exe = ELF("tcache_tear_patched")
libc = ELF("libc.so.6")
ld = ELF("./ld-2.27.so")


