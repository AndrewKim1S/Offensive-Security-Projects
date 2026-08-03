#!/usr/bin/env python3

from pwn import *

exe = ELF("seethefile_patched")
libc = ELF("libc.so.6")
ld = ELF("./ld-2.23.so")


