#!/bin/python3
from pwn import *

# Setup environment
context.binary = binary = ELF('./orw')
context.log_level = 'debug'

# Connect process
p = remote('chall.pwnable.tw', 10100)

p.recv()
p.interactive()
