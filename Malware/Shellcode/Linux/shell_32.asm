; execve("/bin//sh");
; args for syscalls are on registers ebx, ecx, edx

global _start

section .text
_start:

	; set syscall number
	xor eax, eax

	; set arg0 filename
	push eax
	push 0x68732f2f
	push 0x6e69622f
	mov ebx, esp

	; set arg1, & arg2
	xor ecx, ecx
	xor edx, edx

	; syscall
	add eax, 0xb
	int 0x80
