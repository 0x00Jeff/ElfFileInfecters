section .text
	global _start

_start:
	pushad
	xor eax, eax
	add al, 4
	xor ebx, ebx
	mov edx, esp
	push ebx
	push 0x0a206962
	push 0x6f6e656b
	push 0x206c6172
	push 0x656e6567
	mov ecx, esp
	sub edx, esp ; calculating the length of the string
	inc ebx
	int 0x80

	add esp, edx ; stack cleaning 
	popad
	push 0x69696969
	ret
