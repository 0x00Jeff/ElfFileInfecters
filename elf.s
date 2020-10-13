section .text
	global _start

_start:
	pushad ; saving all general purpose registers so we can restore them later, failing to do so will cause the original executable to crash
	xor eax, eax
	xor ebx, ebx
	mov edx, esp
	push eax
	push 0x0a206962
	push 0x6f6e656b
	push 0x206c6172
	push 0x656e6567
	mov ecx, esp
	sub edx, esp ; calculating the length of the string
	add al, 4
	inc ebx
	int 0x80

	add esp, edx ; stack cleaning 
	popad ; restoring the general purpose registers
	push 0x69696969
	ret
