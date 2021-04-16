section .text
	global _start
_start:
	push rdi
	push rdx


	xor edi, edi
	mov rdx, rsp

	mov rax, 0x0a2069626f6e656b
	push rax
	mov rax, 0x206c6172656e6567
	push rax

	xor eax, eax
	mov rsi, rsp
	sub rdx, rsp

	inc edi
	inc eax
	
	syscall

	sub rsp, 16

	pop rdx
	pop rdi

	mov rax, 0x6969696969696969
	push rax
	ret
