section .bss
	len : resd 1

section .data
	name db "Nkateko"

section .text
	global _start

strlen:
	; get the ptr
	push rbp 
	mov rbp, rsp
	;mov rax, 0x8
	sub rsp, 0x8
	mov [rbp-0x8], rdi


	; count the string
.start:
	mov rax, 0
	mov rcx, rax
	;mov rax, [rbp-0x8]
	load rax, rbp-0x8
	add rax, rcx
	mov rdx, [rax]
	mov rbx, 0x00
	cmp rdx, rbx
	je .done
	add rcx, 1 
	jmp .start
.done:
	mov rax, rcx
	pop rbp
	ret

_start:
	mov rdi, [name]
	call strlen

	mov [len], rax

	; print
	mov rax, 1
	mov rdi, 1
	mov rsi, [len]
	mov rdx, 4	
	syscall

	; exit
	mov rax, 60
	mov rdi, 1
	syscall


	