section .bss
	name : resb 60

section .data
	;len equ $ - name
	greet db "Hello "
	len_greet equ $ - greet
	ask db "Enter Your name :"
	len_ask equ $ - ask
	
	


	
section .text
	global _start:
	global strcmp:
	global strlen:

strcmp:
	push rbp
	mov rbp, rsp
	mov [rbp-0x8], rdi
	mov [rbp-0x10], rsi
	
	mov ecx, 0
	lea rax, [rbp-0x8]
	lea rbx, [rbp-0x10]
	
	mov al, WORD [rax]
	mov bl, WORD [rbx]
	
	
	

	mov rsp, rbp
	pop rbp


_start:
	;ask
	mov rax, 1
	mov rdi, 1
	mov rsi, ask
	mov rdx, len_ask
	syscall
	; get name
	mov rax, 0
	mov rdi, 0
	mov rsi, name
	mov rdx, 60
	syscall

	mov rax, 1
	mov rdi, 1
	mov rsi, greet
	mov rdx, len_greet
	syscall

	mov rax, 1
	mov rdi, 1
	mov rsi, name
	mov rdx, 7
	syscall

	; exti
	mov rax, 60
	mov rdi, 0
	syscall
