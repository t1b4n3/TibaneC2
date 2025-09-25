section .bss
	name : resb 60
	len : resb 4
section .data
	;len equ $ - name
	greet db "Hello "
	len_greet equ $ - greet
	ask db "Enter Your name :"
	len_ask equ $ - ask
	
section .text
	global _start:

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
	mov [len], rax

	mov rax, 1
	mov rdi, 1
	mov rsi, greet
	mov rdx, len_greet
	syscall

	mov rax, 1
	mov rdi, 1
	mov rsi, name
	mov rdx, len
	syscall

	; exti
	mov rax, 60
	mov rdi, 0
	syscall
