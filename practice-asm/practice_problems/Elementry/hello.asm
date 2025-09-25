section .data
	msg db "Hello World", 0xa
	len equ $ - msg

section .text
	
	mov rax, 1
	mov rdi, 1
	mov rsi, msg
	mov rdx, len
	syscall

	; exit
	mov rax, 60
	mov rdi, 0
	syscall


