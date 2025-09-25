section .bss
	num1 :resd 1
	num2 : resd 1
	sum : resd 1


section .data
	msg db "Enter Number : "
	len equ $ - msg
	
section .text

	global _start

_start:
	; print
	mov rax, 1
	mov rdi, 1
	mov rsi, msg
	mov rdx, len
	syscall

	; get num1
	mov rax, 0
	mov rdi, 0
	mov rsi, num1
	mov rdx, 4
	syscall
	
	mov rax, 1
	mov rdi, 1
	mov rsi, msg
	mov rdx, len
	syscall

	; get num2
	mov rax, 0
	mov rdi, 0
	mov rsi, num2
	mov rdx, 4
	
	; sum
	mov rax, [num1]
	add rax, [num2]
	mov [sum], rax

	; pring sum
	mov rax, 1
	mov rdi, 1
	mov rsi, sum
	mov rdx, 4
	syscall

	mov rax, 60
	mov rdi, 1
	syscall