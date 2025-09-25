section .bss
	num : resd 1

section .data
	even db "Even", 0xA
	even_len equ $ - even
	odd db "Odd", 0xA
	odd_len equ $ - odd
	x db "Enter Number : "
	x_len equ $ - x	

section .text
	global _start, odd_or_even
	
odd_or_even:
	push rbp
	mov rbp, rsp
	sub rsp, 0x8
	mov [rbp-0x4], rdi
	
	mov rax, [rbp-0x4]
	mov edx, 0
	mov ecx, 2
	div ecx
	;
	mov eax, 0  
	cmp edx, eax
	je .even 
.odd:
	mov rax, 0
	jmp .odd
.even:
	mov rax, 1
.done:
	pop rbp
	ret

	
_start:
	; print out
	mov rax, 1
	mov rdi, 1
	mov rsi, x
	mov rdx, x_len
	syscall

	; get number
	mov rax, 0
	mov rdi, 0
	mov rsi, num
	mov rdx, 4
	syscall
	
	; check if is even or odd
	mov rax, [num]
	mov rdi, rax
	call odd_or_even
	
	mov rbx, 0
	cmp rax, rbx
	je .is_odd
.is_even:
	mov rax, 1
	mov rdi, 1
	mov rsi, even
	mov rdx, even_len
	syscall
	jmp _start

.is_odd:
	mov rax, 0
	mov rdi, 0
	mov rsi, odd
	mov rdx, odd_len
	syscall

	jmp _start
	
	
	
