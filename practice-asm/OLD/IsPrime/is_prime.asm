; Create a function that will tell if a number is a prime or not


section .text
	global _start isPrime

isPrime:
	push rbp
	mov rbp, rsp
	sub rsp, 0x8
	mov [rbp-0x4], rdi
	
	; check if is prime	

	pop rbp
	ret

_start:
	
