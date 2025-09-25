section .text
	global sum:
sum:
	push rbp
	mov rbp, rsp
	mov rdx, 0
	mov rbx, rdi
	mov rcx, 0
loop:
	cmp rbx, rcx
	je done
	add rdx, rcx
	;inc rcx
	mov rax, 1
	add rcx, rax
	jmp loop
done:		
	mov rax, rdx
	mov rsp, rbp
	pop rbp
	ret
