section .text
	global favorate_singer:


; arg = number_of_songs | arg2 = array of singers | all intergers

favorate_singer:
	push rbp
	mov rbp, rsp
	mov DWORD [rbp-0x20], edi
	mov QWORD [rbp-0x30], rsi
	
	; index 
	mov [rbp-0x4], 0
	; most singers
	mov [rbp-0x8], 0;

LOOP:
	mov eax, [rbp-0x4]
	cdqe ; convert dword to qword
	lea rdx, [0+rax*4]
	mov rax, [rbp-0x30]
	add rax, rdx
	; rax = arr[index]	
	

	mov rsp, rbp
	pop rbp
	ret
