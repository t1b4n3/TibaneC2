section .bss
    num1: resd 1
    num2: resd 1
    i: resd 1
    j: resd 1
    target: resd 1


    global result
    result: resd 2

section .text
global _start, twoSum


twoSum:
    ; edi 
    mov QWORD PTR [rbp-24], RDI
    mov DWORD PTR [rbp-28], esi
    mov DWORD PTR [rbp-32], edx
    mov DWORD PTR [rbp-36], ecx
    mov [i], 0
    mov [j], 0
for_loop1:
    add [i], 1
    
for_loop2:
    mov ecx, [j]
    mov rax, QWORD PTR [rbp-24]
    mov eax, DWORD PTR [rax+rcx*4]
    mov [num1], eax

    mov ecx, [i]
    mov rax, QWORD PTR [rbp-24]
    mov eax, DWORD PTR [rax+rcx*4]
    mov [num2], eax

    mov eax , [num1]
    add eax, [num2]
    
    cmp eax, [target]
    je Return

    add [j], 1
    jmp for_loop1

Return:
    mov rsi, result
    mov rbx, 0
    mov [rsi + rbx*4], [i]
    
    mov rbx, 1
    mov [rsi + rbx*4], [j]
    mov rax, rsi
    pop rbp
    ret
