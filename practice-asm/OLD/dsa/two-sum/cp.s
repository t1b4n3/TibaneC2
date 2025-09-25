section .bss
    num1: resd 1
    num2: resd 1
    i: resd 1
    j: resd 1
    target: resd 1


    global result
    result: resd 2

section .text
global twoSum


twoSum:
    ; edi 
    push rbp
    mov rbp, rsp
    sub rsp, 32   ; for locals
    mov QWORD [rbp-24], RDI
    mov DWORD [rbp-28], esi
    mov DWORD [rbp-32], edx
    mov DWORD [rbp-36], ecx
    mov eax, 0
    mov [i], eax
    mov eax, 0
    mov [j], eax

LOOP:
    mov ecx, [j]
    mov rax, QWORD [rbp-24]
    mov eax, DWORD [rax+rcx*4]
    mov [num1], eax

    mov ecx, [i]
    mov rax, QWORD  [rbp-24]
    mov eax, DWORD  [rax+rcx*4]
    mov [num2], eax

    mov eax, [  num1]
    add eax, [ num2]
    
    cmp eax, [target]
    je Return

    mov eax, 1
    add [j], eax

    mov eax, 1
    add [i], eax
    jmp LOOP

Return:
    mov rsi, result
    mov rbx, 0
    mov eax, [i]
    mov [rsi + rbx*4], eax
    
    mov rbx, 1
    mov eax, [j]
    mov [rsi + rbx*4], eax
    mov rax, rsi
    pop rbp
    ret
