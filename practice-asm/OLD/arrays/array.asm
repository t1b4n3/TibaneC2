section .bss
    sum : resb 4
    counter : resb 4

section .text
    global array_sum


array_sum:
    push rbp 
    mov rbp, rsp
    ;sub rsp, 0x12
    mov [rbp-0x8], rdi ; array
    mov [rbp-0x10], rsi ; size

    mov eax, 0
    mov [sum], eax
    mov eax, 0
    mov [counter], eax
    mov ecx, [rbp-0x12]
loop:
    mov     eax, [counter]       ; eax = counter
    movsxd  rdx, eax           ; sign/zero extend eax -> rdx (64-bit index)
    shl     rdx, 2             ; rdx = rdx * 4
    mov     rax, [rbp-0x8]       ; rax = base address
    mov     eax, [rax + rdx]   ; eax = *(int *)(base + index*4)
    add [sum], eax
    cmp ecx, [counter]
    je done
    inc dword [counter] ; increment by 1
    jmp loop

done:
    mov rax, [sum]
    mov rsp, rbp
    pop rbp
    ;leave
    ret