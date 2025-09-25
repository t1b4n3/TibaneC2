section .bss
    str1 resd 10
    str2 resd 10


section .data
    get_str db "Enter String : "
    len equ $ - get_str
    same_str db "The strings are the Same", 0xA
    same_len equ $ - same_str
    not_same_str db "The strings are not the Same", 0xA
    not_same_len equ $ - not_same_str


section .text
    global _start
    global strcmp

strcmp:
    push rbp
    mov rbp, rsp
    sub rsp, 0x32

    ; get arguments (arg1, arg2)
    mov [rbp-0x8], rdi ; str1
    mov [rbp-0x10], rsi ; str2 arg2


    ; cmp the two strings until \x00
    lea rax, [rbp-0x8] ; ptr for str1
    lea rbx, [rbp-0x10]; ptr for str2

compare:
    
    
    mov al, [rax]
    mov bl, [rbx]
    ; are strings \x00 chars?
    
    mov cl, 0x00
    cmp al, cl
    sete r9b ; r9b = 1 if equal

    cmp bl, cl
    sete r8b ; 

    cmp r8b, r9b
    je same

    ; compare the 2 characters
    cmp al, bl
    jne not_same


    ; move on to next character in string 
    add rax, 1
    add rbx, 1
    jmp compare


same:
    mov rax, 0
    jmp done

not_same:
    mov rax, -1
done:
    mov rsp, rbp
    pop rbp
    ret


_start:
    ; get 2 strings from user
    mov rax, 1
    mov rdi, 1
    mov rsi, get_str
    mov rdx, len
    syscall


    mov rax, 0
    mov rdi, 0
    mov rsi, str1
    mov rdx, 40
    syscall


    mov rax, 1
    mov rdi, 1
    mov rsi, get_str
    mov rdx, len
    syscall


    mov rax, 0
    mov rdi, 0
    mov rsi, str2
    mov rdx, 40
    syscall


    ; strcmp

    mov rdi, str2
    mov rsi, str1
    call strcmp

    ; print the result
    mov rbx, 0
    cmp rax, rbx
    jne NOT_SAME

    mov rax, 1
    mov rdi, 1
    mov rsi, same_str
    mov rdx, same_len
    syscall
    jmp exit

NOT_SAME:
    mov rax, 1
    mov rdi, 1
    mov rsi, not_same_str
    mov rdx, not_same_len
    syscall

exit:
    ; exit
    mov rax, 60
    mov rdi, 1
    syscall