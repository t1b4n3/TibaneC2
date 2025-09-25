section .text
    global string_len


;int string_length(const char *str) {
;    int length = 0;
;    while (str[length] != '\0') {
;        length++;
;    }
;    return length;
;}
string_len:
    push rbp
    mov rbp, rsp
    sub rsp, 0x10

    mov rax, 0
    mov [rbp-0x4], rax
    mov [rbp-0x8], rdi

LOOP:
    mov rcx, 1
    add [rbp-0x4], rcx
    mov rsi, [rbp-0x8]
    mov eax, [rbp-0x4]
    add rsi, rax 
    mov al, [rsi]

    mov bl, 0x00
    cmp al, bl ; \0
    je done
    jmp LOOP

done:
    mov rax, [rbp-0x4]
    mov rsp, rbp
    pop rbp
