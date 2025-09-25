;int goose()
;{
;return -4;
;}

section .text
    global goose
    global cow
    global pig
    global sheep
goose:
    push rbp
    mov rbp, rsp

    mov rax, -4;
    pop rbp
    ret


;int cow(int a, int b)
;{
;return a - b;
;}

cow:
    push rbp
    mov rbp, rsp

    mov rax, rdi
    mov rcx, rsi

    sub rax, rcx
    mov rsp, rbp
    pop rbp
    ret

;int pig(int a)
;{
;return a*3;
;}

pig:
    push rbp
    mov rbp, rsp

    mov rax, rdi
    mov rcx, 3
    mul rcx

    mov rsp, rbp
    pop rbp
    ret

;int sheep(int c)
;{
;if(c < 0)
;return 1;
;else
;return 0;
;}

sheep:
    push rbp
    mov rbp, rsp

    mov rax, rdi
    mov rcx, 0
    cmp rax, rcx
    jle .x
    mov rax, 1
    jmp .done
.x:
    mov rax, 0
.done:
    mov rsp, rbp
    pop rbp
    ret