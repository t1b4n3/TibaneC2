section .bss
    num resq 1
    ;len resd 1

section .text
    global _start 
    global fibonacci

; formular f(n)= f(n -1) - f(n -2) ; n  
fibonacci:
    ; get argument
    push rbp
    mov rbp, rsp
    sub rsp, 0x10
    mov [rbp-0x8], rdi
    
    ; if n = 0 return 0;
    mov rax, 0
    cmp rax, [rbp-0x8]
    je .return

    ; if n = 1 return 1;
    mov rax, 1
    cmp rax, [rbp-0x8]
    je .return

    ; return fib(n - 1) + fib(n - 2)
    
    ; fib(n- 1)
    mov rax, [rbp-0x8]
    sub rax, 1
    mov rdi, rax
    call fibonacci
    mov rbx, rax

    mov rax, [rbp-0x8]
    sub rax, 2
    mov rdi, rax
    call fibonacci
    
    add rax, rbx
.return:
    mov rsp, rbp
    pop rbp
    ret

;number_to_string:
;    push rbp
;    mov rbp, rsp
;    
;    mov rax, [rbp+16]   ; Get the number
;    mov rdi, num        ; Pointer to buffer
;    mov rcx, 10         ; Base 10
;    mov rbx, 0          ; Digit counter
;    
;.convert_loop:
;    xor rdx, rdx
;    div rcx             ; Divide by 10
;    add dl, '0'         ; Convert to ASCII
;    mov [rdi+rbx], dl   ; Store digit
;    inc rbx
;    test rax, rax
;    jnz .convert_loop
;    
;    ; Reverse the string
;    mov rsi, num
;    lea rdi, [num+rbx-1]
;    shr rbx, 1
;    jz .done
;    
;.reverse_loop:
;    mov al, [rsi]
;    mov ah, [rdi]
;    mov [rdi], al
;    mov [rsi], ah
;    inc rsi
;    dec rdi
;    dec rbx
;    jnz .reverse_loop
;    
;.done:
;    mov byte [num+rbx], 0   ; Null terminate
;    mov rax, rbx            ; Return length
;    
;    mov rsp, rbp
;    pop rbp
;    ret

_start:
    ; call fibonacci
    mov rax, 6
    mov rdi, rax
    call fibonacci
    ;mov [num], rax


    ;mov rax, [num]
    ;mov rdi, rax
    ;call number_to_string
    ;mov [len], rax


    ; print 
    ;mov rax, 1
    ;mov rdi, 1
    ;mov rsi, num
    ;mov rdx, 8
    ;syscall

    ; exit
    mov rdi, rax
    mov rax, 60
    syscall