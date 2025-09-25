section .data
    hello db "Hello World!", 0xA
    len  equ $ - hello ; length of string

section .text
global _start
_start:

print_hello:
mov eax, 4 ; write syscall
mov ebx, 1 ; stdout
mov ecx, hello ; hello string
mov edx, len ;
int 0x80

exit:
mov eax, 1 
mov ebx, 0
int 0x80