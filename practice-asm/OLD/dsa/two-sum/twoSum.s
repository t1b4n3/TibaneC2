section .text
    global twoSum

twoSum:
    ; Function prototype: int *twoSum(int *nums, int numsSize, int target, int *returnSize);
    ; Registers: RDI = nums, ESI = numsSize, EDX = target, RCX = returnSize
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi        ; R12 = nums (base pointer)
    mov r13d, esi       ; R13D = numsSize
    mov r14d, edx       ; R14D = target
    mov r15, rcx        ; R15 = returnSize pointer

    ; Set the returnSize to 2 (always for this problem)
    mov DWORD [r15], 2

    ; Initialize outer loop counter i = 0
    xor ebx, ebx        ; EBX = i

outer_loop:
    ; Check if i >= numsSize-1, then exit (not found, though problem assumes solution exists)
    mov eax, ebx
    inc eax
    cmp eax, r13d
    jge not_found

    ; Load nums[i] into R8D
    mov r8d, [r12 + rbx*4] ; R8D = nums[i]

    ; Initialize inner loop counter j = i+1
    lea ecx, [rbx + 1]     ; ECX = j = i+1

inner_loop:
    cmp ecx, r13d          ; Check if j >= numsSize
    jge next_i

    ; Load nums[j] into R9D
    mov r9d, [r12 + rcx*4] ; R9D = nums[j]

    ; Check if nums[i] + nums[j] == target
    mov eax, r8d
    add eax, r9d
    cmp eax, r14d
    je found

    inc ecx                ; j++
    jmp inner_loop

next_i:
    inc ebx                ; i++
    cmp ebx, r13d
    jl outer_loop

not_found:
    ; According to the problem, we can assume exactly one solution exists,
    ; so this is an error path. Return NULL.
    xor eax, eax
    jmp done

found:
    ; We found the pair at indices i (EBX) and j (ECX)
    mov rax, result        ; RAX = address of the result buffer
    mov [rax], ebx         ; result[0] = i
    mov [rax + 4], ecx     ; result[1] = j
    mov rax, result        ; Return the pointer to the result buffer

done:
    pop r15
    pop r14
    pop r13
    pop r12
    ret

section .bss
    global result
    result: resd 2