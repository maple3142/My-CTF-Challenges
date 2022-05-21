global _start

section .text

_start:
    call main
    mov rdi, 0
    mov rax, 60 ; exit
    syscall

main:
    push rbp
    mov rbp, rsp
    sub rsp, 0x400

    mov rdx, msglen
    mov rsi, msg
    mov rdi, 1
    mov rax, 1 ; write
    syscall

    mov rdx, 0x410
    lea rsi, [rbp-0x400]
    mov rdi, 0
    mov rax, 0 ; read
    syscall

    mov rdx, rax ; length from read
    lea rsi, [rbp-0x400]
    mov rdi, 1
    mov rax, 1 ; write
    syscall

    leave
    ret


section .rodata
    msg: db "What do you want to say? ", 
    msglen: equ $ - msg

section .bss
    buf: resb 0x1000

section .note.GNU-stack noalloc noexec nowrite progbits
