BITS 64

org 0x400000 ; Default base address for 64-bit executables

ehdr:                         ; Elf64_Ehdr
    db 0x7F, "ELF"            ; e_ident: ELF magic
    db 2, 1, 1, 0             ; e_ident: 64 bit, little endian, version 1, target System V
    db 0, 0, 0, 0, 0, 0, 0, 0 ; e_ident: padding
    dw 2                      ; e_type
    dw 0x3E                   ; e_machine
    dd 1                      ; e_version
    dq _start                 ; e_entry
    dq phdr - $$              ; e_phoff
    dq 0                      ; e_shoff
    dd 0                      ; e_flags
    dw ehdr_size              ; e_ehsize
    dw phdr_size              ; e_phentsize
    dw 1                      ; e_phnum
    dw 0                      ; e_shentsize
    dw 0                      ; e_shnum
    dw 0                      ; e_shstrndx

ehdr_size equ $ - ehdr

phdr:            ; Elf64_Phdr
    dd 1         ; p_type
    dd 5         ; p_flags
    dq 0         ; p_offset
    dq $$        ; p_vaddr
    dq $$        ; p_paddr
    dq file_size ; p_filesz
    dq file_size ; p_memsz
    dq 0x1000    ; p_align

phdr_size equ $ - phdr

msg: db 'hitcon{no_idea_how_to_make_a_challenge?_just_take_a_real_world_project_and_add_some_weird_constraint_lol}', 0xA
msglen equ $ - msg

_start:
    ; syscall: sys_write (1)
    push 1             ; syscall number
    pop rax
    mov edi, eax       ; file descriptor: stdout
    lea esi, [rel msg] ; pointer to message
    push msglen        ; message length
    pop rdx
    syscall            ; invoke syscall

    ; syscall: sys_exit (60)
    mov eax, 60        ; syscall number
    xor edi, edi       ; exit code 0
    syscall            ; invoke syscall

file_size equ $ - $$

; nasm -f bin readflag.s -o readflag && chmod +x readflag
