section .text
    global main
main:       xor     rax, rax
            mov     rbx, "/bin/sh"
            push    rbx
            mov     rdi, rsp
            mov     rsi, rax
            mov     rax, 59
            syscall

            mov     rax, 0x0
            ret
