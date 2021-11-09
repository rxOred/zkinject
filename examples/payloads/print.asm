section .text
    global _start:

_start:     push    rdx
            push    rbx
            push    rdi
            push    rsi
            jmp     string

print:      mov     rsi,    QWORD[rsp]
            mov     rdi,    1
            mov     rdx,    20
            mov     rax,    0x1
            syscall

            pop     rax
            pop     rsi
            pop     rdi
            pop     rbx
            pop     rdx
            mov     rax,    0x991234
            jmp     rax

string:     call    print
            db      "string is here baby", 0xa, 0x0
