#define _fork()         call(__NR_fork)

static int call(int sys)
{
    asm("                           \
        movl    8(%esp), %eax       \
        int     $0x80               \
    ");
}
