#include <iostream>
#include <zkhooks.hh>

int main(int argc, char *argv[])
{
    pid_t pid = 121;
    puts("launcher");
    getchar();
    Hooks::ProcGotPltHook hook(nullptr, pid);
    auto base_addr = 
    hook.HookFunc(const char *func_name, void *fake_addr, void *base_addr)
}
