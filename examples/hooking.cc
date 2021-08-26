#include <iostream>
#include <zkhooks.hh>

/* example code for redirecting puts call to redirected_function */
void redirected_puts(char *s)
{
    puts(s);
    puts("again again againn!!!!");
}

int main(int argc, char *argv[])
{
    puts("hello world");
    Hooks::ElfGotPltHook putshook(argv[0]);
    Addr base_addr = putshook.GetModuleBaseAddress(argv[0]);
    putshook.HookFunc("puts", (void *)redirected_puts, base_addr);
    puts("hello");
}
