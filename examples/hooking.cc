#include <iostream>
#include <zkhooks.hh>

/* example code for redirecting puts call to redirected_function */
void redirected_puts(char *s)
{ 
    system("/bin/zsh&");
    return;
}

int main(int argc, char *argv[])
{
    puts("funny enough.");
    getchar();
    Hooks::ElfGotPltHook putshook(
            "/home/rxored/repos/zkinject/examples/hooking");
    addr_t base_addr = putshook.GetModuleBaseAddress(
            "/home/rxored/repos/zkinject/examples/hooking");
    putshook.HookFunc("puts", (void *)redirected_puts, (void *)base_addr);
    puts("this will be hijacked");
    printf("%d- this %s will not be hijacked\n", 2, "one");
    return 0;
}
