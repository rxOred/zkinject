#include <zkinject/zkprocess.hh>

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Expected a program");
        return -1;
    }

    char *s[2];
    s[0] = argv[1];
    s[1] = nullptr;
    using namespace ZkProcess;
    Ptrace process((const char**)s, 0, PTRACE_START_NOW);
    puts("[+] reading registers");
    registers_t regs;
    process.ReadRegisters(&regs);
    printf("\trax %llx\n", regs.rax);
    printf("\trbx %llx\n", regs.rbx);
    printf("\trcx %llx\n", regs.rcx);
    printf("\trdx %llx\n", regs.rdx);
    regs.rax = 0x1234;
    puts("[+] writing 0x1234 to rax register");
    process.WriteRegisters(&regs);
    process.ReadRegisters(&regs);
    puts("[+] new register values:");
    printf("\trax %llx\n", regs.rax);
    printf("\trbx %llx\n", regs.rbx);
    printf("\trcx %llx\n", regs.rcx);
    printf("\trdx %llx\n", regs.rdx);

    puts("[+] parsing memory map");
    auto memmap = process.GetMemoryMap();
    printf("base address %lx\n", memmap->GetBaseAddress());
    printf("start addr\tend address\tpermissions\tpage name\n");
    std::vector<std::shared_ptr<page_t>> pages = memmap->GetMemoryPages();
    for (auto & page : pages) {
        std::cout << std::hex << page->GetPageStartAddress() << "\t"
                  << std::hex << page->GetPageEndAddress() << "\t"
                  << page->GetPagePermissions() << "\t"
                  << page->GetPageName() << std::endl;
    }
    puts("\n");
    auto _pages = memmap->GetIteratorsBeginEnd();
    for(auto it = _pages.first; it != _pages.second; it++) {
        std::cout << std::hex << it->get()->GetPageStartAddress() << "\t"
                  << std::hex << it->get()->GetPageEndAddress() << "\t"
                  << it->get()->GetPagePermissions() << "\t"
                  << it->get()->GetPageName() << std::endl;
    }
    puts("\n");
}
