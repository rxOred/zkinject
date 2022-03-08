#include <memory>

#include <zkinject/zkelf.hh>

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Expected a program");
        return -1;
    }

    using namespace ZkElf;
    Elf elf(const_cast<char *>(argv[1]), ELF_AUTO_SAVE);
    // elf header methods
    auto ehdr = elf.GetElfHeader();
    printf("ehsize %x\n", ehdr->e_ehsize);
    printf("phentrysize %x\n", ehdr->e_phentsize);
    printf("section haeders %d\n", ehdr->e_shnum);

    // other methods to parse ehdr
    printf("machine %x\n", elf.GetElfMachine());
    printf("version %x\n", elf.GetElfVersion());

    printf("changing entry point to 0x1234\n");
    elf.SetElfEntryPoint(0x1234);
    printf("new entry point %lx\n", elf.GetElfEntryPoint());

    printf("\n");
    // testing section header table
    auto shdrtab = elf.GetSectionHeaderTable();
    printf("section [1] address %lx\n", shdrtab[1].sh_addr);
    printf("section [2] entry size %lx\n", shdrtab[2].sh_entsize);
    printf("section [3] size %lx\n", shdrtab[3].sh_size);

    //other shdr methods
    printf("section [4] %lx\n", elf.GetSectionAddressAlign(4));
    printf("section [5] %lx\n", elf.GetSectionOffset(5));

    printf("chaning offset of [4] to 0x1234\n");
    elf.SetSectionOffset(4, 0x1234);
    printf("changed offset %lx\n", elf.GetSectionOffset(4));

}
