#include <memory>

#include <zkinject/zkelf.hh>

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Expected a program");
        return -1;
    }

    using namespace ZkElf;
    Elf elf(const_cast<char *>(argv[1]), ZkElf::ELF_AUTO_SAVE);
    // elf header
    auto ehdr = elf.GetElfHeader();
    printf("ehsize %x\n", ehdr->e_ehsize);
    printf("phentrysize %x\n", ehdr->e_phentsize);
    printf("section haeders %d\n", ehdr->e_shnum);

    printf("machine %x\n", elf.GetElfMachine());
    printf("version %x\n", elf.GetElfVersion());

    puts("changing entry point to 0x1234");
    elf.SetElfEntryPoint(0x1234);
    printf("new entry point %lx\n", elf.GetElfEntryPoint());

    // section header and section header table
    auto shdrtab = elf.GetSectionHeaderTable();
    printf("section [1] address %lx\n", shdrtab[1].sh_addr);
    printf("section [2] entry size %lx\n", shdrtab[2].sh_entsize);
    printf("section [3] size %lx\n", shdrtab[3].sh_size);

    printf("section [4] %lx\n", elf.GetSectionAddressAlign(4));
    printf("section [5] %lx\n", elf.GetSectionOffset(5));

    puts("chaning offset of [4] to 0x1234");
    elf.SetSectionOffset(4, 0x1234);
    printf("changed offset %lx\n", elf.GetSectionOffset(4));

    // program header and phdr
    auto phdrtab = elf.GetProgramHeaderTable();
    printf("segment [1] file size %lx\n", phdrtab[1].p_filesz);
    printf("segment [2] mem size %lx\n", phdrtab[1].p_memsz);
    printf("segment [3] offset %lx\n", phdrtab[1].p_offset);

    printf("section [4] %lx\n", elf.GetSegmentAlignment(4));
    printf("section [5] %lx\n", elf.GetSegmentVAddress(5));

    puts("changing filesie of [4] to 0x1234");
    elf.SetSegmentFileSize(4, 0x1234);
    printf("changed offset %lx\n", phdrtab[4].p_filesz);
    //ZkUtils::SaveMemoryMap("elf-patched", elf.GetMemoryMap(), elf.GetElfSize());
}
