#include <zkinject/zkelf.hh>
#include <memory>

int main(int argc, char *argv[]) 
{
    if (argc < 2) {
        return -1;
    }

    // testing elf headers
    Binary::Elf elf(const_cast<char*>(argv[1]));
    auto ehdr = elf.GetElfHeader();
    printf("ehsize %x\n", ehdr->e_ehsize); 
    printf("entry %lx\n", ehdr->e_entry);
    printf("flags %x\n", ehdr->e_flags); 
    printf("phentrysize %x\n", ehdr->e_phentsize);
    printf("section haeders %d\n", ehdr->e_shnum);

    // testing section headers
    auto shdrtab = elf.GetSectionHeaderTable();
    printf("[1] %lx\n", shdrtab[1].sh_addr);
    printf("[2] %lx\n", shdrtab[1].sh_addralign);
    printf("[3] %lx\n", shdrtab[1].sh_offset);
    printf("[4] %lx\n", shdrtab[1].sh_size);

    // testing program headers 
    auto phdrtab = elf.GetProgramHeaderTable();
    printf("filesz %lx\n", phdrtab[1].p_filesz);
    printf("offset %lx\n", phdrtab[1].p_offset);
    printf("vadr %lx\n", phdrtab[1].p_vaddr);
    printf("flags %x\n", phdrtab[1].p_flags);

    auto type = elf.GetElfType();
    printf("elf type %x\n", type);

    auto entry = 0x1234;
    elf.SetEntryPoint(entry); 
    printf("new entry point %lx\n", elf.GetElfHeader()->e_entry);
}
