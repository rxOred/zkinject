#include <memory>

#include <zkinject/zkelf.hh>

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Expected a program");
        return -1;
    }

    using namespace zkelf;
    auto elf = load_elf_from_file(const_cast<char *>(argv[1]), zkelf::elf_flags::ELF_AUTO_SAVE);

    std::cout << "is stripped: " << elf->is_stripped() << std::endl;
    std::cout << "elf size: " << elf->get_map_size() << std::endl;
    std::cout << "elf class: " << elf->get_elf_class() << std::endl;
    std::cout << "elf encoding: " << elf->get_elf_encoding() << std::endl;
    std::cout << "elf osabi: " << elf->get_elf_osabi() << std::endl;
    std::cout << "elf types: " << elf->get_elf_type() << std::endl;
    std::cout << "elf machine: " << elf->get_elf_machine() << std::endl;
    std::cout << "elf version: " << elf->get_elf_version() << std::endl;
    std::cout << "elf entry: " << elf->get_elf_entry_point() << std::endl;
    std::cout << "elf phdr offset: " << elf->get_elf_phdr_offset() << std::endl;
    std::cout << "elf shdr offset: " << elf->get_elf_shdr_offset() << std::endl;
    std::cout << "elf flags: " << elf->get_elf_flags() <<  std::endl:
    std::cout << "elf header size: " << elf->get_elf_header_size() << std:endl;
    std::cout << "elf phdr entry count: "<< elf->get_elf_phdr_entry_count() << std::endl;
    std::cout << "elf phdr entry size: " << elf->get_elf_phdr_entry_size() << std::endl;
    std::cout << "elf shdr entry count: "<< elf->get_elf_shdr_entry_count() << std::endl;
    std::cout << "elf shdr entry size: " << elf->get_elf_shdr_entry_size() << std::endl;
    std::cout << "elf string table index: " << elf->get_elf_shdr_string_table_index() << std::endl << std::endl;


    std::cout << "program header table" << std::endl;
    std::cout << "type\toffset\tvaddress\tpaddress\tflags\tfilesize\tmemorysize\talignment\t" << std::endl;
    for (std::size_t i = 0; i < elf->get_elf_phdr_entry_count(); i++) {
        std::cout << elf->get_segment_type(i) << "\t";
        std::cout << elf->get_segment_offset(i) << "\t";
        std::cout << elf->get_segment_vaddress(i) << "\t";
        std::cout << elf->get_segment_paddress(i) << "\t";
        std::cout << elf->get_segment_flags(i) << "\t";
        std::cout << elf->get_segment_file_size(i) << "\t";
        std::cout << elf->get_segment_memory_size(i) << "\t";
        std::cout << elf->get_segment_address_alignment(i) << std::endl;
    }
    puts("");

    

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
