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
    std::cout << "elf flags: " << elf->get_elf_flags() <<  std::endl;
    std::cout << "elf header size: " << elf->get_elf_header_size() << std::endl;
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

    std::cout << "section header table " << std::endl;
    std::cout << "nameindex\t type \t flags \t address \t offset \t size \t addralign \t entrysz \t link \t info" << std::endl;
    for (std::size_t i = 0; i < elf->get_elf_shdr_entry_count(); i++) {
        std::cout << elf->get_section_name_index(i) << "\t";
        std::cout << elf->get_section_type(i) << "\t";
        std::cout << elf->get_section_flags(i) << "\t";
        std::cout << elf->get_section_address(i) << "\t";
        std::cout << elf->get_section_offset(i) << "\t";
        std::cout << elf->get_section_size(i) << "\t";
        std::cout << elf->get_section_address_alignment(i) << "\t";
        std::cout << elf->get_section_entry_size(i) << "\t";
        std::cout << elf->get_section_link(i) << "\t";
        std::cout << elf->get_section_info(i) << "\t";
    }
}
