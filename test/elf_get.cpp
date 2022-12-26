#include <memory>

#include <zkinject/zkelf.hh>

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Expected a program");
        return -1;
    }

    using namespace zkelf;
    auto elf = load_elf_writable_from_file(argv[1]);
    printf("parsing elf binary");

    printf("is stripped: %lx\n", elf->is_stripped());
    printf("elf size:  %lx\n",  elf->get_map_size());
    printf("elf class: %lx\n", elf->get_elf_class());
    printf("elf encoding: %lx\n",  elf->get_elf_encoding());
    printf("elf osabi: %lx\n",  elf->get_elf_osabi());
    printf("elf types: %lx\n",  elf->get_elf_type());
    printf("elf machine: %lx\n",  elf->get_elf_machine());
    printf("elf version: %lx\n",  elf->get_elf_version());
    printf("elf entry: %lx\n",  elf->get_elf_entry_point());
    printf("elf phdr offset: %lx\n",  elf->get_elf_phdr_offset());
    printf("elf shdr offset: %lx\n",  elf->get_elf_shdr_offset());
    printf("elf flags: %lx\n",  elf->get_elf_flags());
    printf("elf header size: %lx\n",  elf->get_elf_header_size());
    printf("elf phdr entry count: %lx\n", elf->get_elf_phdr_entry_count());
    printf("elf phdr entry size: %lx\n",  elf->get_elf_phdr_entry_size());
    printf("elf shdr entry count: %lx\n", elf->get_elf_shdr_entry_count());
    printf("elf shdr entry size: %lx\n",  elf->get_elf_shdr_entry_size());
    printf("elf string table index: %lx\n",  elf->get_elf_shdr_string_table_index());

    printf("program header table");
    printf("type\toffset\tvaddress\tpaddress\tflags\tfilesize\tmemorysize\talignment\t");
    for (std::size_t i = 0; i < elf->get_elf_phdr_entry_count(); i++) {
        printf("%lx\t", elf->get_segment_type(i));
        printf("%lx\t", elf->get_segment_offset(i));
        printf("%lx\t", elf->get_segment_vaddress(i));
        printf("%lx\t", elf->get_segment_paddress(i));
        printf("%lx\t", elf->get_segment_flags(i));
        printf("%lx\t", elf->get_segment_file_size(i));
        printf("%lx\t", elf->get_segment_memory_size(i));
        printf("%lx\t", elf->get_segment_address_alignment(i));
    }
    puts("");

    printf("section header table ");
    printf("nameindex\t type \t flags \t address \t offset \t size \t addralign \t entrysz \t link \t info");
    for (std::size_t i = 0; i < elf->get_elf_shdr_entry_count(); i++) {
        printf("%lx\t", elf->get_section_name_index(i));
        printf("%lx\t", elf->get_section_type(i));
        printf("%lx\t", elf->get_section_flags(i));
        printf("%lx\t", elf->get_section_address(i));
        printf("%lx\t", elf->get_section_offset(i));
        printf("%lx\t", elf->get_section_size(i));
        printf("%lx\t", elf->get_section_address_alignment(i));
        printf("%lx\t", elf->get_section_entry_size(i));
        printf("%lx\t", elf->get_section_link(i));
        printf("%lx\t", elf->get_section_info(i));
    }
}
