#include <wait.h>

#include <cstddef>
#include <iostream>
#include <optional>
#include <zkinject/zkelf.hh>
#include <zkinject/zklog.hh>
#include <zkinject/zkmemorymap.hh>
#include <zkinject/zkprocess.hh>
#include <zkinject/zktypes.hh>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Expected a process\n");
        return -1;
    }
    std::cout << "analyzing memory map of " << argv[1] << std::endl;
    char* s[2];
    s[0] = argv[1];
    s[1] = nullptr;

    auto proc = zkprocess::load_process_from_file(s, std::nullopt);
    if (proc->get_process_arch() == zkelf::ei_class::ELFCLASS64) {
        std::cout << "architecture : x64\n";
        auto mm =
            proc->get_memory_map_if_x64();
        if (mm == nullptr) {
            std::cout << "memory map is null" << std::endl;
            return -1;
        }
        else {
            std::cout << "memory map is not null" << std::endl;
        }
        std::cout << "base address is " << std::hex << mm->get_base_address() << std::endl;

        auto begin_page = mm->get_base_page();
        std::cout << "begin page load address is " << std::hex << begin_page.get_page_start_address() << std::endl;
        std::cout << "begin page end address is " << std::hex << begin_page.get_page_end_address() << std::endl;
        std::cout << "begin page name " << begin_page.get_page_name() << std::endl;

        std::cout << "page name\tpage start address\tpage end "
                     "address\tpage permissions\n";

        for (auto page = mm->get_iterator_begin();
             page != mm->get_iterator_end(); page++) {
            printf("%s\t%lx\t%lx\t%s\n", page->get_page_name().c_str(),
                   page->get_page_start_address(),
                   page->get_page_end_address(),
                   page->get_page_permissions().c_str());
        }
    } else {
        std::cout << "architecture : x86\n";
        auto mm =
            proc->get_memory_map_if_x86();
        for (auto page = mm->get_iterator_begin();
             page != mm->get_iterator_end(); page++) {
            printf("%s\t%x\t%x\t%s\n", page->get_page_name().c_str(),
                   page->get_page_start_address(),
                   page->get_page_end_address(),
                   page->get_page_permissions().c_str());
        }
    }
}
