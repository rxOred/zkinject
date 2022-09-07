#include <cstddef>
#include <optional>
#include <iostream>
#include <zkinject/zkelf.hh>
#include <zkinject/zkmemorymap.hh>
#include <zkinject/zkprocess.hh>
#include <zkinject/zklog.hh>
#include <zkinject/zktypes.hh>
#include <wait.h>

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Expected a process\n");
        return -1;
    }
    char *s[2];
    s[0] = argv[1];
    s[1] = nullptr;

    auto proc = zkprocess::load_process_from_file(s, std::nullopt);
	if (proc->get_process_arch() == zkelf::ei_class::ELFCLASS64) {
		std::cout << "architecture : x64\n";
		std::cout
			<< "page name\tpage start address\tpage end address\tpage permissions\n";
		const zkprocess::MemoryMap<x64>* mm = proc->get_memory_map_if_x64();
		for (auto page = mm->get_iterator_begin(); page != mm->get_iterator_end();
			 page++) {
			printf("%s\t%lx\t%lx\t%s\n",
				   page->get_page_name().c_str(),
				   page->get_page_start_address(),
				   page->get_page_end_address(),
				   page->get_page_permissions().c_str()
			);
		}
	} else {	
		std::cout << "architecture : x86\n";
		const zkprocess::MemoryMap<x86>* mm = proc->get_memory_map_if_x86();		
		for (auto page = mm->get_iterator_begin(); page != mm->get_iterator_end();
			 page++) {
			printf("%s\t%x\t%x\t%s\n",
				   page->get_page_name().c_str(),
				   page->get_page_start_address(),
				   page->get_page_end_address(),
				   page->get_page_permissions().c_str()
			);
		}
	}
}
