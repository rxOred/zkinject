#include <memory>
#include <zkinject/zkelf.hh>
#include <zkinject/zktypes.hh>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Expected a program");
        return -1;
    }

    using namespace zkelf;
    auto elf = load_elf_writable_from_file(argv[1]);
    puts("parsing elf binary");

	std::cout << "changing entry point to 0xaa55" << std::endl;
    elf->set_elf_entry_point(x64::addr_t(0xaa));
	std::cout << "new entry point is " << std::hex << elf->get_elf_entry_point() << std::endl;
}
