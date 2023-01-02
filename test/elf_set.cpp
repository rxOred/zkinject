#include <memory>
#include <zkinject/zkelf.hh>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Expected a program");
        return -1;
    }

    using namespace zkelf;
    auto elf = load_elf_writable_from_file(argv[1]);
    printf("parsing elf binary\n");

    printf("changing entry point to 0xaa\t");
    elf->set_elf_entry_point(0xaa);
    printf("new entry point is : %lx\n", elf->get_elf_entry_point());
}
