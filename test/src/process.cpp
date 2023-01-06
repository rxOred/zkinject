#include <zkinject/zkprocess.hh>

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
}
