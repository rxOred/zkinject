#include <zkinject/zkelf.hh>
#include <memory>

int main(int argc, char *argv[]) 
{
    if (argc < 2) {
        return -1;
    }
    auto elf = std::make_shared<Binary::Elf>(const_cast<char *>(argv[1]));
    auto ehdr = elf->GetElfHeader();
    printf("%x\n", ehdr->e_ehsize); 
    printf("%lx\n", ehdr->e_entry);
    printf("%x\n", ehdr->e_flags);
    printf("%x\n", ehdr->e_ehsize);
    printf("%x\n", ehdr->e_phentsize);
}
