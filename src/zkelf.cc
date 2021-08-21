#include "zkelf.hh"

Binary::Elf::Elf()
    :elf_memmap(nullptr), elf_pathname(nullptr), elf_ehdr(nullptr),
    elf_phdr(nullptr), elf_shdr(nullptr), elf_size(0), elf_baseaddr(0)
{}

Binary::Elf::Elf(const char *pathname)
    :elf_memmap(nullptr), elf_pathname(pathname), elf_ehdr(nullptr),
    elf_phdr(nullptr), elf_shdr(nullptr), elf_size(0), elf_baseaddr(0)
{
    try{
        OpenElf();
        LoadFile();
    } catch (std::exception& e) {
        std::cerr << e.what();
        RemoveMap();
        std::abort();
    }
}

void Binary::Elf::OpenElf(void)
{
    assert(elf_pathname != nullptr && "pathname is not specified");

    elf_fd = open(elf_pathname, O_RDONLY);
    if(elf_fd < 0)
        ERROR(std::runtime_error("open failed\n"));

    struct stat st;
    if(fstat(elf_fd, &st) < 0)
        ERROR(std::runtime_error("fstat failed\n"));

    elf_size = st.st_size;
}

void Binary::Elf::LoadFile(void)
{
    assert(elf_fd != 0 && "file descriptor is empty");

    elf_memmap = mmap(elf_memmap, elf_size, PROT_READ | PROT_WRITE, 
            MAP_PRIVATE, elf_fd, 0);
    if(elf_memmap == MAP_FAILED)
        ERROR(std::runtime_error("mmap failed\n"));

    elf_ehdr = (Ehdr *)elf_memmap;
    assert(VerifyElf() != false && "File is not an Elf binary");

    u8 *m = (u8 *)elf_ehdr;
    elf_phdr = (Phdr *)&m[elf_ehdr->e_phoff];
    elf_shdr = (Shdr *)&m[elf_ehdr->e_shoff];
}

bool Binary::Elf::VerifyElf(void) const
{
    if(elf_ehdr->e_ident[0] != 0x7f || elf_ehdr->e_ident[1] != 'E' ||
            elf_ehdr->e_ident[2] != 'L' || elf_ehdr->e_ident[4] != 'F')
    {
        return false;
    }

    return true;
}

void Binary::Elf::RemoveMap(void)
{
    assert(elf_memmap != nullptr && "memory is not mapped to unmap");
    if(munmap(elf_memmap, elf_size) < 0)
        ERROR(std::runtime_error("munmap failed"));

    elf_memmap = nullptr;
}

int Binary::Elf::FindSegmentbyAttr(u32 type, u32 flags) const
{
    for(int i = 0; i < elf_ehdr->e_phnum; i++){
        if(elf_phdr[i].p_type == type && elf_phdr[i].p_flags == flags){
            return i;
        }
    }

    return -1;
}

int Binary::Elf::GetSectionIndexByName(const char *name) const
{
    char *memmap = (char *)elf_memmap;
    char *shstrtab = &memmap[elf_shdr[elf_ehdr->e_shstrndx].sh_offset];
    for(int i = 0; i< elf_ehdr->e_shnum; i++){
        if(strcmp(&shstrtab[elf_shdr[i].sh_name], name) == 0){
            return i;
        }
    }
    return -1;
}

void *Binary::Elf::ElfRead(off_t readoff, size_t size) const
{
    u8 *buffer = (u8 *)calloc(size, sizeof(u8));
    if(buffer == nullptr)
        ERROR(std::bad_alloc());

    u8 *memmap = (u8 *)elf_memmap;
    for(int i = readoff; i < readoff + size; i++){
        buffer[i] = memmap[i];
    }

    return buffer;
}

void Binary::Elf::ElfWrite(void *buffer, off_t writeoff, size_t size)
 const
{
    u8 *memmap = (u8 *)elf_memmap;
    u8 *_buffer = (u8 *)buffer;
    for(int i = 0; i < writeoff + size; i++){
        _buffer[i] = memmap[i];
    } 
}

Binary::TextPaddingInfection::TextPaddingInfection(char *target)
    :Elf(target), tpi_shellcode(nullptr), tpi_orgentry(0), 
    tpi_fakeetry(0)
{}

off_t Binary::TextPaddingInfection::FindFreeSpace(int size) const
{
    /* text segment has permission bits set to read and exec */
    int text_index = FindSegmentbyAttr(PT_LOAD, PF_X | PF_R);
    assert(text_index != -1 && "text segment not found");

    /* data segment has permission bits set to read and write */
    int data_index = FindSegmentbyAttr(PT_LOAD, PF_W | PF_R);
    assert(data_index != -1 && "data segment not found");

    assert(text_index + 1 == data_index);
    int available_space = elf_phdr[data_index].p_offset - 
        elf_phdr[text_index].p_offset;
    assert(available_space >= size && "available free space is less     \
            than size");
    return elf_phdr[text_index].p_offset + elf_phdr[text_index].
        p_filesz;
}

Binary::TextPaddingInfection::InjectCode(void)
{

}