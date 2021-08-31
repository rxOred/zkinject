#include "zkelf.hh"
#include "zkexcept.hh"
#include "zktypes.hh"

void Binary::PatchAddress(u8 *buffer, size_t len, u64 addr, u8 *magic)
{
    for(int i = 0; i < len; i++){
        if(buffer[i] == magic[0]){
            for(int j = i; j < i + MAGIC_LEN; j++){
                if(buffer[i] != magic[j - i])
                    goto error;
            }
            /* magic found!!! */
            *(u64 *)((void *)(buffer + i)) = addr;
        }
    }
error:
    throw zkexcept::magic_not_found_error();
}

Binary::Elf::Elf()
    :elf_memmap(nullptr), elf_pathname(nullptr), elf_baseaddr(0), 
    elf_ehdr(nullptr), elf_phdr(nullptr), elf_shdr(nullptr), elf_size(0),
    elf_dynamic(nullptr), elf_symtab(nullptr), elf_dynsym(nullptr),
    elf_dynstr(nullptr), elf_strtab(nullptr)
{}

Binary::Elf::Elf(const char *pathname)
    :elf_memmap(nullptr), elf_pathname(pathname), elf_baseaddr(0),
    elf_ehdr(nullptr), elf_phdr(nullptr), elf_shdr(nullptr), elf_size(0),
    elf_dynamic(nullptr), elf_symtab(nullptr), elf_dynsym(nullptr),
    elf_dynstr(nullptr), elf_strtab(nullptr)
{
    try{
        OpenElf();
        LoadFile();
        return;
    } catch (std::exception& e) {
        std::cerr << e.what();
        std::exit(1);
    }
}

Binary::Elf::~Elf()
{
    try{
        RemoveMap();
    } catch(std::exception& e){
        std::cout << e.what();
        std::abort();
    }
}

void Binary::Elf::OpenElf(void)
{
    assert(elf_pathname != nullptr && "pathname is not specified");

    elf_fd = open(elf_pathname, O_RDONLY);
    if(elf_fd < 0)
        throw zkexcept::file_not_found_error();

    struct stat st;
    if(fstat(elf_fd, &st) < 0)
        throw std::runtime_error("fstat failed");

    elf_size = st.st_size;
}

void Binary::Elf::LoadFile(void)
{
    assert(elf_fd != 0 && "file descriptor is empty");

    elf_memmap = mmap(elf_memmap, elf_size, PROT_READ | PROT_WRITE, 
            MAP_PRIVATE, elf_fd, 0);
    if(elf_memmap == MAP_FAILED)
        throw std::runtime_error("mmap failed\n");

    elf_ehdr = (Ehdr *)elf_memmap;
    assert(VerifyElf() != true && "File is not an Elf binary");

    u8 *m = (u8 *)elf_ehdr;
    elf_phdr = (Phdr *)&m[elf_ehdr->e_phoff];
    elf_shdr = (Shdr *)&m[elf_ehdr->e_shoff];

    /* symbol table and string table */
    int symtab_index = 0;
    try{
        symtab_index = GetSectionIndexbyName(".symtab");
        elf_indexes[ELF_SYMTAB_INDEX] = symtab_index;
    } catch (zkexcept::section_not_found_error& e){
        std::cerr << e.what();
        std::exit(1);
    }
    u8 *memmap = (u8 *)elf_memmap;
    elf_symtab = (Symtab *)&memmap[elf_shdr[symtab_index].sh_offset];
    elf_indexes[ELF_STRTAB_INDEX] = elf_shdr[symtab_index].sh_link;
    elf_strtab = (Strtab)&memmap[elf_shdr[elf_indexes[ELF_STRTAB_INDEX]].
        sh_offset];
}

void Binary::Elf::LoadDynamicData(void)
{
    int dynamic_index = 0;
    try{
        dynamic_index = GetSectionIndexbyName(".dynamic");
        elf_indexes[ELF_DYNAMIC_INDEX] = dynamic_index;
    } catch (zkexcept::section_not_found_error& e){
        std::cerr << e.what();
        std::exit(1);
    }

    u8 *memmap = (u8 *)elf_memmap;
    elf_dynamic = (Dynamic *)&memmap[elf_shdr[dynamic_index].sh_offset];
    elf_indexes[ELF_DYNSTR_INDEX] = elf_shdr[dynamic_index].sh_link;
    elf_dynstr = (Strtab) &memmap[elf_shdr[elf_indexes[ELF_DYNSTR_INDEX]].
        sh_offset];
    int dynsym_index = 0;
    try{
        dynsym_index = GetSectionIndexbyName(".dynsym");
        elf_indexes[ELF_DYNSYM_INDEX] = dynsym_index;
    } catch (zkexcept::section_not_found_error& e){
        std::cerr << e.what();
        std::exit(1);
    }

    elf_dynsym = (Symtab *)&memmap[elf_shdr[dynsym_index].sh_offset];
}

bool Binary::Elf::VerifyElf(void) const
{
    if(elf_ehdr->e_ident[0] != 0x7f || elf_ehdr->e_ident[1] != 0x45 ||
            elf_ehdr->e_ident[2] != 0x4c || elf_ehdr->e_ident[4] != 0x46)
    {
        return false;
    }
    return true;
}

u16 Binary::Elf::GetElfType(void) const
{
    return elf_ehdr->e_type;
}

void Binary::Elf::RemoveMap(void)
{
    assert(elf_memmap != nullptr && "memory is not mapped to unmap");
    if(munmap(elf_memmap, elf_size) < 0)
        throw std::runtime_error("munmap failed");

    elf_memmap = nullptr;
}

int Binary::Elf::GetSegmentIndexbyAttr(u32 type, u32 flags) const
{
    for(int i = 0; i < elf_ehdr->e_phnum; i++){
        if(elf_phdr[i].p_type == type && elf_phdr[i].p_flags == flags){
            return i;
        }
    }
    throw zkexcept::segment_not_found_error();
}

int Binary::Elf::GetSectionIndexbyAttr(u32 type, u32 flags) const
{
    for(int i = 0; i < elf_ehdr->e_shnum; i++){
        if(elf_shdr[i].sh_type == type && elf_shdr[i].sh_flags == 
                flags)
            return i;
    }
    throw zkexcept::section_not_found_error();
}

/* duh you cant get a segment by name */

int Binary::Elf::GetSectionIndexbyName(const char *name) const
{
    if(elf_ehdr->e_shstrndx == 0)
        throw zkexcept::stripped_binary_error("section header string    \
                table not found");
    Strtab memmap = (Strtab)elf_memmap;
    Strtab shstrtab = &memmap[elf_shdr[elf_ehdr->e_shstrndx].sh_offset];
    for(int i = 0; i< elf_ehdr->e_shnum; i++){
        if(strcmp(&shstrtab[elf_shdr[i].sh_name], name) == 0){
            return i;
        }
    }
    throw zkexcept::section_not_found_error();
}

int Binary::Elf::GetSymbolIndexbyName(const char *name)
    const
{
    int index = elf_indexes[ELF_SYMTAB_INDEX];
    for(int i = 0; i < elf_shdr[index].sh_size / sizeof(Symtab); i++){
        if(strcmp(&elf_strtab[elf_symtab[i].st_name], name) == 0){
            return i;
        }
    }
    throw zkexcept::symbol_not_found_error();
}

int Binary::Elf::GetDynSymbolIndexbyName(const char *name)
    const
{
    assert(elf_indexes[ELF_DYNSYM_INDEX] != 0 && 
            "dynamic sections are not parsed\n");
    int index = elf_indexes[ELF_DYNSTR_INDEX];
    for(int i = 0; i < elf_shdr[index].sh_size / sizeof(Symtab); i++){
        if(strcmp(&elf_dynstr[elf_dynsym[i].st_name], name) == 0){
            return i;
        }
    }
    throw zkexcept::symbol_not_found_error();
}

void *Binary::Elf::ElfRead(off_t readoff, size_t size) const
{
    u8 *buffer = (u8 *)calloc(size, sizeof(u8));
    if(buffer == nullptr)
        throw std::bad_alloc();

    u8 *memmap = (u8 *)elf_memmap;
    for(int i = readoff; i < readoff + size; i++){
        buffer[i] = memmap[i];
    }
    /* im not responsible for freeing these shits */
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
