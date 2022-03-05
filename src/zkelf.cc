#include "zkelf.hh"
#include "zkexcept.hh"
#include "zktypes.hh"
#include "zkutils.hh"
#include <asm-generic/errno-base.h>
#include <cerrno>
#include <elf.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

void ZkElf::Elf::PatchAddress(u8 *buffer, size_t len, u64 addr, 
        u8 *magic)
{
    int count = 0;
    for (int i = 0; i < len; i++){
        printf("%x\n", buffer[i]);
        if(buffer[i] == magic[0]){
            for (int j = 0; j < MAGIC_LEN; j++){
                if(buffer[i + j] == magic[j])
                    count++;
            }
            if(count == MAGIC_LEN)
                *(u64 *)((void *)(buffer + i)) = addr;
            else
                continue;
        }
    }
error:
    throw zkexcept::magic_not_found_error();
}

ZkElf::Elf::Elf(ZkElf::ELFFLAGS flags)
    :elf_memmap(nullptr), elf_pathname(nullptr), elf_baseaddr(0), 
    elf_ehdr(nullptr), elf_phdr(nullptr), elf_shdr(nullptr), elf_size(0),
    elf_dynamic(nullptr), elf_symtab(nullptr), elf_dynsym(nullptr),
    elf_dynstr(nullptr), elf_strtab(nullptr), elf_flags(flags)
{}

ZkElf::Elf::Elf(const char *pathname)
    :elf_memmap(nullptr), elf_pathname(pathname), elf_baseaddr(0),
    elf_ehdr(nullptr), elf_phdr(nullptr), elf_shdr(nullptr), elf_size(0),
    elf_dynamic(nullptr), elf_symtab(nullptr), elf_dynsym(nullptr),
    elf_dynstr(nullptr), elf_strtab(nullptr)
{
    try{
        OpenElf();
        return;
    } catch (std::exception& e) {
        std::cerr << e.what();
        std::exit(1);
    }
}

ZkElf::Elf::~Elf()
{
    if (elf_flags == ELF_SAVE_AT_EXIT) {
        SaveElf();
    }
    try{
        RemoveMap();
    } catch(std::exception& e){
        std::cout << e.what();
        std::abort();
    }
}

void ZkElf::Elf::OpenElf(void)
{
    assert(elf_pathname != nullptr && "pathname is not specified");

    int fd = open(elf_pathname, O_RDONLY);
    if(fd < 0)
        throw zkexcept::file_not_found_error();

    struct stat st;
    if(fstat(fd, &st) < 0)
        throw std::runtime_error("fstat failed");

    elf_size = st.st_size;
    LoadFile(fd); 
}

/* load the elf binary into memory, parse most essential headers */
void ZkElf::Elf::LoadFile(int fd)
{
    assert(fd != 0 && "file descriptor is empty");

    elf_memmap = mmap(elf_memmap, elf_size, PROT_READ | PROT_WRITE, 
            MAP_PRIVATE, fd, 0);
    if(elf_memmap == MAP_FAILED)
        throw std::runtime_error("mmap failed\n");

    close(fd);
    
    elf_ehdr = (ehdr_t *)elf_memmap;
    assert(VerifyElf() != true && "File is not an Elf binary");

    u8 *m = (u8 *)elf_memmap;
    assert(elf_ehdr->e_phoff < elf_size && 
            "Anomaly detected in program header offset");
    elf_phdr = (phdr_t *)&m[elf_ehdr->e_phoff];
        assert(elf_ehdr->e_shoff < elf_size && 
            "Anomaly detected in section header offset");
    elf_shdr = (shdr_t *)&m[elf_ehdr->e_shoff];

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
    elf_symtab = (symtab_t *)&memmap[elf_shdr[symtab_index].sh_offset];
    elf_indexes[ELF_STRTAB_INDEX] = elf_shdr[symtab_index].sh_link;
    elf_strtab = (strtab_t)&memmap[elf_shdr[elf_indexes[ELF_STRTAB_INDEX]].
        sh_offset];
}

void ZkElf::Elf::LoadDynamicData(void)
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
    elf_dynamic = (dynamic_t *)&memmap[elf_shdr[dynamic_index].sh_offset];
    elf_indexes[ELF_DYNSTR_INDEX] = elf_shdr[dynamic_index].sh_link;
    elf_dynstr = (strtab_t) &memmap[elf_shdr[elf_indexes[ELF_DYNSTR_INDEX]]
        .sh_offset];
    int dynsym_index = 0;
    try{
        dynsym_index = GetSectionIndexbyName(".dynsym");
        elf_indexes[ELF_DYNSYM_INDEX] = dynsym_index;
    } catch (zkexcept::section_not_found_error& e){
        std::cerr << e.what();
        std::exit(1);
    }

    elf_dynsym = (symtab_t *)&memmap[elf_shdr[dynsym_index].sh_offset];
}

bool ZkElf::Elf::VerifyElf(void) const
{
    if(elf_ehdr->e_ident[0] != 0x7f || elf_ehdr->e_ident[1] != 0x45 ||
            elf_ehdr->e_ident[2] != 0x4c || elf_ehdr->e_ident[4] != 0x46)
    {
        return false;
    }

// if libzkinject.so is compiled in a 64 bit envirnment, it cant parse 
// 32bit elf binaries
#ifdef __BITS_64__
    if(elf_ehdr->e_ident[EI_CLASS] == ELFCLASS32) {
        return false;
    }

// if libzkinject.so is compiled in a 32 bit envirnment, it cant parse 
// 64bit elf binaries
#elif __BITS32__
    if(elf_ehdr->e_ident[EI_CLASS] == ELFCLASS64) {
        return false;
    }
#endif
    return true;
}

void ZkElf::Elf::RemoveMap(void)
{
    assert(elf_memmap != nullptr && "memory is not mapped to unmap");
    if(munmap(elf_memmap, elf_size) < 0)
        throw std::runtime_error("munmap failed");

    elf_memmap = nullptr;
}

int ZkElf::Elf::GetSegmentIndexbyAttr(u32 type, u32 flags, u32 prev_flags)
    const
{
    for(int i = 0; i < elf_ehdr->e_phnum; i++){
        if(elf_phdr[i].p_type == type && elf_phdr[i].p_flags == flags){
            if(prev_flags != 0){
                if(elf_phdr[i - 1].p_flags == prev_flags)
                    return i;
            } else
                return i;
        }
    }
    throw zkexcept::segment_not_found_error();
}

int ZkElf::Elf::GetSectionIndexbyAttr(u32 type, u32 flags) const
{
    for(int i = 0; i < elf_ehdr->e_shnum; i++){
        if(elf_shdr[i].sh_type == type && elf_shdr[i].sh_flags == 
                flags)
            return i;
    }
    throw zkexcept::section_not_found_error();
}

/* duh you cant get a segment by name */

int ZkElf::Elf::GetSectionIndexbyName(const char *name) const
{
    if(elf_ehdr->e_shstrndx == 0)
        throw zkexcept::stripped_binary_error("section header string    \
                table not found");
    strtab_t memmap = (strtab_t)elf_memmap;
    strtab_t shstrtab = &memmap[elf_shdr[elf_ehdr->e_shstrndx].sh_offset];
    for(int i = 0; i< elf_ehdr->e_shnum; i++){
        if(strcmp(&shstrtab[elf_shdr[i].sh_name], name) == 0){
            return i;
        }
    }
    throw zkexcept::section_not_found_error();
}

int ZkElf::Elf::GetSymbolIndexbyName(const char *name)
    const
{
    int index = elf_indexes[ELF_SYMTAB_INDEX];
    for(int i = 0; i < elf_shdr[index].sh_size / sizeof(symtab_t); i++){
        if(strcmp(&elf_strtab[elf_symtab[i].st_name], name) == 0){
            return i;
        }
    }
    throw zkexcept::symbol_not_found_error();
}

int ZkElf::Elf::GetDynSymbolIndexbyName(const char *name)
    const
{
    assert(elf_indexes[ELF_DYNSYM_INDEX] != 0 && 
            "dynamic sections are not parsed\n");
    int index = elf_indexes[ELF_DYNSTR_INDEX];
    for(int i = 0; i < elf_shdr[index].sh_size / sizeof(symtab_t); i++){
        if(strcmp(&elf_dynstr[elf_dynsym[i].st_name], name) == 0){
            return i;
        }
    }
    throw zkexcept::symbol_not_found_error();
}

void *ZkElf::Elf::ElfRead(off_t readoff, size_t size) const
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

void ZkElf::Elf::ElfWrite(void *buffer, off_t writeoff, size_t size) 
    const
{
    u8 *memmap = (u8 *)elf_memmap;
    u8 *_buffer = (u8 *)buffer;
    for(int i = 0; i < writeoff + size; i++){
        _buffer[i] = memmap[i];
    }
    SaveBufferToDisk(elf_pathname, writeoff, buffer, size);
}

void ZkElf::Elf::SaveElf(void) const
{
    int fd = open(GetPathname(), O_CREAT | O_TRUNC | O_WRONLY, 0666);
    if (fd < 0) {
        throw zkexcept::file_not_found_error();
    }

    if (write(fd, elf_memmap, GetElfSize()) < GetElfSize()) {
        throw zkexcept::file_not_found_error();
    }
}

void ZkElf::Elf::SaveBufferToDisk(const char *pathname, off_t offset, 
        void *buffer, int buffer_size) const
{
    int fd = open(pathname, O_CREAT | O_WRONLY, 0666);
    if (fd < 0)
        throw zkexcept::file_not_found_error();

    if (pwrite(fd, buffer, buffer_size, offset) < buffer_size) {
        throw zkexcept::file_not_found_error();
    }
}
