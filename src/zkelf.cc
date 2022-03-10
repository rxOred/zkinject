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

/* TODO narrow down errno to report user about the error that caused expection */

ZkElf::Elf::Elf(ZkElf::ELFFLAGS flags)
    :elf_memmap(nullptr), elf_pathname(nullptr), elf_baseaddr(0), 
    elf_ehdr(nullptr), elf_phdr(nullptr), elf_shdr(nullptr), elf_size(0),
    elf_dynamic(nullptr), elf_symtab(nullptr), elf_dynsym(nullptr),
    elf_dynstr(nullptr), elf_strtab(nullptr), elf_flags(flags)
{}

ZkElf::Elf::Elf(const char *pathname, ZkElf::ELFFLAGS flags)
    :elf_memmap(nullptr), elf_pathname(pathname), elf_baseaddr(0),
    elf_ehdr(nullptr), elf_phdr(nullptr), elf_shdr(nullptr), elf_size(0),
    elf_dynamic(nullptr), elf_symtab(nullptr), elf_dynsym(nullptr),
    elf_dynstr(nullptr), elf_strtab(nullptr), elf_flags(flags)
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
        ZkUtils::SaveMemoryMap(GetPathname(), GetMemoryMap(), 
                GetElfSize());
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

    SetElfSize(st.st_size);
    LoadFile(fd); 
}

/* load the elf binary into memory, parse most essential headers */
void ZkElf::Elf::LoadFile(int fd)
{
    assert(fd != 0 && "file descriptor is empty");

    elf_memmap = mmap(nullptr, GetElfSize(), PROT_READ | PROT_WRITE,
            MAP_PRIVATE, fd, 0);
    if(elf_memmap == MAP_FAILED)
        throw std::runtime_error("mmap failed\n");

    if (close(fd) < 0)
        throw std::runtime_error("close failed\n");
    
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

#ifdef __BITS_64__
    if(elf_ehdr->e_ident[EI_CLASS] == ELFCLASS32) {
        return false;
    }

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

void ZkElf::Elf::SetElfType(u16 new_type)
{
    elf_ehdr->e_type = new_type;
    autoSaveMemoryMap();
}

void ZkElf::Elf::SetElfMachine(u16 new_machine)
{
    elf_ehdr->e_machine = new_machine;
    autoSaveMemoryMap();
}

void ZkElf::Elf::SetElfVersion(u32 new_version)
{
    elf_ehdr->e_version = new_version;
    autoSaveMemoryMap();
}

void ZkElf::Elf::SetElfEntryPoint(addr_t new_entry)
{
    elf_ehdr->e_entry = new_entry;
    autoSaveMemoryMap();
}

void ZkElf::Elf::SetElfPhdrOffset(off_t new_offset)
{
    elf_ehdr->e_phoff = new_offset;
    autoSaveMemoryMap();
}

void ZkElf::Elf::SetElfShdrOffset(off_t new_offset)
{
    elf_ehdr->e_shoff = new_offset;
    autoSaveMemoryMap();
}

void ZkElf::Elf::SetElfFlags(u32 new_flags)
{
    elf_ehdr->e_flags = new_flags;
    autoSaveMemoryMap();
}

void ZkElf::Elf::SetPhdrCount(u16 new_count)
{
    elf_ehdr->e_phnum = new_count;
    autoSaveMemoryMap();
}

void ZkElf::Elf::SetShdrCount(u16 new_count)
{
    elf_ehdr->e_shnum = new_count;
    autoSaveMemoryMap();
}

void ZkElf::Elf::SetShstrndx(u16 new_index)
{
    elf_ehdr->e_shstrndx = new_index;
    autoSaveMemoryMap();
}

void ZkElf::Elf::SetElfHeader(ehdr_t *new_ehdr)
{
    memcpy(elf_ehdr, new_ehdr, GetElfHeaderSize());
    autoSaveMemoryMap();
}

void ZkElf::Elf::SetSectionNameIndex(int shdr_index, int new_index)
{
    elf_shdr[shdr_index].sh_name = new_index;
    autoSaveMemoryMap();
}
void ZkElf::Elf::SetSectionType(int shdr_index, u32 new_type)
{
    elf_shdr[shdr_index].sh_type = new_type;
    autoSaveMemoryMap();
}
void ZkElf::Elf::SetSectionAddress(int shdr_index, addr_t new_addr)
{
    elf_shdr[shdr_index].sh_addr = new_addr;
    autoSaveMemoryMap();
}
void ZkElf::Elf::SetSectionOffset(int shdr_index, off_t new_offset)
{
    elf_shdr[shdr_index].sh_offset = new_offset;
    autoSaveMemoryMap();
}

#ifdef __x86_64__
void ZkElf::Elf::SetSectionSize(int shdr_index, u64 new_size)
{
    elf_shdr[shdr_index].sh_size = new_size;
    autoSaveMemoryMap();
}
void ZkElf::Elf::SetSectionAddressAlign(int shdr_index, u64 new_address_align)
{
    elf_shdr[shdr_index].sh_addralign = new_address_align;
    autoSaveMemoryMap();
}
void ZkElf::Elf::SetSectionEntrySize(int shdr_index, u64 new_size)
{
    elf_shdr[shdr_index].sh_entsize = new_size;
    autoSaveMemoryMap();
}

#elif __i386__
void ZkElf::Elf::SetSectionSize(int shdr_index, u32 new_size)
{
    elf_shdr[shdr_index].sh_size = new_size;
    autoSaveMemoryMap();
}
void ZkElf::Elf::SetSectionAddressAlign(int shdr_index, u32 new_address_align)
{
    elf_shdr[shdr_index].sh_addralign = new_address_align;
    autoSaveMemoryMap();
}
void ZkElf::Elf::SetSectionEntrySize(int shdr_index, u32 new_size)
{
    elf_shdr[shdr_index].sh_entsize = new_size;
    autoSaveMemoryMap();
}

#endif

void ZkElf::Elf::SetSectionHeader(int shdr_index, shdr_t *new_shdr)
{
    memcpy(&elf_shdr[shdr_index], new_shdr, GetElfShdrEntrySize());
    autoSaveMemoryMap();
}

void ZkElf::Elf::SetSectionData(int shdr_index, void *data)
{
    auto offset = GetSectionOffset(shdr_index);
    memcpy(((u8 *)GetMemoryMap() + offset), data, GetSectionSize(shdr_index));
    autoSaveMemoryMap();
}

void ZkElf::Elf::SetSegmentType(int phdr_index, u32 new_type)
{
    elf_phdr[phdr_index].p_type = new_type;
    autoSaveMemoryMap();

}
void ZkElf::Elf::SetSegmentOffset(int phdr_index, off_t new_offset)
{
    elf_phdr[phdr_index].p_offset = new_offset;
    autoSaveMemoryMap();
}
void ZkElf::Elf::SetSegmentVAddress(int phdr_index, addr_t new_address)
{
    elf_phdr[phdr_index].p_vaddr = new_address;
    autoSaveMemoryMap();
}
void ZkElf::Elf::SetSegmentPAddress(int phdr_index, addr_t new_address)
{
    elf_phdr[phdr_index].p_paddr = new_address;
    autoSaveMemoryMap();
}
void ZkElf::Elf::SetSegmentFlags(int phdr_index, u32 new_flags)
{
    elf_phdr[phdr_index].p_flags = new_flags;
    autoSaveMemoryMap();
}
#ifdef __x86_64__
void ZkElf::Elf::SetSegmentFileSize(int phdr_index, u64 new_size)
{
    elf_phdr[phdr_index].p_filesz = new_size;
    autoSaveMemoryMap();
}
void ZkElf::Elf::SetSegmentMemorySize(int phdr_index, u64 new_size)
{
    elf_phdr[phdr_index].p_memsz = new_size;
    autoSaveMemoryMap();
}
void ZkElf::Elf::SetSegmentAlignment(int phdr_index, u64 new_alignment)
{
    elf_phdr[phdr_index].p_align = new_alignment;
    autoSaveMemoryMap();
}
#elif __i386__
void ZkElf::Elf::SetSegmentFileSize(int phdr_index, u32 new_size)
{
    elf_phdr[phdr_index].p_filesz = new_size;
    autoSaveMemoryMap();
}
void ZkElf::Elf::SetSegmentMemorySize(int phdr_index, u32 new_size)
{
    elf_phdr[phdr_index].p_memsz = new_size;
    autoSaveMemoryMap();
}
void ZkElf::Elf::SetSegmentAlignment(int phdr_index, u32 new_alignment)
{
    elf_phdr[phdr_index].p_align = new_alignment;
    autoSaveMemoryMap();
}
#endif

void ZkElf::Elf::SetSegmentHeader(int phdr_index, phdr_t *new_phdr)
{
    memcpy(&elf_phdr[phdr_index], new_phdr, sizeof(phdr_t));
    autoSaveMemoryMap();
}

void ZkElf::Elf::SetSegmentData(int phdr_index, void *data)
{
    auto offset = GetSegmentOffset(phdr_index);
    memcpy(((u8 *)GetMemoryMap() + offset), data, GetSegmentFileSize(phdr_index));
    autoSaveMemoryMap();
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
    autoSaveMemoryMap();
}

void ZkElf::Elf::autoSaveMemoryMap(void) const
{
    if (elf_flags == ELF_AUTO_SAVE) {
        remove(GetPathname());
        ZkUtils::SaveMemoryMap(GetPathname(), GetMemoryMap(), GetElfSize());
    }
}
