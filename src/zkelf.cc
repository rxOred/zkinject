#include "zkelf.hh"
#include "zkerr.hh"
#include "zktypes.hh"
#include <iostream>
#include <exception>
#include <string.h>
#include <fcntl.h>
#include <assert.h>
#include <stdexcept>
#include <sys/mman.h>
#include <sys/stat.h>

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

    return 0;
}


void Binary::TextPaddingInfection::FindFreeSpace(int size) const
{
    bool text_found = false;
    for(int i = 0; i < elf_ehdr->e_phnum; i++){
        if(elf_phdr[i].p_type)
    }
}
