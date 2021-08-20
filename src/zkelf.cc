#include "zkelf.hh"
#include "zkerr.hh"
#include "zktypes.hh"
#include <elf.h>
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
{}

void Binary::Elf::OpenElf(void)
{
    assert(elf_pathname != nullptr && "pathname is not specified");

    elf_fd = open(elf_pathname, O_RDONLY);
    if(elf_fd < 0)
        ERROR(std::runtime_error("open failed"));

    struct stat st;
    if(fstat(elf_fd, &st) < 0)
        ERROR(std::runtime_error("fstat failed"));

    elf_size = st.st_size;
}

void Binary::Elf::LoadFile(void)
{
    assert(elf_fd != 0 && "file descriptor is empty");

    elf_memmap = mmap(elf_memmap, elf_size, PROT_READ | PROT_WRITE, 
            MAP_PRIVATE, elf_fd, 0);
    if(elf_memmap == MAP_FAILED)
        ERROR(std::runtime_error("mmap failed"));

    elf_ehdr = (Elf64_Ehdr *)elf_memmap;
    CheckType()
}
