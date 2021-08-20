#ifndef ZKTYPES_HH
#define ZKTYPES_HH

#include <cstdint>
#include <elf.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint8_t u8;

#if defined(__x86_64__)

    typedef Elf64_Ehdr  Ehdr;
    typedef Elf64_Phdr  Phdr;
    typedef Elf64_Shdr  Shdr;
    typedef Elf64_Dyn   Dynamic;
    typedef Elf64_Nhdr  Note;
    typedef Elf64_Rela  Rela;

    typedef Elf64_Addr  Addr;

#elif(__i386__)

    typedef Elf32_Ehdr  Ehdr;
    typedef Elf32_Phdr  Phdr;
    typedef Elf32_Shdr  Shdr;
    typedef Elf32_Dyn   Dynamic;
    typedef Elf32_Nhdr  Note;
    typedef Elf32_Rela  Rela;

    typedef Elf32_Addr  Addr;

#endif

#endif /* ZKTYPES_HH */
