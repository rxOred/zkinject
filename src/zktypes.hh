#ifndef ZKTYPES_HH
#define ZKTYPES_HH

#include <cstdint>
#include <elf.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint8_t u8;

/* architecture specific types */
#if defined(__x86_64__)

    typedef Elf64_Ehdr  Ehdr;
    typedef Elf64_Phdr  Phdr;
    typedef Elf64_Shdr  Shdr;
    typedef Elf64_Dyn   Dynamic;
    typedef Elf64_Sym   Symtab;
    typedef char *      Strtab;
    typedef Elf64_Nhdr  Note;
    typedef Elf64_Rela  Relocation;
    typedef Elf64_Addr  Addr;
    #define ADDR_LEN    16
#elif(__i386__)

    typedef Elf32_Ehdr  Ehdr;
    typedef Elf32_Phdr  Phdr;
    typedef Elf32_Shdr  Shdr;
    typedef Elf32_Dyn   Dynamic;
    typedef Elf32_Nhdr  Note;
    typedef Elf32_Rela  Relocation;
    typedef Elf32_Addr  Addr;
    #define ADDR_LEN    8
#endif

/* macros and struff */
#define MAGIC_LEN   2   /* for magic numbers */

#endif /* ZKTYPES_HH */
