#ifndef ZKTYPES_HH
#define ZKTYPES_HH

#include <cstdint>
#include <elf.h>

typedef uint64_t    u64;
typedef uint32_t    u32;
typedef uint16_t    u16;
typedef uint8_t     u8;

/* architecture specific types */
#if defined(__x86_64__) || defined (__aarch64__)

    #define __BITS_64__
    typedef Elf64_Ehdr  Ehdr;
    typedef Elf64_Phdr  Phdr;
    typedef Elf64_Shdr  Shdr;
    typedef Elf64_Dyn   Dynamic;
    typedef Elf64_Sym   Symtab;
    typedef Elf64_Nhdr  Note;
    typedef Elf64_Rela  Relocation;
    typedef Elf64_Addr  Addr;

    #define RELOC_TYPE  SHT_RELA
    #define RELOC_PLT   ".rela.plt"
    #define RELOC_DYN   ".rela.dyn"
    #define ADDR_LEN    16

    #ifndef ELF_R_SYM
    #define ELF_R_SYM     ELF64_R_SYM
    #endif /* ELF_R_SYM */

#elif(__i386__)

    #define __BITS_32__
    typedef Elf32_Ehdr  Ehdr;
    typedef Elf32_Phdr  Phdr;
    typedef Elf32_Shdr  Shdr;
    typedef Elf32_Dyn   Dynamic;
    typedef Elf32_Sym   Symtab;
    typedef Elf32_Nhdr  Note;
    typedef Elf32_Rel   Relocation;
    typedef Elf32_Addr  Addr;

    #define RELOC_TYPE  SHT_REL
    #define RELOC_PLT   ".rel.plt"
    #define RELOC_DYN   ".rel.dyn"
    #define ADDR_LEN    8

    #ifndef ELF_R_SYM
    #define ELF_R_SYM   ELF32_R_SYM
    #endif /* ELF_R_SYM */

#endif /* (__x86_64__) */

typedef char *      Strtab;

/* macros and struff */
#define MAGIC_LEN   3   /* for magic numbers */

#endif /* ZKTYPES_HH */
