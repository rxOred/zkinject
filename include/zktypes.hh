#ifndef ZKTYPES_HH
#define ZKTYPES_HH

#include <string>
#include <cstdint>
#include <elf.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/types.h>

typedef uint64_t    u64_t;
typedef uint32_t    u32_t;
typedef uint16_t    u16_t;
typedef uint8_t     u8_t;

// architecture specific types
#if defined(__x86_64__) || defined (__aarch64__)

    #define __BITS_64__
    typedef Elf64_Ehdr  ehdr_t;
    typedef Elf64_Phdr  phdr_t;
    typedef Elf64_Shdr  shdr_t;
    typedef Elf64_Dyn   dynamic_t;
    typedef Elf64_Sym   symtab_t;
    typedef Elf64_Nhdr  note_t;
    typedef Elf64_Rela  relocation_t;
    typedef Elf64_Addr  addr_t;

    #define RELOC_TYPE  SHT_RELA
    #define RELOC_PLT   ".rela.plt"
    #define RELOC_DYN   ".rela.dyn"
    #define ADDR_LEN    16

    #ifndef ELF_R_SYM
    #define ELF_R_SYM     ELF64_R_SYM
    #endif // ELF_R_SYM

#elif(__i386__)

    #define __BITS_32__
    typedef Elf32_Ehdr  ehdr_t;
    typedef Elf32_Phdr  phdr_t;
    typedef Elf32_Shdr  shdr_t;
    typedef Elf32_Dyn   dynamic_t;
    typedef Elf32_Sym   symtab_t;
    typedef Elf32_Nhdr  note_t;
    typedef Elf32_Rel   relocation_t;
    typedef Elf32_Addr  addr_t;

    #define RELOC_TYPE  SHT_REL
    #define RELOC_PLT   ".rel.plt"
    #define RELOC_DYN   ".rel.dyn"
    #define ADDR_LEN    8

    #ifndef ELF_R_SYM
    #define ELF_R_SYM   ELF32_R_SYM
    #endif // ELF_R_SYM

#endif // (__x86_64__)

// TODO that since we are using char *, someone can make a special elf
// binary with
// 1 less null terminator at the end and fuck us up. so validate it

typedef char * strtab_t;

typedef __ptrace_eventcodes eventcodes_t;
typedef struct user_regs_struct registers_t;

#endif // ZKTYPES_HH
