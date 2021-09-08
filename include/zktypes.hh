#ifndef ZKTYPES_HH
#define ZKTYPES_HH

#include <string>
#include <cstdint>
#include <elf.h>
#include <sys/ptrace.h>
#include <sys/types.h>

typedef uint64_t    u64;
typedef uint32_t    u32;
typedef uint16_t    u16;
typedef uint8_t     u8;

/* architecture specific types */
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
    #endif /* ELF_R_SYM */

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
    #endif /* ELF_R_SYM */

#endif /* (__x86_64__) */

/* 
 * NOTE that since we are using char *, someone can make a special elf 
 * binary with
 * 1 less null terminator at the end and fuck us up. so validate it
 */
typedef char * strtab_t;

/* 
* a type that represent start and end address of a 
* memory mapped page 
*/ 
class page_t {
        addr_t      page_saddr;
        addr_t      page_eaddr;
        std::string page_permissions;
        std::string page_name;

    public:
        page_t(addr_t saddr, addr_t eaddr, std::string permissions, std::string 
                name)
            :page_saddr(saddr), page_eaddr(eaddr), page_permissions(permissions),
            page_name(name)
        {}

        inline addr_t GetPageStartAddress(void) const
        {
            return page_saddr;
        }

        inline addr_t GetPageEndAddress(void) const
        {
            return page_eaddr;
        }

        inline std::string GetPagePermissions(void) const
        {
            return page_permissions;
        }

        inline std::string GetPageName(void) const
        {
            return page_name;
        }
};

typedef struct user_regs_struct registers_t;

/* macros and struff */
#define MAGIC_LEN   3   /* for magic numbers */

#endif /* ZKTYPES_HH */
