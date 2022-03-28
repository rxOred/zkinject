#ifndef ZKTYPES_HH
#define ZKTYPES_HH

#include <cstdint>
#include <string>
//#include <elf.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>

#include <zkinject/zktypes.hh>

/*
** TODO
** move all the template implementations to header files
** make all single lined functions non-inline
** make all functions less than 10 lines inline
*/

struct zktypes {
    using u8_t = std::uint8_t;
    using i8_t = std::int8_t;
    using u16_t = std::uint16_t;
    using u32_t = std::uint32_t;
    using i32_t = std::int32_t;
    using u64_t = std::uint64_t;
    using i64_t = std::int64_t;
};

struct x86 : public zktypes {
    using addr_t = std::uint32_t;
    using saddr_t = std::int64_t;
    using off_t = std::uint32_t;
};

struct x64 : public zktypes {
    using addr_t = std::uint64_t;
    using saddr_t = std::int64_t;
    using off_t = std::uint64_t;
};

using eventcodes_t      = __ptrace_eventcodes;
// TODO make this independant
using registers_t       = struct user_regs_struct;



/*
        using ehdr64_t          = Elf64_Ehdr;
        using phdr64_t          = Elf64_Phdr;
        using shdr64_t          = Elf64_Shdr;
        using dynamic64_t       = Elf64_Dyn;
        using symtab64_t        = Elf64_Sym;
        using note64_t          = Elf64_Nhdr;
        using relocation64_t    = Elf64_Rela;
        using addr64_t          = Elf64_Addr;

        using  ehdr32_t         = Elf32_Ehdr;
        using  phdr32_t         = Elf32_Phdr;
        using  shdr32_t         = Elf32_Shdr;
        using  dynamic32_t      = Elf32_Dyn;
        using  symtab32_t       = Elf32_Sym;
        using  note32_t         = Elf32_Nhdr;
        using  relocation32_t   = Elf32_Rel;
        using  addr32_t         = Elf32_Addr;

        // NOTE that since we are using char *, someone can make a special elf
        // binary with 1 less null terminator at the end and fuck us up.
        // so validate it
        using strtab_t          = char *;
        using eventcodes_t      = __ptrace_eventcodes;
        using registers_t       = struct user_regs_struct;

        // typedefs for processes. zkinject
        #if defined(__x86_64__)
            using ehdr_t          = Elf64_Ehdr;
            using phdr_t          = Elf64_Phdr;
            using shdr_t          = Elf64_Shdr;
            using dynamic_t       = Elf64_Dyn;
            using symtab_t        = Elf64_Sym;
            using note_t          = Elf64_Nhdr;
            using relocation_t    = Elf64_Rela;
            using addr_t          = Elf64_Addr;

            #define ADDR_LEN    8
        #elif defined(__i386__)
            using  ehdr_t         = Elf32_Ehdr;
            using  phdr_t         = Elf32_Phdr;
            using  shdr_t         = Elf32_Shdr;
            using  dynamic_t      = Elf32_Dyn;
            using  symtab_t       = Elf32_Sym;
            using  note_t         = Elf32_Nhdr;
            using  relocation_t   = Elf32_Rel;
            using  addr_t         = Elf32_Addr;

            #define ADDR_LEN    4
        #endif

        */
#endif  // ZKTYPES_HH
