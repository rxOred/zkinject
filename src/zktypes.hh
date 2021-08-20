#ifndef ZKTYPES_HH
#define ZKTYPES_HH

#include <cstdint>
#include <elf.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint8_t u8;

typedef Elf64_Ehdr ehdr64;
typedef Elf64_Phdr phdr64;
typedef Elf64_Shdr shdr64;
typedef Elf64_Dyn dynamic64;
typedef Elf64_Nhdr note64;
typedef Elf64_Rela rela64;

#endif
