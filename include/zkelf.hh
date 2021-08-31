#ifndef ZKELF_HH
#define ZKELF_HH

#include "zkexcept.hh"
#include "zktypes.hh"
#include <cstddef>
#include <cstdlib>
#include <cstdint>
#include <elf.h>
#include <new>
#include <string.h>
#include <iostream>
#include <exception>
#include <fcntl.h>
#include <assert.h>
#include <stdexcept>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#define PAGE_SIZE   sysconf(_SC_PAGESIZE);

namespace Binary{
    /* class which defines important parts of an elf binary */
    class Elf {
        protected:
            int     elf_fd;
            /* memory mapped elf binary */
            void    *elf_memmap;
            /* load address of elf */
            u64     elf_baseaddr;
            /* elf header */
            Ehdr    *elf_ehdr;
            /* elf program header table */
            Phdr    *elf_phdr;
            /* elf section header table */
            Shdr    *elf_shdr;
            /* elf symbol table */
            Symtab  *elf_symtab;
            /* elf symbol string table */
            Strtab  elf_strtab;
            /* elf dynamic symbol table optional */
            Dynamic *elf_dynamic;
            /* elf dynamic symtab optional */
            Symtab  *elf_dynsym;
            /* elf dynamic string table optional */
            Strtab  elf_dynstr;

            enum ELF_SHDR_TABLE{
                ELF_SYMTAB_INDEX,
                ELF_STRTAB_INDEX,
                ELF_SHSTRTAB_INDEX, 
                ELF_DYNAMIC_INDEX,
                ELF_DYNSYM_INDEX,
                ELF_DYNSTR_INDEX, 
                ELF_INDEX_TABLE_SIZE,
            };

            int elf_indexes[ELF_INDEX_TABLE_SIZE];
        public:
            const char *elf_pathname;
            size_t  elf_size;

            Elf();
            Elf(const char *pathname);
            ~Elf();
            void OpenElf(void);
            void LoadFile(void);
            void LoadDynamicData(void);
            bool VerifyElf(void) const;
            void RemoveMap(void);
            /* commonly used malware stuff */
            u16 GetElfType(void) const;
            inline Ehdr *GetElfHeader() const
            {
                return elf_ehdr;
            }

            inline Shdr *GetSectionHeaderTable() const
            {
                return elf_shdr;
            }

            inline Phdr *GetProgramHeaderTable() const
            {
                return elf_phdr;
            }

            inline Shdr *GetSectionbyIndex(int index) const
            {
                return &elf_shdr[index];
            }

            inline void SetEntryPoint(Addr fake_entry) const
            {
                elf_ehdr->e_entry = fake_entry;
            }

            int GetSegmentIndexbyAttr(u32 type, u32 flags) const;
            int GetSectionIndexbyAttr(u32 tyoe, u32 flags) const;
            int GetSymbolIndexbyName(const char *name) const;
            int GetDynSymbolIndexbyName(const char *name) const;
            int GetSectionIndexbyName(const char *name) const;
            void *ElfRead(off_t readoff, size_t size) const;
            void ElfWrite(void *buffer, off_t writeoff, size_t size) const;
    };
   /* data segment infection */

    /* reverse text padding infection */

    /* patch addresses and shit */
    void PatchAddress(u8 *buffer, size_t len, Addr addr, u8 *magic);
};

#endif /* ZKELF_HH */
