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

//#define PAGE_SIZE   sysconf(_SC_PAGESIZE);

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
            ehdr_t    *elf_ehdr;
            /* elf program header table */
            phdr_t    *elf_phdr;
            /* elf section header table */
            shdr_t    *elf_shdr;
            /* elf symbol table */
            symtab_t *elf_symtab;
            /* elf symbol string table */
            strtab_t  elf_strtab;
            /* elf dynamic symbol table optional */
            dynamic_t *elf_dynamic;
            /* elf dynamic symtab optional */
            symtab_t  *elf_dynsym;
            /* elf dynamic string table optional */
            strtab_t  elf_dynstr;

            enum ELF_SHDR_TABLE : short{
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
            size_t      elf_size;

            Elf();
            Elf(const char *pathname);
            ~Elf();
            void OpenElf(void);
            void LoadFile(void);
            void LoadDynamicData(void);
            bool VerifyElf(void) const;
            void RemoveMap(void);

            virtual bool CheckElfType() const = 0;

            /* commonly used malware stuff */
            inline u16 GetElfType(void) const { return elf_ehdr->e_type; }
 
            inline ehdr_t *GetElfHeader() const { return elf_ehdr; }

            inline shdr_t *GetSectionHeaderTable() const { return elf_shdr; }

            inline phdr_t *GetProgramHeaderTable() const { return elf_phdr; }

            /* we allow caller to modify those section headers */
            inline shdr_t& GetSectionbyIndex(const int& index) const
            {
                return elf_shdr[index];
            }

            inline phdr_t& GetSegmentByIndex(const int& index) const
            {
                return elf_phdr[index];
            }

            inline void SetEntryPoint(addr_t fake_entry) const
            {
                elf_ehdr->e_entry = fake_entry;
            }

            int GetSegmentIndexbyAttr(u32 type, u32 flags, u32 prev_flags) 
                const;
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
    void PatchAddress(u8 *buffer, size_t len, addr_t addr, u8 *magic);
};

#endif /* ZKELF_HH */
