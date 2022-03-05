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
#include <unistd.h>
#include <assert.h>
#include <stdexcept>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#define AUTOSAVE                                                    \
    if(elf_flags ==  ELF_AUTO_SAVE) {                               \
        SaveElf()                                                   \
    }

namespace ZkElf {

    enum ELFFLAGS : u8 {
        ELF_AUTO_SAVE,
        ELF_SAVE_AT_EXIT,
        ELF_NO_SAVE
    };

    class Elf {
        protected:
            ELFFLAGS      elf_flags;

            const char *elf_pathname;

            size_t      elf_size;

            void        *elf_memmap;

            u64     elf_baseaddr;

            ehdr_t    *elf_ehdr;

            phdr_t    *elf_phdr;

            shdr_t    *elf_shdr;

            symtab_t *elf_symtab;

            strtab_t  elf_strtab;

            dynamic_t *elf_dynamic;

            symtab_t  *elf_dynsym;

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
            void LoadFile(int fd);
        public:
            Elf(ELFFLAGS flags);

            Elf(const char *pathname);
            ~Elf();

            void OpenElf(void);

            inline const char *GetPathname(void) const 
            {
                return elf_pathname;
            }

            inline int GetElfSize(void) const
            {
                return elf_size;
            }

            void LoadDynamicData(void);
            bool VerifyElf(void) const;
            void RemoveMap(void);

            virtual bool CheckElfType() const 
            { 
                return true;
            }

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

            inline void SetEntryPoint(addr_t new_entry) const
            {
                elf_ehdr->e_entry = new_entry;
            }

            int GetSegmentIndexbyAttr(u32 type, u32 flags, u32 prev_flags) 
                const;
            int GetSectionIndexbyAttr(u32 tyoe, u32 flags) const;
            int GetSymbolIndexbyName(const char *name) const;
            int GetDynSymbolIndexbyName(const char *name) const;
            int GetSectionIndexbyName(const char *name) const;

            void *ElfRead(off_t readoff, size_t size) const;
            void ElfWrite(void *buffer, off_t writeoff, size_t size) const;

            void PatchAddress(u8 *buffer, size_t len, addr_t addr, u8 *magic);

            void SaveElf(void) const;
            void SaveBufferToDisk(const char *pathname, off_t offset, void 
                *buffer, int buffer_size) const;
    };

};

#endif /* ZKELF_HH */
