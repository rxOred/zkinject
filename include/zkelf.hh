#ifndef ZKELF_HH
#define ZKELF_HH

#include "zkexcept.hh"
#include "zktypes.hh"
#include "zkutils.hh"
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

#define AUTOSAVE                                                             \
    if(elf_flags ==  ELF_AUTO_SAVE) {                                        \
        ZkUtils::SaveMemoryMap(GetPathname(), GetMemoryMap(), GetElfSize()); \
    }

namespace ZkElf {

    enum ELFFLAGS : u8 {
        ELF_AUTO_SAVE,
        ELF_SAVE_AT_EXIT,
        ELF_NO_SAVE
    };

    class Elf {
        protected:
            ELFFLAGS    elf_flags;
            const char  *elf_pathname;
            size_t      elf_size;
            void        *elf_memmap;
            u64         elf_baseaddr;
            ehdr_t      *elf_ehdr;
            phdr_t      *elf_phdr;
            shdr_t      *elf_shdr;
            symtab_t    *elf_symtab;
            strtab_t    elf_strtab;
            dynamic_t   *elf_dynamic;
            symtab_t    *elf_dynsym;
            strtab_t    elf_dynstr;

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
            inline void *GetMemoryMap(void) const
            {
                return elf_memmap;
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
            inline u16 GetElfMachine(void) const { return elf_ehdr->e_machine; }
            inline u32 GetElfVersion(void) const { return elf_ehdr->e_version; }
            inline addr_t GetElfEntryPoint(void) const {return elf_ehdr->e_entry; }
            inline off_t GetElfPhdrOffset(void) const { return elf_ehdr->e_phoff; }
            inline off_t GetElfShdrOffset(void) const { return elf_ehdr->e_shoff; }
            inline u32 GetElfFlags(void) const { return elf_ehdr->e_flags; }
            inline u16 GetElfHeaderSize(void) const { return elf_ehdr->e_ehsize; }
            inline u16 GetElfPhdrEntrySize(void) const { return elf_ehdr->e_phentsize; }
            inline u16 GetElfPhdrEntryCount(void) const { return elf_ehdr->e_phnum; }
            inline u16 GetElfShdrEntrySize(void) const { return elf_ehdr->e_shentsize; }
            inline u16 GetElfShdrEntryCount(void) const { return elf_ehdr->e_shnum; }
            inline u16 GetElfShdrStringTableIndex(void) const
            {
                return elf_ehdr->e_shstrndx;
            }

            inline ehdr_t *GetElfHeader() const { return elf_ehdr; }

            inline u32 GetSectionNameIndex(int shdr_index) const
            {
                return elf_shdr[shdr_index].sh_name;
            }
            inline u32 GetSectionType(int shdr_index) const
            {
                return elf_shdr[shdr_index].sh_type;
            }
            inline addr_t GetSectionAddress(int shdr_index) const
            {
                return elf_shdr[shdr_index].sh_addr;
            }
            inline off_t GetSectionOffset(int shdr_index) const
            {
                return elf_shdr[shdr_index].sh_offset;
            }
#ifdef __x86_64__
            inline u64 GetSectionSize(int shdr_index) const
            {
                return elf_shdr[shdr_index].sh_size;
            }
            inline u64 GetSectionAddressAlign(int shdr_index) const
            {
                return elf_shdr[shdr_index].sh_addralign;
            }
            inline u64 GetSectionEntrySize(int shdr_index) const
            {
                return elf_shdr[shdr_index].sh_entsize;
            }
#elif __i386__
            inline u32 GetSectionSize(int shdr_index) const
            {
                return elf_shdr[shdr_index].sh_size;
            }
            inline u32 GetSectionAddressAlign(int shdr_index) const
            {
                return elf_shdr[shdr_index].sh_addralign;
            }
            inline u32 GetSectionEntrySize(int shdr_index) const
            {
                return elf_shdr[shdr_index].sh_entsize;
            }
#endif
            inline u32 GetSectionLink(int shdr_index) const
            {
                return elf_shdr[shdr_index].sh_link;
            }
            inline u32 GetSectionInfo(int shdr_index) const
            {
                return elf_shdr[shdr_index].sh_info;
            }
            inline shdr_t *GetSectionHeaderTable() const { return elf_shdr; }

            inline u32 GetSegmentType(int phdr_index) const
            {
                return elf_phdr[phdr_index].p_type;
            }
            inline off_t GetSegmentOffset(int phdr_index) const
            {
                return elf_phdr[phdr_index].p_offset;
            }
            inline addr_t GetSegmentVAddress(int phdr_index) const
            {
                return elf_phdr[phdr_index].p_vaddr;
            }
            inline addr_t GetSegmentPAddress(int phdr_index) const
            {
                return elf_phdr[phdr_index].p_paddr;
            }
            inline u32 GetSegmentFlags(int phdr_index) const
            {
                return elf_phdr[phdr_index].p_flags;
            }
#ifdef __x86_64__
            inline u64 GetSegmentFileSize(int phdr_index) const
            {
                return elf_phdr[phdr_index].p_filesz;
            }
            inline u64 GetSegmentMemorySize(int phdr_index) const
            {
                return elf_phdr[phdr_index].p_memsz;
            }
            inline u64 GetSegmentAlignment(int phdr_index) const
            {
                return elf_phdr[phdr_index].p_align;
            }
#elif __i386__
            inline u32 GetSegmentFileSize(int phdr_index) const
            {
                return elf_phdr[phdr_index].p_filesz;
            }
            inline u32 GetSegmentMemorySize(int phdr_index) const
            {
                return elf_phdr[phdr_index].p_memsz;
            }
            inline u32 GetSegmentAlignment(int phdr_index) const
            {
                return elf_phdr[phdr_index].p_align;
            }
#endif

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

            int GetSegmentIndexbyAttr(u32 type, u32 flags, u32 prev_flags) 
                const;
            int GetSectionIndexbyAttr(u32 tyoe, u32 flags) const;
            int GetSymbolIndexbyName(const char *name) const;
            int GetDynSymbolIndexbyName(const char *name) const;
            int GetSectionIndexbyName(const char *name) const;

            inline void SetPathname(const char *new_pathname)
            {
                elf_pathname = new_pathname;
            }
            inline void SetElfSize(int new_size)
            {
                elf_size = new_size;
            }
            void SetElfType(u16 new_tupe);
            void SetElfMachine(u16 new_machine);
            void SetElfVersion(u32 new_version);
            void SetElfEntryPoint(addr_t new_entry);
            void SetElfPhdrOffset(off_t new_offset);
            void SetElfShdrOffset(off_t new_offset);
            void SetElfFlags(u32 new_flags);
            void SetPhdrCount(u16 new_count);
            void SetShdrCount(u16 new_count);
            void SetShstrndx(u16 new_index);

            void SetElfHeader(ehdr_t *new_ehdr);

            void SetSectionNameIndex(int shdr_index, int new_index);
            void SetSectionType(int shdr_index, u32 new_type);
            void SetSectionAddress(int shdr_index, addr_t new_addr);
            void SetSectionOffset(int shdr_index, off_t new_offset);
#ifdef __x86_64__
            void SetSectionSize(int shdr_index, u64 new_size);
            void SetSectionAddressAlign(int shdr_index, u64 new_address_align);
            void SetSectionEntrySize(int shdr_index, u64 new_size);
#elif __i386__
            void SetSectionSize(int shdr_index, u32 new_size);
            void SetSectionAddressAlign(int shdr_index, u32 new_address_align);
            void SetSectionEntrySize(int shdr_index, u32 new_size);
#endif

            void SetSectionHeader(int shdr_index, shdr_t *new_shdr);
            void SetSectionData(int shdr_index, void *data);

            void SetSegmentType(int phdr_index, u32 new_type);
            void SetSegmentOffset(int phdr_index, off_t new_offset);
            void SetSegmentVAddress(int phdr_index, addr_t new_address);
            void SetSegmentPAddress(int phdr_index, addr_t new_address);
            void SetSegmentFlags(int phdr_index, u32 new_flags);
#ifdef __x86_64__
            void SetSegmentFileSize(int phdr_index, u64 new_size);
            void SetSegmentMemorySize(int phdr_index, u64 new_size);
            void SetSegmentAlignment(int phdr_index, u64 new_alignment);
#elif __i386__
            void SetSegmentFileSize(int phdr_index, u32 new_size);
            void SetSegmentMemorySize(int phdr_index, u32 new_size);
            void SetSegmentAlignment(int phdr_index, u32 new_alignment);
#endif

            void *ElfRead(off_t readoff, size_t size) const;
            void ElfWrite(void *buffer, off_t writeoff, size_t size) const;

            void PatchAddress(u8 *buffer, size_t len, addr_t addr, u8 *magic);
    };

};

#endif /* ZKELF_HH */
