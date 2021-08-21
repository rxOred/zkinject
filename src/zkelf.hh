#ifndef ZKINJECT_HH
#define ZKINJECT_HH

#include "zkerr.hh"
#include "zktypes.hh"
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

namespace Binary{
    /* class which defines important parts of an elf binary */
    class Elf {
        protected:
            int elf_fd;
            /* memory mapped elf binary */
            void *elf_memmap;
            /* load address of elf */
            u64 elf_baseaddr;
            /* elf header */
            Ehdr *elf_ehdr;
            /* elf program header table */
            Phdr *elf_phdr;
            /* elf section header table */
            Shdr *elf_shdr;

        public:
            const char *elf_pathname;
            size_t elf_size;

            Elf();
            Elf(const char *pathname);
            void OpenElf(void);
            void LoadFile(void);
            bool VerifyElf(void) const;
            void RemoveMap(void);

            /* commonly used stuff with infectors */
            int FindSegmentbyAttr(u32 type, u32 flags) const;
            int GetSectionIndexByName(const char *name) const;
            void *ElfRead(off_t readoff, size_t size) const;
            void ElfWrite(void *buffer, off_t writeoff, size_t 
            size) const;
    };

    /* text padding infection */
    class TextPaddingInfection : public Elf{
        private:
            void *tpi_shellcode;
            Addr tpi_orgentry;
            Addr tpi_fakeetry;
        public:
            TextPaddingInfection(char *target);
            off_t FindFreeSpace(int size) const;
    };
};

#endif /* ZKINJECT_HH */