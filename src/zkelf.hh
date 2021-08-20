#ifndef ZKINJECT_HH
#define ZKINJECT_HH

#include "zktypes.hh"
#include <cstdint>
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
    };

    /* text padding infection */
    class TextPaddingInfection : public Elf{
        private:
            void *tpi_shellcode;

        public:
            void FindFreeSpace(int size) const;
    };
};

#endif /* ZKINJECT_HH */
