#ifndef ZKINJECT_HH
#define ZKINJECT_HH

#include <cstdint>
#include <elf.h>
#include <sys/types.h>

namespace Binary{
    /* class which defines important parts of an elf binary */
    class Elf {
        protected:
            int elf_fd;
            /* memory mapped elf binary */
            void *elf_memmap;
            /* load address of elf */
            uint64_t elf_baseaddr;
            /* elf header */
            Elf64_Ehdr *elf_ehdr;
            /* elf program header table */
            Elf64_Phdr *elf_phdr;
            /* elf section header table */
            Elf64_Shdr *elf_shdr;

        public:
            const char *elf_pathname;
            size_t elf_size;

            Elf();
            Elf(const char *pathname);
            void OpenElf(void);
            void LoadFile(void);
            bool CheckFlags(uint16_t);
    };
};

#endif /* ZKINJECT_HH */
