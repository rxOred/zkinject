#include "zkelf.hh"
#include "zkproc.hh"
#include <cstddef>

namespace Injections {
    /* text padding infection */
    class TextPaddingInfection : public Binary::Elf{
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
             * re-alloc space for a new payload with a modified return address. 
             * return address = tpi_org_entry
             */
            void SetPayload(u8 *payload, size_t payload_sz);
            /* find a freespace and set tpi_fake_entry */
            off_t FindFreeSpace(void);
            void InjectPayload(off_t writeoff, size_t size) const;
    };

    class CodeInjection : public Process::Proc{
        private:
            void    *cd_payload;
            size_t  cd_payload_sz;

        
    };
}
