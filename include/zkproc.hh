#ifndef ZKPROC_HH
#define ZKPROC_HH

#include "zktypes.hh"
#include "zkexcept.hh"
#include <cstddef>
#include <memory>
#include <sys/types.h>
#include <vector>
#include <fcntl.h>
#include <fstream>
#include <string>
#include <sstream>

#define PATH_LEN  64

#define MAPPATH     "/proc/%d/maps"
#define MEMPATH     "/proc/%d/mem"
#define CMDLINE     "/proc/%d/cmdline"

/*
 * following class stores information about a process.
 * such information include, memory map, command line args
 * and more
 */
#define MASK_ONLY_BASE_ADDR     (1 << 0)
#define CHECK_MASK(x, y)        (x & y)

namespace Process {
    class MemoryMap  {
            u8 flag;
            std::vector<std::shared_ptr<page_t>> mm_pageinfo;
        public:
            MemoryMap(pid_t pid);
            addr_t GetModuleBaseAddress(const char *module_name) const;
            addr_t GetModuleEndAddress(const char *module_name) const;
            std::shared_ptr<page_t> GetModulePage(const char *module_name) const;

            inline std::shared_ptr<page_t> GetBasePage(void) const
            {
                return  mm_pageinfo[0];
            }

            inline addr_t GetBaseAddress(void) const
            {
                return mm_pageinfo[0]->GetPageStartAddress();
            }

            inline addr_t GetBaseEndAddress(void) const
            {
                return mm_pageinfo[0]->GetPageEndAddress();
            }
    };

    class Ptrace {
        private:
            addr_t p_baseaddr;

        public:
            void *ReadProcess(addr_t address, size_t buffer_sz) const;
            void WriteProcess(void *buffer, addr_t address, size_t buffer_sz);
            registers_t ReadRegisters(void) const;
            void WriteRegisters(registers_t& registers) const;
    };
};

#endif /* ZKPROC_HH */
