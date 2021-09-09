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

#define CHECK_FLAGS(x, y) ((x) & (y))

namespace Process {

    enum PROCESS_INFO : u16 {
        PTRACE_ATTACH_NOW       = 1 << 0,
        PTRACE_START_NOW        = 1 << 1,
        PTRACE_DISABLE_ASLR     = 1 << 2,
        MEMMAP_ONLY_BASE_ADDR   = 1 << 3
    };

    class MemoryMap  {
            u8 mm_flags = 0;
            std::vector<std::shared_ptr<page_t>> mm_pageinfo;
        public:
            MemoryMap(pid_t pid, u8 flag);
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
            u8 p_flags = 0;

            enum PROCESS_STATE : u8 {
                PROCESS_NOT_STARTED     = 1 << 0,
                PROCESS_STATE_EXITED    = 1 << 1,
                PROCESS_STATE_SIGNALED  = 1 << 2,
                PROCESS_STATE_STOPPED   = 1 << 3,
                PROCESS_STATE_CONTINUED = 1 << 4,
                PROCESS_STATE_FAILED    = 1 << 5
            };

            PROCESS_STATE p_state = PROCESS_NOT_STARTED;

            std::shared_ptr<MemoryMap> p_memmap;            /* NOTE make this unique */
            pid_t p_pid;
            registers_t& p_registers;
        public:
            Ptrace(const char **pathname, pid_t pid, registers_t& regs, u8 flags);
            void AttachToPorcess(void) const;
            void StartProcess(char **pathname);
            PROCESS_STATE WaitForProcess(void) const;
            template<class T> T ReadProcess(addr_t address, size_t buffer_sz) const;
            void WriteProcess(void *buffer, addr_t address, size_t buffer_sz);
            registers_t ReadRegisters(void) const;
            void WriteRegisters(registers_t& registers) const;
    };
};

#endif /* ZKPROC_HH */
