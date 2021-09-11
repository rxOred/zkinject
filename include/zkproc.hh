#ifndef ZKPROC_HH
#define ZKPROC_HH

#include "zktypes.hh"
#include "zkexcept.hh"
#include <iostream>
#include <cstddef>
#include <memory>
#include <sys/types.h>
#include <vector>
#include <fcntl.h>
#include <fstream>
#include <string>
#include <sstream>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/personality.h>
#include <sys/ptrace.h>

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

    enum PROCESS_INFO : u8 {
        PTRACE_ATTACH_NOW       = 1 << 0,
        PTRACE_START_NOW        = 1 << 1,
        PTRACE_DISABLE_ASLR     = 1 << 2,
        MEMMAP_ONLY_BASE_ADDR   = 1 << 3
    };

    enum PROCESS_STATE : u8 {
        PROCESS_NOT_STARTED     = 1,
        PROCESS_STATE_EXITED,
        PROCESS_STATE_SIGNALED,
        PROCESS_STATE_STOPPED,
        PROCESS_STATE_CONTINUED,
        PROCESS_STATE_FAILED
    };

    class page_t {
            addr_t      page_saddr;
            addr_t      page_eaddr;
            std::string page_permissions;
            std::string page_name;

        public:
            page_t(addr_t saddr, addr_t eaddr, std::string permissions, std::string 
                    name)
                :page_saddr(saddr), page_eaddr(eaddr), page_permissions(permissions),
                page_name(name)
            {}

            inline addr_t GetPageStartAddress(void) const
            {
                return page_saddr;
            }

            inline addr_t GetPageEndAddress(void) const
            {
                return page_eaddr;
            }

            inline std::string GetPagePermissions(void) const
            {
                return page_permissions;
            }

            inline std::string GetPageName(void) const
            {
                return page_name;
            }
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
            PROCESS_STATE p_state = PROCESS_NOT_STARTED;
            std::shared_ptr<MemoryMap> p_memmap;            /* NOTE make this unique */
            pid_t p_pid;
            registers_t p_registers;
        public:
            /* 
             * pathname = filepath to elf binary which should be forkd and execed with 
             * ptrace 
             * pid = pid for a currently active process
             * regs = register struct
             */
            Ptrace(const char **pathname, pid_t pid, u8 flags);
            ~Ptrace();
            void AttachToPorcess(void) const;
            void DetachFromProcess(void) const;
            PROCESS_STATE StartProcess(char **pathname);
            PROCESS_STATE WaitForProcess(void) const;
            template<class T> T ReadProcess(addr_t address, size_t buffer_sz) const;
            void WriteProcess(void *buffer, addr_t address, size_t buffer_sz);
            registers_t ReadRegisters(void) const;
            void WriteRegisters(registers_t& registers) const;
    };
};

#endif /* ZKPROC_HH */
