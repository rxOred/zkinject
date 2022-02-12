#ifndef ZKPROC_HH
#define ZKPROC_HH

#include "zktypes.hh"
#include "zkexcept.hh"
#include <cstdint>
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
#include <random>

#define PATH_LEN  64

#define MAPPATH     "/proc/%d/maps"
#define MEMPATH     "/proc/%d/mem"
#define CMDLINE     "/proc/%d/cmdline"

#define PAGE_ALIGN_UP(x) ((x) & ~(4095))

#define DEFAULT_SNAPSHOT_STACK_SZ   1024
#define DEFAULT_SNAPSHOT_INSTR      64

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

    enum PROCESS_SNAPSHOT : u8 {
        PROCESS_SNAP_ALL     = 1,
        PROCESS_SNAP_FUNC
    };

    class page_t {
            addr_t      page_saddr;
            addr_t      page_eaddr;
            std::string page_permissions;
            std::string page_name;

        public:
            page_t(addr_t saddr, addr_t eaddr, std::string permissions, 
                    std::string name)
                :page_saddr(saddr), page_eaddr(eaddr), page_permissions
                 (permissions),page_name(name)
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
            std::shared_ptr<page_t> GetModulePage(const char *module_name) 
                const;

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

            inline bool IsMapped(addr_t addr) const
            {
                /* check if given address is kernel allocated */
                if (addr >= 0x7fffffffffffff){
                    return true;
                }
                for(int i = 0; i < mm_pageinfo.size(); i++){
                    if((addr & 0x000000000000ffff) == 
                        mm_pageinfo[i]->GetPageStartAddress() ||
                        (addr & 0x000000000000ffff) == 
                        mm_pageinfo[i]->GetPageEndAddress()){
                        return true;
                    } 
                }
                return false;
            }
            /*
             * TODO
             * Implement VirtualAlloc
             * Implement VirtualProtect
             */
    };

    class Ptrace {
        private:
            u8 p_flags = 0;
            PROCESS_STATE p_state = PROCESS_NOT_STARTED;
            std::shared_ptr<MemoryMap> p_memmap;
            pid_t p_pid;
        public:
            /* 
             * pathname = filepath to elf binary which should be forkd 
             * and execed with ptrace 
             * pid = pid for a currently active process
             * regs = register struct
             */
            Ptrace(const char **pathname, pid_t pid, u8 flags);
            ~Ptrace();

            inline std::shared_ptr<MemoryMap> GetMemoryMap(void) const 
            {
                return p_memmap;
            }

            /* attach and detach from a process */
            void AttachToPorcess(void) const;
            void DetachFromProcess(void) const;

            /* Start the proces */
            PROCESS_STATE StartProcess(char **pathname);

            /* wait until process stops */
            PROCESS_STATE WaitForProcess(void) const;

            /* generate a random address */
            inline addr_t GenerateAddress(int seed) const 
            {
                std::mt19937_64 gen(seed);
                std::uniform_int_distribution<u64> distr(0, 0x7ffffffffffffff);

                return distr(gen);
            }
            /* 
             * read from process to an allocated buffer starting at address, 
             * sizeof buffer_sz len.
             */
            void ReadProcess(void *buffer, addr_t address, size_t 
                    buffer_sz) const;
            void WriteProcess(void *buffer, addr_t address, size_t 
                    buffer_sz) const;
            void ReadRegisters(registers_t* registers) const;
            void WriteRegisters(registers_t* registers) const;

            void *ReplacePage(addr_t addr, void *buffer, int buffer_size) 
                const;
            void *MemAlloc(void *mmap_shellcode, int protection, int size);
            inline std::string GetProcessPathname(void) const 
            {
                return p_memmap->GetBasePage()->GetPageName();
            }
            /* 
             * TODO
             * methods to read thread state using registers
             * CreateThread
             */
    };

    /* singly-linked list (queue) to store recent process state */
    class ProcessSnapshot {
        private:
            /* generic information about amount of the captured data */
            u8              ps_flags;
            registers_t     *ps_registers;
            void            *ps_stack;      /* 100 bytes from rsp */
            void            *ps_instructions;
            ProcessSnapshot *ps_next;
        public:
            ProcessSnapshot(u8 flags, registers_t *regs, void *stack, 
                    void *instr)
                :ps_flags(flags), ps_registers(regs), 
                ps_instructions(instr), ps_stack(stack), 
                ps_next(nullptr)
            {}

            ~ProcessSnapshot()
            {
                if (ps_registers) { free(ps_registers); }
                if (ps_instructions) { free(ps_instructions); }
                if (ps_stack) { free(ps_stack); }
            }

            inline u8 GetFlags(void) const
            {
                return ps_flags;
            }

            inline void SetNext(ProcessSnapshot *next)
            {
                ps_next = next;
            }

            inline ProcessSnapshot *GetNext(void) const
            {
                return ps_next;
            }

            inline registers_t *GetRegisters(void) const 
            {
                return ps_registers;
            }

            inline void *GetStack(void) const 
            {
                return ps_stack;
            }

            inline void *GetInstructions(void) const 
            {
                return ps_instructions;
            }
    };

    // snapshot of the thread context
    class Snapshot {
        private:
            ProcessSnapshot *snap_state;   // head
        public:
            Snapshot(void)
                :snap_state(nullptr)
            {}

            ~Snapshot(void)
            {
                ProcessSnapshot *curr;
                for (curr = snap_state; curr != nullptr; curr = 
                        snap_state->GetNext()) {
                    delete 
                }
            }

            bool SaveSnapshot(Process::Ptrace &ptrace, u8 flags);
            bool RestoreSnapshot(Process::Ptrace &ptrace);
    };
};

#endif /* ZKPROC_HH */
