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

#define MAPPATH     "/proc/%d/maps"
#define MEMPATH     "/proc/%d/mem"
#define CMDLINE     "/proc/%d/cmdline"

#define DEFAULT_SNAPSHOT_STACK_SZ   1024
#define DEFAULT_SNAPSHOT_INSTR      64

#define CHECK_PTRACE_STOP                                           \
    if(!isPtraceStopped()) {                                        \
        throw zkexcept::ptrace_error("process is not stopped");     \
    }

#define GET_PTRACE_EVENT_VALUE(x) (((x) << (8)) | SIGTRAP )

/*
 * following class stores information about a process.
 * such information include, memory map, command line args
 * and more
 */

namespace ZkProcess {

    enum PROCESS_INFO : u8 {
        PTRACE_SEIZE            = 0,    // TODO ptrace seize
        PTRACE_ATTACH_NOW       = 1 << 0,
        PTRACE_START_NOW        = 1 << 1,
        PTRACE_DISABLE_ASLR     = 1 << 2,
        MEMMAP_ONLY_BASE_ADDR   = 1 << 3
    };

    /* 
     * These are not to be confused with ptrace process state
     * There are only two process states in ptrace context
     *      1. running      2. stopped
     * zkinject treats process state in more detailed manner.
     * 
     *
     */
    enum PROCESS_STATE : u8 {
        PROCESS_NOT_STARTED     = 1,
        PROCESS_STATE_DETACHED,
        PROCESS_STATE_EXITED,
        PROCESS_STATE_SIGNALED,
        PROCESS_STATE_STOPPED,
        PROCESS_STATE_CONTINUED,
        PROCESS_STATE_FAILED
    };


    /* This enum describes ptrace stopped process state */
    enum PTRACE_STOP_STATE : u8 {
        /* ptrace-stop state - tracee is ready accept ptrace commands */
        PTRACE_STOP_NOT_STOPPED = 0,
        PTRACE_STOP_SIGNAL_DELIVERY,
        PTRACE_STOP_GROUP, 
        PTRACE_STOP_SYSCALL,
        PTRACE_STOP_PTRACE_EVENT, 
        
        /* */
    };

    /* exit status of the process */
    union PROCESS_STATE_INFO {
        struct {
            int exit_status;
        } exited;
        struct{
            int term_sig;
            bool is_coredumped;
        } signal_terminated;
        struct {
            int stop_sig;
            PTRACE_STOP_STATE ptrace_stop;
            __ptrace_eventcodes ptrace_event;
        } signal_stopped;
    };

    enum TRACE_OPTIONS: u16 {
        /* TODO trace options
         * options for ptrace 
         */
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

            bool IsMapped(addr_t addr) const;

           /* TODO virtualAlloc /protect */
    };

    class Signal {
        private:
            siginfo_t s_siginfo;
            pid_t s_pid;
        public:
            Signal(pid_t pid)
                :s_pid(pid)
            {
                memset(s_siginfo, 0x0, sizeof(s_siginfo));
            }

            bool SignalProcess(int signal) const
            {
                if (kill(s_pid, signal) < 0) return false;
                else return true;
            }

            inline bool SignalStopProcess(void) const
            {
                return SignalProcess(SIGSTOP);
            }

            inline bool SignalKillProcess(void) const
            {
                return SignalProcess(SIGKILL);
            }

            inline bool SignalContinueProcess(void) const
            {
                return SignalProcess(SIGCONT);
            }

            inline bool SignalTrapProcess(void) const
            {
                return SignalProcess(SIGTRAP);
            }
    };

    class Ptrace {
        private:
            u8 p_flags = 0;

            PROCESS_STATE p_state = PROCESS_NOT_STARTED;
            PROCESS_STATE_INFO p_state_info; 

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

            /* attach to the process, stopping it */
            void AttachToPorcess(void);

            /* attach to the process but without stopping it */ 
            void SeizeProcess(void);

            /* Start the proces, stopping it */
            PROCESS_STATE StartProcess(char **pathname);

            /* detach from attached / started process */
            void DetachFromProcess(void);

            void KillProcess(void);

            void ContinueProcess(bool pass_signal);

            /* wait for process state changes */
            void WaitForProcess(int options);

            PROCESS_STATE SignalProcess(int signal);

            PROCESS_STATE SignalStopProcess(void);

            PROCESS_STATE SignalKillProcess(void);

            PROCESS_STATE SignalContinueProcess(void);

            /* generate a random unallocated userland address */
            addr_t GenerateAddress(int seed) const;
            /* 
             * read from process to an allocated buffer starting at address, 
             * sizeof buffer_sz len.
             */
            void ReadProcess(void *buffer, addr_t address, size_t 
                    buffer_sz);

            addr_t WriteProcess(void *buffer, addr_t address, size_t 
                    buffer_sz);
            
            void ReadRegisters(registers_t* registers);
            
            void WriteRegisters(registers_t* registers);
            
            void *ReplacePage(addr_t addr, void *buffer, int buffer_size);
            
            void *MemAlloc(void *mmap_shellcode, int protection, int size);
            inline std::string GetProcessPathname(void) const 
            {
                return p_memmap->GetBasePage()->GetPageName();
            }
            /* 
             * TODO methods to read thread state using registers
             * CreateThread
             */

        private:
            bool isPtraceStopped(void) const;
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

    class Snapshot {
        private:
            ProcessSnapshot *snap_state;   // head
        public:
            Snapshot(void)
                :snap_state(nullptr)
            {}

            ~Snapshot(void)
            {
                ProcessSnapshot *curr = snap_state;
                while (curr != nullptr) {
                    auto next = curr->GetNext();
                    delete curr;
                    curr = next;
                }
            }

            bool SaveSnapshot(ZkProcess::Ptrace &ptrace, u8 flags);
            bool RestoreSnapshot(ZkProcess::Ptrace &ptrace);
            /*inline registers_t *GetSnapshotRegisters(void) const
            {
                return snap_state->GetRegisters();
            }*/
    };
};

#endif /* ZKPROC_HH */