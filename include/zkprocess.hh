#ifndef ZKPROCESS_HH
#define ZKPROCESS_HH

#include "zktypes.hh"
#include "zkexcept.hh"
#include "zklog.hh"
#include <cstdint>
#include <iostream>
#include <cstddef>
#include <memory>
#include <sys/types.h>
#include <vector>
#include <queue>
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

#define DEFAULT_SNAPSHOT_COUNT      5
#define DEFAULT_SNAPSHOT_STACK_SZ   1024
#define DEFAULT_SNAPSHOT_INSTR      64

// TODO check if p_log is null. if so dont queue the log

#define CHECKFLAGS_AND_ATTACH                                        \
    if(!ZK_CHECK_FLAGS(PTRACE_ATTACH_NOW, p_flags) &&                \
       !ZK_CHECK_FLAGS(PTRACE_START_NOW, p_flags)) {                 \
        p_log->PushLog("attaching tp process",                       \
            ZkLog::LOG_LEVEL_DEBUG);                                 \
        DetachFromProcess();                                         \
    }

#define CHECKFLAGS_AND_DETACH                                        \
    if(!ZK_CHECK_FLAGS(PTRACE_ATTACH_NOW, p_flags) &&                \
       !ZK_CHECK_FLAGS(PTRACE_START_NOW, p_flags)) {                 \
        p_log->PushLog("detaching from process",                     \
            ZkLog::LOG_LEVEL_DEBUG);                                 \
        DetachFromProcess();                                         \
    }

#define RETURN_IF_EXITED(x)                                          \
    if(GetProcessState() == PROCESS_STATE_EXITED) {                  \
        p_log->PushLog("process has exited", ZkLog::LOG_LEVEL_ERROR);\
        return (x);                                                  \
    }

#define RETURN_IF_NOT_STOPPED(x)                                     \
    if(!isPtraceStopped()) {                                         \
        p_log->PushLog                                               \
        ("process needs to be in PROCESS_STATE_STOPPED to call the method", \
         ZkLog::LOG_LEVEL_ERROR);                                    \
        return (x);                                                  \
    }

#define GET_PTRACE_EVENT_VALUE(x) (((x) << (8)) | SIGTRAP )


// following class stores information about a process.
// such information include, memory map, command line args
// and more


namespace ZkProcess {

    enum PROCESS_INFO : u8_t {
        PTRACE_SEIZE            = 0,    // TODO ptrace seize
        PTRACE_ATTACH_NOW       = 1 << 0,
        PTRACE_START_NOW        = 1 << 1,
        PTRACE_DISABLE_ASLR     = 1 << 2,
        MEMMAP_ONLY_BASE_ADDR   = 1 << 3
    };


    // These are not to be confused with ptrace process state
    // There are only two process states in ptrace context
    //      1. running      2. stopped
    // zkinject treats process state in more detailed manner.
    enum PROCESS_STATE : u8_t {
        PROCESS_NOT_STARTED     = 1,
        PROCESS_STATE_DETACHED,
        PROCESS_STATE_EXITED,
        PROCESS_STATE_SIGNALED,
        PROCESS_STATE_STOPPED,
        PROCESS_STATE_CONTINUED,
        PROCESS_STATE_FAILED
    };


    // This enum describes ptrace stopped process state
    enum PTRACE_STOP_STATE : u8_t {
        // ptrace-stop state - tracee is ready accept ptrace commands
        PTRACE_STOP_NOT_STOPPED = 0,
        PTRACE_STOP_SIGNAL_DELIVERY,
        PTRACE_STOP_GROUP, 
        PTRACE_STOP_SYSCALL,
        PTRACE_STOP_PTRACE_EVENT, 


    };

    // exit status of the process
    union PROCESS_STATE_INFO {
        struct {
            int e_exit_status;
        } exited;
        struct{
            int st_term_sig;
            bool st_is_coredumped;
        } signal_terminated;
        struct {
            int ss_stop_sig;
            PTRACE_STOP_STATE ss_ptrace_stop;
            eventcodes_t ss_ptrace_event;
        } signal_stopped;
    };

    enum TRACE_OPTIONS: u16_t {
         // TODO trace options
         // options for ptrace
         //
    };

    enum PROCESS_SNAPSHOT : u8_t {
        PROCESS_SNAP_ALL     = 1,
        PROCESS_SNAP_FUNC
    };

    struct page_t {
        public:
            page_t(addr_t saddr, addr_t eaddr, std::string permissions, 
                    std::string name);

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
        private:
            addr_t      page_saddr;
            addr_t      page_eaddr;
            std::string page_permissions;
            std::string page_name;
    };

    class MemoryMap  {
        private:
            u8_t mm_flags = 0;
            std::vector<std::shared_ptr<page_t>> mm_pageinfo;
        public:
            MemoryMap(pid_t pid, u8_t flag);
            ~MemoryMap();

            addr_t GetModuleBaseAddress(const char *module_name) const;
            addr_t GetModuleEndAddress(const char *module_name) const;
            std::shared_ptr<page_t> GetModulePage(const char *module_name) 
                const;

            inline std::shared_ptr<page_t> GetBasePage(void) const
            {
                return  mm_pageinfo[0];
            }
            inline std::shared_ptr<page_t> GetLastPage(void) const
            {
                return *mm_pageinfo.end();
            }
            inline std::vector<std::shared_ptr<page_t>>::const_iterator
            GetIteratorBegin(void) const
            {
                return mm_pageinfo.begin();
            }
            inline std::vector<std::shared_ptr<page_t>>::const_iterator
            GetIteratorLast(void) const
            {
                return mm_pageinfo.end();
            }
            inline std::pair<std::vector<std::shared_ptr<page_t>>::const_iterator,
                      std::vector<std::shared_ptr<page_t>>::const_iterator>
            GetIteratorsBeginEnd(void) const
            {
                return std::make_pair(mm_pageinfo.begin(), mm_pageinfo.end());
            }
            inline addr_t GetBaseAddress(void) const
            {
                return mm_pageinfo[0]->GetPageStartAddress();
            }
            inline addr_t GetBaseEndAddress(void) const
            {
                return mm_pageinfo[0]->GetPageEndAddress();
            }
            inline std::vector<std::shared_ptr<page_t>> GetMemoryPages(void) const
            {
                return mm_pageinfo;
            }
            bool IsMapped(addr_t addr) const;

           // TODO virtualAlloc /protect
    };

    class Signal {
        private:
            siginfo_t s_siginfo;
            pid_t s_pid;
        public:
            Signal(pid_t pid)
                :s_pid(pid)
            {// TODO initialize s_siginfo to 0x0
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
            u8_t p_flags = 0;

            PROCESS_STATE p_state = PROCESS_NOT_STARTED;
            PROCESS_STATE_INFO p_state_info; 

            std::shared_ptr<MemoryMap> p_memmap;
            ZkLog::Log *p_log;
            pid_t p_pid;
        public:

            // pathname = filepath to elf binary which should be forkd
            // and execed with ptrace
            // pid = pid for a currently active process
            // regs = register struct
            Ptrace(const char **pathname, pid_t pid, u8_t flags, ZkLog::Log *log);
            Ptrace(const char **pathname, pid_t pid, u8_t flags);
            ~Ptrace();

            inline std::shared_ptr<MemoryMap> GetMemoryMap(void) const 
            {
                return p_memmap;
            }
            inline PROCESS_STATE GetProcessState(void) const
            {
                return p_state;
            }
            inline PROCESS_STATE_INFO GetProcessStateInfo(void) const
            {
                return p_state_info;
            }

            void AttachToPorcess(void);
            void SeizeProcess(void);
            void StartProcess(char **pathname);
            void DetachFromProcess(void);
            void KillProcess(void);
            bool ContinueProcess(bool pass_signal);

            void WaitForProcess(int options);

            PROCESS_STATE SignalProcess(int signal);
            PROCESS_STATE SignalStopProcess(void);
            PROCESS_STATE SignalKillProcess(void);
            PROCESS_STATE SignalContinueProcess(void);


            addr_t GenerateAddress(int seed) const;

            bool ReadProcess(void *buffer, addr_t address, size_t
                    buffer_sz);
            addr_t WriteProcess(void *buffer, addr_t address, size_t 
                    buffer_sz);
            bool ReadRegisters(registers_t* registers);
            bool WriteRegisters(registers_t* registers);
            void *ReplacePage(addr_t addr, void *buffer, int buffer_size);
            
            void *MemAlloc(void *mmap_shellcode, int protection, int size);
            inline std::string GetProcessPathname(void) const 
            {
                return p_memmap->GetBasePage()->GetPageName();
            }

            //TODO methods to read thread state using registers
            // CreateThread


        private:
            bool isPtraceStopped(void) const;
    };

    // queue to store process state
    struct snapshot_t {
        public:
            snapshot_t(u8_t flags, registers_t *regs, void *stack, 
                    void *instr);

            ~snapshot_t();

            inline u8_t GetFlags(void) const
            {
                return ps_flags;
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
        private:
            // generic information about amount of the captured data
            u8_t              ps_flags;
            registers_t     *ps_registers;
            void            *ps_stack;
            void            *ps_instructions;
    };

    class Snapshot {
        private: 
            int s_count = DEFAULT_SNAPSHOT_COUNT;
            std::queue<std::shared_ptr<snapshot_t>> s_snapshots;
            ZkLog::Log *s_log;
        public:
            Snapshot();
            Snapshot(int count);
            Snapshot(int count, ZkLog::Log *log);
            ~Snapshot();

            bool SaveSnapshot(ZkProcess::Ptrace &ptrace, u8_t flags);
            bool RestoreSnapshot(ZkProcess::Ptrace &ptrace);
    };
};

#endif // ZKPROCESS_HH
