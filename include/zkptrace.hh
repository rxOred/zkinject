#ifndef ZKPTRACE_HH
#define ZKPTRACE_HH

#include "zktypes.hh"
#include "zkexcept.hh"
#include "zklog.hh"
#include <optional>

// TODO set up handlers to handle various stops, signals.

// TODO -done 
// !check if p_log is null. if so dont push the log

#define CHECKFLAGS_AND_ATTACH                                           \
    if(!ZK_CHECK_FLAGS(PTRACE_ATTACH_NOW, p_flags) &&                   \
       !ZK_CHECK_FLAGS(PTRACE_START_NOW, p_flags)) {                    \
        if (p_log.has_value()) {                                        \
            p_log.value()->PushLog("attaching to process",              \
                ZkLog::LOG_LEVEL_DEBUG);                                \
        }                                                               \
        DetachFromProcess();                                            \
    }

#define CHECKFLAGS_AND_DETACH                                           \
    if(!ZK_CHECK_FLAGS(PTRACE_ATTACH_NOW, p_flags) &&                   \
       !ZK_CHECK_FLAGS(PTRACE_START_NOW, p_flags)) {                    \
        if (p_log.has_value()) {                                        \
            p_log.value()->PushLog("detaching from process",            \
                ZkLog::LOG_LEVEL_DEBUG);                                \
        }                                                               \
        DetachFromProcess();                                            \
    }

#define RETURN_IF_EXITED(x)                                             \
    if(GetProcessState() == PROCESS_STATE_EXITED) {                     \
        if (p_log.has_value()) {                                        \
            p_log.value()->PushLog("process has exited",                \
                    ZkLog::LOG_LEVEL_ERROR);                            \
        }                                                               \
        return (x);                                                     \
    }

#define RETURN_IF_NOT_STOPPED(x)                                        \
    if(!isPtraceStopped()) {                                            \
        if (p_log.has_value()) {                                        \
        p_log.value()->PushLog(                                         \
            "process needs to be in STATE_STOPPED to call the method",  \
             ZkLog::LOG_LEVEL_ERROR);                                   \
        }                                                               \
        return (x);                                                     \
    }

#define GET_PTRACE_EVENT_VALUE(x) (((x) << (8)) | SIGTRAP )

namespace ZkProcess {

    enum PTRACE_FLAGS : u8_t {
        PTRACE_SEIZE            = 0,    // TODO ptrace seize
        PTRACE_ATTACH_NOW,
        PTRACE_START_NOW,
        PTRACE_DISABLE_ASLR
    };


    // These are not to be confused with ptrace process state
    // There are only two process states in ptrace context
    //      1. running      2. stopped
    // zkinject treats process state in more detailed manner.
    enum PROCESS_STATE : u8_t {
        PROCESS_NOT_STARTED     = 0,
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
        // such as PTRACE_PEEKDATA, PTRACE_POKEDATA, PTRACE_GETREGS
        // and so on
        PTRACE_STOP_NOT_STOPPED = 0,
        PTRACE_STOP_SIGNAL_DELIVERY,
        PTRACE_STOP_GROUP,
        PTRACE_STOP_SYSCALL,
        PTRACE_STOP_PTRACE_EVENT
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

    enum PTRACE_OPTIONS: u16_t {
         // TODO trace options
         // options for ptrace
         //
    };

    class Ptrace {
        public:
            Ptrace(const char **pathname, std::optional<u8_t> flags
                    = std::nullopt);
            Ptrace(pid_t pid, std::optional<u8_t> flags = std::nullopt);
            Ptrace(const char **pathname, pid_t pid, u8_t flags);
            Ptrace(const char **pathname, pid_t pid, u8_t flags,
                   std::optional<ZkLog::Log *>log = std::nullopt);
            ~Ptrace();

            inline pid_t GetProcessId(void) const 
            {
                return p_pid;
            }

            inline PROCESS_STATE GetProcessState(void) const noexcept
            {
                return p_state;
            }
            inline PROCESS_STATE_INFO GetProcessStateInfo(void) const
                noexcept
            {
                return p_state_info;
            }

            void AttachToPorcess(void);
            void SeizeProcess(void);
            void StartProcess(char **pathname);
            void DetachFromProcess(void);
            void KillProcess(void);
            bool ContinueProcess(bool pass_signal);

            PROCESS_STATE WaitForProcess(int options);

            addr_t GenerateAddress(int seed) const;

            bool ReadProcess(void *buffer, addr_t address, size_t
                    buffer_sz);
            addr_t WriteProcess(void *buffer, addr_t address, size_t
                    buffer_sz);
            bool ReadRegisters(const registers_t& registers);
            bool WriteRegisters(const registers_t& registers);
            void *ReplacePage(addr_t addr, void *buffer, int buffer_size);

            //void *MemAlloc(void *mmap_shellcode, int protection, int size);

            //TODO methods to read thread state using registers
            // CreateThread

        private:
            u8_t p_flags = 0;

            PROCESS_STATE p_state = PROCESS_NOT_STARTED;
            PROCESS_STATE_INFO p_state_info;
            pid_t p_pid;

            std::optional<ZkLog::Log *> p_log;

            bool isPtraceStopped(void) const;
    };
};

#endif // ZKPTRACE_HH
