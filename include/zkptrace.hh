#ifndef ZKPTRACE_HH
#define ZKPTRACE_HH

#include <sched.h>

#include <memory>
#include <optional>

#include "zkexcept.hh"
#include "zklog.hh"
#include "zktypes.hh"

// TODO set up handlers to handle various stops, signals.

// TODO -done
// !check if p_log is null. if so dont push the log

#define CHECKFLAGS_AND_ATTACH                                           \
    if (!ZK_CHECK_FLAGS(PTRACE_ATTACH_NOW, p_flags) &&                  \
        !ZK_CHECK_FLAGS(PTRACE_START_NOW, p_flags)) {                   \
        if (p_log.has_value()) {                                        \
            p_log.value()->push_log("attaching to process",             \
                                    zklog::log_level::LOG_LEVEL_DEBUG); \
        }                                                               \
        detach_from_process();                                          \
    }

#define CHECKFLAGS_AND_DETACH                                           \
    if (!ZK_CHECK_FLAGS(PTRACE_ATTACH_NOW, p_flags) &&                  \
        !ZK_CHECK_FLAGS(PTRACE_START_NOW, p_flags)) {                   \
        if (p_log.has_value()) {                                        \
            p_log.value()->push_log("detaching from process",           \
                                    zklog::log_level::LOG_LEVEL_DEBUG); \
        }                                                               \
        detach_from_process();                                          \
    }

#define RETURN_IF_EXITED(x)                                             \
    if (get_process_state() == PROCESS_STATE_EXITED) {                  \
        if (p_log.has_value()) {                                        \
            p_log.value()->push_log("process has exited",               \
                                    zklog::log_level::LOG_LEVEL_ERROR); \
        }                                                               \
        return (x);                                                     \
    }

#define RETURN_IF_NOT_STOPPED(x)                                    \
    if (!is_ptrace_stop()) {                                        \
        if (p_log.has_value()) {                                    \
            p_log.value()->push_log(                                \
                "process needs to be in STATE_STOPPED to call the " \
                "method",                                           \
                zklog::log_level::LOG_LEVEL_ERROR);                 \
        }                                                           \
        return (x);                                                 \
    }

#define GET_PTRACE_EVENT_VALUE(x) (((x) << (8)) | SIGTRAP)

namespace zkprocess {

enum PTRACE_FLAGS : zktypes::u8_t {
    PTRACE_SEIZE = 0,  // TODO ptrace seize
    PTRACE_ATTACH_NOW,
    PTRACE_START_NOW,
    PTRACE_DISABLE_ASLR
};

// These are not to be confused with ptrace process state
// There are only two process states in ptrace context
//      1. running      2. stopped
// zkinject treats process state in more detailed manner.
enum PROCESS_STATE : zktypes::u8_t {
    PROCESS_NOT_STARTED = 0,
    PROCESS_STATE_DETACHED,
    PROCESS_STATE_EXITED,
    PROCESS_STATE_SIGNALED,
    PROCESS_STATE_STOPPED,
    PROCESS_STATE_CONTINUED,
    PROCESS_STATE_FAILED
};

// This enum describes ptrace stopped process state
enum PTRACE_STOP_STATE : zktypes::u8_t {
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
    struct {
        int st_term_sig;
        bool st_is_coredumped;
    } signal_terminated;
    struct {
        int ss_stop_sig;
        PTRACE_STOP_STATE ss_ptrace_stop;
        eventcodes_t ss_ptrace_event;
    } signal_stopped;
};

enum PTRACE_OPTIONS : zktypes::u16_t {
    // TODO trace options
    // options for ptrace
    //
};

template <typename T = x64>
class Ptrace {
public:
    Ptrace(pid_t pid, std::optional<zktypes::u8_t> flags = std::nullopt);
    ~Ptrace();

    Ptrace(char *const *path,
           std::optional<zktypes::u8_t> flags = PTRACE_START_NOW |
                                                PTRACE_DISABLE_ASLR,
           std::optional<zklog::ZkLog *> log = std::nullopt);
    Ptrace(pid_t pid,
           std::optional<zktypes::u8_t> flags = PTRACE_ATTACH_NOW,
           std::optional<zklog::ZkLog *> log = std::nullopt);

    void ptrace_init_from_file(char *const *path,
                               zktypes::u8_t flags) noexcept;
    void ptrace_init_from_pid(pid_t pid) noexcept;

    inline pid_t get_pid(void) const { return p_pid; }
    inline PROCESS_STATE get_process_state(void) const { return p_state; }
    inline PROCESS_STATE_INFO get_process_state_info(void) const {
        return p_state_info;
    }

    // dont want these to terminate after exception
    // because user should be able to handle those
    void attach_to_process(void);
    void seize_process(void);
    void start_process(char **pathname);
    void detach_from_process(void);
    void kill_process(void);
    bool continue_process(bool pass_signal);
    bool is_ptrace_stop(void) const;

    PROCESS_STATE wait_for_process(int options);

    typename T::addr_t generate_address(int seed) const;

    bool read_process_memory(void *buffer, typename T::addr_t address,
                             size_t buffer_sz);
    typename T::addr_t write_process_memory(void *buffer,
                                            typename T::addr_t address,
                                            size_t buffer_sz);
    bool read_process_registers(const registers_t &registers);
    bool write_process_registers(const registers_t &registers);
    void *replace_memory_page(typename T::addr_t addr, void *buffer,
                              int buffer_size);

    /*
    void * GenerateAddress(int seed) const;

    bool ReadProcess(void *buffer, void * address, size_t buffer_sz);
    void * WriteProcess(void *buffer, void * address, size_t buffer_sz);
    bool ReadRegisters(const registers_t &registers);
    bool WriteRegisters(const registers_t &registers);
    void *ReplacePage(void * addr, void *buffer, int buffer_size);
    */

    // void *MemAlloc(void *mmap_shellcode, int protection, int size);

    // TODO methods to read thread state using registers
    //  CreateThread

    friend std::shared_ptr<Ptrace<x64>> init_from_file_if_x64(
        char *const *path, zktypes::u8_t flags,
        std::optional<zklog::ZkLog *> log) noexcept;

    friend std::shared_ptr<Ptrace<x86>> init_from_file_if_x86(
        char *const *path, zktypes::u8_t flags,
        std::optional<zklog::ZkLog *> log) noexcept;

    friend std::shared_ptr<Ptrace<x64>> init_from_pid_if_x64(
        pid_t pid, std::optional<zklog::ZkLog *> log) noexcept;

    friend std::shared_ptr<Ptrace<x86>> init_from_pid_if_x86(
        pid_t pid, std::optional<zklog::ZkLog *> log) noexcept;

private:
    zktypes::u8_t p_flags = 0;

    PROCESS_STATE p_state = PROCESS_NOT_STARTED;
    PROCESS_STATE_INFO p_state_info;
    pid_t p_pid;
    std::optional<zklog::ZkLog *> p_log;
};

std::shared_ptr<Ptrace<x64>> init_from_file_if_x64(
    char *const *path, zktypes::u8_t flags,
    std::optional<zklog::ZkLog *> log) noexcept;

std::shared_ptr<Ptrace<x86>> init_from_file_if_x86(
    char *const *path, zktypes::u8_t flags,
    std::optional<zklog::ZkLog *> log) noexcept;

std::shared_ptr<Ptrace<x64>> init_from_pid_if_x64(
    pid_t pid, std::optional<zklog::ZkLog *> log) noexcept;

std::shared_ptr<Ptrace<x86>> init_from_pid_if_x86(
    pid_t pid, std::optional<zklog::ZkLog *> log) noexcept;

};  // namespace zkprocess

#endif  // ZKPTRACE_HH
