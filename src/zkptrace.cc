#include "zkptrace.hh"

#include <asm-generic/errno-base.h>
#include <bits/types/siginfo_t.h>
#include <sched.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <optional>
#include <random>
#include <stdexcept>

#include "zkexcept.hh"
#include "zklog.hh"
#include "zktypes.hh"
#include "zkutils.hh"

// FIXME remove all the XXX_NOW bullshit. those are useless specifially,
// attach_NOW. instead just attach and start processes.

std::shared_ptr<zkprocess::Ptrace<x64>> zkprocess::init_from_file_if_x64(
    char *const *path, zktypes::u8_t flags,
    std::optional<zklog::ZkLog *> log) noexcept {
    return std::make_shared<Ptrace<x64>>(path, flags, log);
}

std::shared_ptr<zkprocess::Ptrace<x86>> zkprocess::init_from_file_if_x86(
    char *const *path, zktypes::u8_t flags,
    std::optional<zklog::ZkLog *> log) noexcept {
    return std::make_shared<Ptrace<x86>>(path, flags, log);
}

std::shared_ptr<zkprocess::Ptrace<x64>> zkprocess::init_from_pid_if_x64(
    pid_t pid, std::optional<zklog::ZkLog *> log) noexcept {
    return std::make_shared<Ptrace<x64>>(pid, std::nullopt, log);
}

std::shared_ptr<zkprocess::Ptrace<x86>> zkprocess::init_from_pid_if_x86(
    pid_t pid, std::optional<zklog::ZkLog *> log) noexcept {
    return std::make_shared<Ptrace<x86>>(pid, std::nullopt, log);
}

template <typename T>
zkprocess::Ptrace<T>::Ptrace(char *const *path,
                             std::optional<zktypes::u8_t> flags,
                             std::optional<zklog::ZkLog *> log)
    : p_flags(flags.value()), p_log(log) {
    if (path == nullptr) {
        throw std::invalid_argument("path is invalid");
    }
    // TODO call internal functions like start_process , atttach_process
    //ptrace_init_from_file(path, flags.value_or(PTRACE_DISABLE_ASLR));
	start_process(path);
}

template <typename T>
zkprocess::Ptrace<T>::Ptrace(pid_t pid, std::optional<zktypes::u8_t> flags,
                             std::optional<zklog::ZkLog *> log) {}

/* TODO
template <typename T>
zkprocess::Ptrace<T>::Ptrace(pid_t pid, std::optional<zktypes::u8_t> flags,
                             std::optional<zklog::Log *> log) {
    : p_flags(flags.value()), p_log(log) {
        if (pid == 0) {
            throw std::invalid_argument("path is wrong")
        }
    }
}
*/

template <typename T>
bool zkprocess::Ptrace<T>::is_ptrace_stop(void) const {
    if (p_state_info.signal_stopped.ss_ptrace_stop >
                PTRACE_STOP_NOT_STOPPED &&
            p_state_info.signal_stopped.ss_ptrace_stop <
                PTRACE_STOP_PTRACE_EVENT ||
        p_state == PROCESS_STATE_STOPPED) {
        return true;
    }
    return false;
}

template <typename T>
zkprocess::Ptrace<T>::~Ptrace() {
    if (ZK_CHECK_FLAGS(PTRACE_ATTACH_NOW, p_flags) &&
        ZK_CHECK_FLAGS(PTRACE_START_NOW, p_flags))
        detach_from_process();
}

template <typename T>
void zkprocess::Ptrace<T>::attach_to_process(void) {
    if (ptrace(PTRACE_ATTACH, p_pid, nullptr, nullptr) < 0) {
        throw zkexcept::ptrace_error("ptrace attach failed\n");
    }
    wait_for_process(0);
}

// TODO
template <typename T>
void zkprocess::Ptrace<T>::seize_process(void) {
    //    if (ptrace(PTRACE_SEIZE, p_pid, nullptr, nullptr) < 0)
    //      throw zkexcept::ptrace_error("ptrace seize failed\n");
    p_state = PROCESS_STATE_CONTINUED;
}

template <typename T>
void zkprocess::Ptrace<T>::start_process(char *const *pathname) {
    p_pid = fork();
    if (p_pid == 0) {
        if (ZK_CHECK_FLAGS(p_flags, PTRACE_DISABLE_ASLR)) {
            personality(ADDR_NO_RANDOMIZE);
        }
        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) {
			auto err = "ptrace traceme failed ", std::strerror(errno) 
            throw zkexcept::ptrace_error("ptrace traceme failed");
        }
        if (execvp(pathname[0], pathname) == -1) {
            throw zkexcept::process_error("failed to exec given file");
        }
    } else if (p_pid > 0) {
        wait_for_process(0);
    } else {
        throw zkexcept::process_error("forking failed\n");
    }
}

template <typename T>
void zkprocess::Ptrace<T>::detach_from_process(void) {
    if (!ZK_CHECK_FLAGS(PTRACE_ATTACH_NOW, p_flags) &&
        !ZK_CHECK_FLAGS(PTRACE_START_NOW, p_flags)) {
        return;
    }
    if (ptrace(PTRACE_DETACH, p_pid, nullptr, nullptr) < 0) {
        throw zkexcept::ptrace_error("ptrace detach failed\n");
    }
    p_state = PROCESS_STATE_DETACHED;
}

template <typename T>
void zkprocess::Ptrace<T>::kill_process(void) {
    if (ptrace(PTRACE_KILL, p_pid, nullptr, nullptr) < 0) {
        throw zkexcept::ptrace_error("ptrace kill failed\n");
    }
    p_state = PROCESS_STATE_SIGNALED;
    p_state_info.signal_terminated.st_term_sig = SIGKILL;
}

template <typename T>
bool zkprocess::Ptrace<T>::continue_process(bool pass_signal) {
    RETURN_IF_EXITED(false)
    RETURN_IF_NOT_STOPPED(false)

    if (pass_signal) {
        if (p_state_info.signal_stopped.ss_ptrace_stop ==
            PTRACE_STOP_SIGNAL_DELIVERY) {
            if (ptrace(PTRACE_CONT, p_pid, nullptr,
                       p_state_info.signal_stopped.ss_stop_sig) < 0) {
                throw zkexcept::ptrace_error("ptrace continue failed\n");
            }
        } else {
            goto continue_without_signal;
        }
    } else {
    continue_without_signal:
        if (ptrace(PTRACE_CONT, p_pid, nullptr, nullptr) < 0) {
            throw zkexcept::ptrace_error("ptrace continue failed\n");
        }
    }
    p_state = PROCESS_STATE_CONTINUED;
    return true;
}

/*
zkprocess::PROCESS_STATE ZkProcess::Ptrace<T>::InterruptProcess(void)
{
    if (ptrace(PTRACE_INTERRUPT, p_pid, nullptr, nullptr) < 0)
        throw zkexcept::ptrace_error("ptrace interrupt failedb\n");

}
*/

/* find a way to extract ptrace-stop information from status
 * find a way to stop processes
 */

template <typename T>
zkprocess::PROCESS_STATE zkprocess::Ptrace<T>::wait_for_process(
    int options) {
    if (p_log.has_value()) {
        p_log.value()->push_log("process id is not specified",
                                zklog::log_level::LOG_LEVEL_ERROR);
        return zkprocess::PROCESS_STATE_FAILED;
    }
    int wstatus = 0;
    pid_t pid = waitpid(p_pid, &wstatus, options);
    // if child exited normally
    if (WIFEXITED(wstatus)) {
        p_state_info.exited.e_exit_status = WEXITSTATUS(wstatus);
        p_state = PROCESS_STATE_EXITED;
        return p_state;
    }
    // if child was terminated by a signal
    else if (WIFSIGNALED(wstatus)) {
        p_state_info.signal_terminated.st_term_sig = WTERMSIG(wstatus);
        p_state_info.signal_terminated.st_is_coredumped =
            WCOREDUMP(wstatus);
        p_state = PROCESS_STATE_SIGNALED;
        return p_state;
    }
    // if child was stopped by a singal
    else if (WIFSTOPPED(wstatus) && pid > 0) {
        p_state = PROCESS_STATE_STOPPED;
        p_state_info.signal_stopped.ss_stop_sig = WSTOPSIG(wstatus);
        // if the signal is a stop signal - SIGSTOP, SIGTSTP, SIGTTOU,
        // SIGTTIN
        if (p_state_info.signal_stopped.ss_stop_sig == SIGSTOP ||
            p_state_info.signal_stopped.ss_stop_sig == SIGTSTP ||
            p_state_info.signal_stopped.ss_stop_sig == SIGTTOU ||
            p_state_info.signal_stopped.ss_stop_sig == SIGTTIN) {
            // if result of the query GETSETINGO is EINVAL or ESRCH
            // it is a group stop.
            //
            siginfo_t siginfo;
            if (ptrace(PTRACE_GETSIGINFO, p_pid, nullptr, &siginfo) < 0) {
                if (errno == EINVAL || errno == ESRCH) {
                    p_state_info.signal_stopped.ss_ptrace_stop =
                        PTRACE_STOP_GROUP;
                    return p_state;
                }
            }
            // if status >> 16 ==  PTRACE_EVENT_STOP, it is a stop
            // caused by PTRACE_SEIZE and is a group stop.
            // event code is set to PTRACE_EVENT_STOP
            if (wstatus >> 16 == PTRACE_EVENT_STOP) {
                p_state_info.signal_stopped.ss_ptrace_stop =
                    PTRACE_STOP_GROUP;
                p_state_info.signal_stopped.ss_ptrace_event =
                    PTRACE_EVENT_STOP;
            }
        } else if (p_state_info.signal_stopped.ss_stop_sig == SIGTRAP) {
            // if signal is a debugger trap - SIGTRAP. it is a
            // PRTRACE_EVENT stop. (wstatus >> 8) indicates the event
            // that caused the stop.
            // These events are essentially set by PTRACE_O_TRACE options.
            switch (wstatus >> 8) {
                case GET_PTRACE_EVENT_VALUE(PTRACE_EVENT_VFORK):
                    p_state_info.signal_stopped.ss_ptrace_stop =
                        PTRACE_STOP_PTRACE_EVENT;
                    p_state_info.signal_stopped.ss_ptrace_event =
                        PTRACE_EVENT_VFORK;
                    return p_state;
                case GET_PTRACE_EVENT_VALUE(PTRACE_EVENT_FORK):
                    p_state_info.signal_stopped.ss_ptrace_stop =
                        PTRACE_STOP_PTRACE_EVENT;
                    p_state_info.signal_stopped.ss_ptrace_event =
                        PTRACE_EVENT_FORK;
                    return p_state;
                case GET_PTRACE_EVENT_VALUE(PTRACE_EVENT_CLONE):
                    p_state_info.signal_stopped.ss_ptrace_stop =
                        PTRACE_STOP_PTRACE_EVENT;
                    p_state_info.signal_stopped.ss_ptrace_event =
                        PTRACE_EVENT_CLONE;
                    return p_state;
                case GET_PTRACE_EVENT_VALUE(PTRACE_EVENT_VFORK_DONE):
                    p_state_info.signal_stopped.ss_ptrace_stop =
                        PTRACE_STOP_PTRACE_EVENT;
                    p_state_info.signal_stopped.ss_ptrace_event =
                        PTRACE_EVENT_VFORK_DONE;
                    return p_state;
                case GET_PTRACE_EVENT_VALUE(PTRACE_EVENT_EXEC):
                    p_state_info.signal_stopped.ss_ptrace_stop =
                        PTRACE_STOP_PTRACE_EVENT;
                    p_state_info.signal_stopped.ss_ptrace_event =
                        PTRACE_EVENT_EXEC;
                    return p_state;
                case GET_PTRACE_EVENT_VALUE(PTRACE_EVENT_EXIT):
                    p_state_info.signal_stopped.ss_ptrace_stop =
                        PTRACE_STOP_PTRACE_EVENT;
                    p_state_info.signal_stopped.ss_ptrace_event =
                        PTRACE_EVENT_EXIT;
                    return p_state;
                case GET_PTRACE_EVENT_VALUE(PTRACE_EVENT_SECCOMP):
                    p_state_info.signal_stopped.ss_ptrace_stop =
                        PTRACE_STOP_PTRACE_EVENT;
                    p_state_info.signal_stopped.ss_ptrace_event =
                        PTRACE_EVENT_SECCOMP;
                    return p_state;
            }
            // if signal is a debugger trap and PTRACE_GETSIGINFO returns
            // si_code == SIGTRAP or si_code == (SIGTRAP | 0x80),
            // it is a syscall-enter-stop or syscall-exit-stop
            siginfo_t siginfo;
            if (ptrace(PTRACE_GETSIGINFO, p_pid, nullptr, &siginfo) < 0)
                throw zkexcept::ptrace_error("ptrace getsiginfo failed");
            if (siginfo.si_code == SIGTRAP ||
                siginfo.si_code == (SIGTRAP | 0x80)) {
                p_state_info.signal_stopped.ss_ptrace_stop =
                    PTRACE_STOP_SYSCALL;
                return p_state;
            }
        }
        // if signal is not either a debug trap or a stop call, it is then
        // a signal delivery stop.
        //
        else {
            p_state_info.signal_stopped.ss_ptrace_stop =
                PTRACE_STOP_SIGNAL_DELIVERY;
            return p_state;
        }
    } else if (WIFCONTINUED(wstatus)) {
        p_state = PROCESS_STATE_CONTINUED;
    } else {
        p_state = PROCESS_STATE_FAILED;
    }
    return p_state;
}

// generate a random address
template <typename T>
typename T::addr_t zkprocess::Ptrace<T>::generate_address(int seed) const {
    std::mt19937_64 gen(seed);
    std::uniform_int_distribution<zktypes::u64_t> distr(0,
                                                        0x7ffffffffffffff);

    return distr(gen);
}

template <typename T>
bool zkprocess::Ptrace<T>::read_process_memory(void *buffer,
                                               typename T::addr_t address,
                                               size_t buffer_sz) {
    CHECKFLAGS_AND_ATTACH

    RETURN_IF_EXITED(false)
    RETURN_IF_NOT_STOPPED(false)

    typename T::addr_t addr = address;
    zktypes::u8_t *dst = (zktypes::u8_t *)buffer;
    typename T::addr_t data;
    for (int i = 0; i < (buffer_sz / sizeof(typename T::addr_t));
         addr += sizeof(typename T::addr_t),
             dst += sizeof(typename T::addr_t), ++i) {
        data = ptrace(PTRACE_PEEKTEXT, p_pid, addr, nullptr);
        if (data < 0) {
            throw zkexcept::ptrace_error("ptrace peektext failed\n");
        }
        *(typename T::addr_t *)dst = data;
    }

    CHECKFLAGS_AND_DETACH

    return false;
}

template <typename T>
typename T::addr_t zkprocess::Ptrace<T>::write_process_memory(
    void *buffer, typename T::addr_t address, size_t buffer_sz) {
    CHECKFLAGS_AND_ATTACH

    RETURN_IF_EXITED(0)
    RETURN_IF_NOT_STOPPED(0)

    typename T::addr_t addr = address;
    /* TODO add this block to zkprocess's write process memory
    if (addr == 0x0){
        while (true){
            addr = GenerateAddress(buffer_sz);
            std::cout << std::hex << addr << std::endl;
            if (p_memmap->IsMapped(addr) ==  false) {
                break;
            }
        }
    }
    */
    //  if buffer size is greater than the maximum size of data
    //  ptrace can write from a single call - (sizeof(addr_t))
    //  and
    //  can be evenly divide by that size
    //
    if (buffer_sz > sizeof(typename T::addr_t) &&
        (buffer_sz % sizeof(typename T::addr_t)) == 0) {
        zktypes::u8_t *src = (zktypes::u8_t *)buffer;
        for (int i = 0; i < (buffer_sz / sizeof(typename T::addr_t));
             addr += sizeof(typename T::addr_t),
                 src += sizeof(typename T::addr_t), ++i) {
            if (ptrace(PTRACE_POKETEXT, p_pid, addr, src) < 0) {
                throw zkexcept::ptrace_error("ptrace poketext failed\n");
            }
        }
    }
    // if buffer size is less than max size of ptace can write
    else if (buffer_sz < sizeof(typename T::addr_t)) {
        // read what is at that address, and replace original data
        try {
            zktypes::u64_t o_buffer = 0x0;
            read_process_memory(&o_buffer, addr,
                                sizeof(typename T::addr_t));
            o_buffer =
                (((o_buffer) & (0xffffffffffffffff << (buffer_sz * 8))) |
                 o_buffer);
            if (ptrace(PTRACE_POKETEXT, p_pid, addr, &o_buffer) < 0) {
                throw zkexcept::ptrace_error("ptrace poketext failed");
            }
        } catch (zkexcept::ptrace_error &e) {
            std::cerr << e.what();
            std::exit(1);
        }
    } else if (buffer_sz % sizeof(typename T::addr_t) != 0) {
        int count = buffer_sz / sizeof(typename T::addr_t);
        int remainder = buffer_sz % sizeof(typename T::addr_t);

        // write sizeof(addr_t) size chunks
        zktypes::u8_t *src = (zktypes::u8_t *)buffer;
        for (int i = 0; i < count; addr += sizeof(typename T::addr_t),
                 src += sizeof(typename T::addr_t)) {
            if (ptrace(PTRACE_POKETEXT, p_pid, addr, src) < 0) {
                throw zkexcept::ptrace_error("ptrace poketext failed\n");
            }
        }
        // write remaining bytes
        try {
            zktypes::u64_t o_buffer = 0x0;
            read_process_memory(&o_buffer, addr,
                                sizeof(typename T::addr_t));
            o_buffer =
                (((o_buffer) & (0xffffffffffffffff << (remainder * 8))) |
                 o_buffer);
            if (ptrace(PTRACE_POKETEXT, p_pid, addr, &o_buffer) < 0) {
                throw zkexcept::ptrace_error("ptrace poketext failed\n");
            }
        } catch (zkexcept::ptrace_error &e) {
            std::cerr << e.what();
            std::exit(1);
        }
    }

    CHECKFLAGS_AND_DETACH

    return addr;
}

template <typename T>
bool zkprocess::Ptrace<T>::read_process_registers(
    const registers_t &registers) {
    CHECKFLAGS_AND_ATTACH

    RETURN_IF_EXITED(false)
    RETURN_IF_NOT_STOPPED(false)

    if (ptrace(PTRACE_GETREGS, p_pid, nullptr, &registers) < 0) {
        throw zkexcept::ptrace_error("ptrace getregs failed\n");
    }

    CHECKFLAGS_AND_DETACH

    return true;
}

template <typename T>
bool zkprocess::Ptrace<T>::write_process_registers(
    const registers_t &registers) {
    CHECKFLAGS_AND_ATTACH

    RETURN_IF_EXITED(false)
    RETURN_IF_NOT_STOPPED(false)

    if (ptrace(PTRACE_SETREGS, p_pid, nullptr, &registers) < 0) {
        throw zkexcept::ptrace_error("ptrace setregs failed\n");
    }

    CHECKFLAGS_AND_DETACH

    return true;
}

template <typename T>
void *zkprocess::Ptrace<T>::replace_memory_page(typename T::addr_t addr,
                                                void *buffer,
                                                int buffer_size) {
    CHECKFLAGS_AND_ATTACH

    RETURN_IF_EXITED(nullptr)
    RETURN_IF_NOT_STOPPED(nullptr)

    void *data = malloc(ZK_PAGE_ALIGN_UP(buffer_size));
    if (data == nullptr) {
        throw std::runtime_error("failed allocate memory\n");
        return nullptr;
    }
    memset(data, 0, ZK_PAGE_ALIGN_UP(buffer_size));
    try {
        read_process_memory(data, addr, ZK_PAGE_ALIGN_UP(buffer_size));
    } catch (zkexcept::ptrace_error &e) {
        std::cerr << e.what();
        std::exit(1);
    }

    try {
        write_process_memory(buffer, addr, buffer_size);
    } catch (zkexcept::ptrace_error &e) {
        std::cerr << e.what();
        std::exit(1);
    }

    zktypes::u8_t nop_array[ZK_PAGE_ALIGN_UP(buffer_size) - buffer_size];
    memset(nop_array, 0x90, sizeof(nop_array));
    try {
        write_process_memory(nop_array, addr + buffer_size,
                             sizeof(nop_array));
    } catch (zkexcept::ptrace_error &e) {
        std::cerr << e.what();
        std::exit(1);
    }

    CHECKFLAGS_AND_DETACH

    return data;
}

/*
 * Inject a small shellcode into an executable memory segment
 * which calls mmap
 * if protection is not null or something, inject another shellcode that
 * calls mprotect
 */
/* TODO move this to zkprocess.hh / zkprocess.cc
void *zkprocess::Ptrace<T>::MemAlloc(void *mmap_shellcode, int protection,
        int size)
{
    CHECKFLAGS_AND_ATTACH

    RETURN_IF_EXITED(nullptr)
    RETURN_IF_NOT_STOPPED(nullptr)

    if (p_snapshot != nullptr) {

    }
    Snapshot snapshot = Snapshot();
    snapshot.SaveSnapshot(*this, PROCESS_SNAP_FUNC);
    if (mmap_shellcode != nullptr){
        // Write given shellcode to a random address
        addr_t shellcode_addr = WriteProcess(mmap_shellcode, 0, size);
        registers_t regs;
        ReadRegisters(&regs);
        regs.rip = shellcode_addr;

    }
#ifdef __BITS_64__

#elif __BITS_32__

#endif

    CHECKFLAGS_AND_DETACH

    return nullptr;
}
*/

template class zkprocess::Ptrace<x64>;
template class zkprocess::Ptrace<x86>;
