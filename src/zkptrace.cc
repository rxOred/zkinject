#include "zkexcept.hh"
#include "zkprocess.hh"
#include "zktypes.hh"
#include "zkutils.hh"
#include <asm-generic/errno-base.h>
#include <bits/types/siginfo_t.h>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <stdexcept>
#include <sys/ptrace.h>
#include <cstring>
#include <sys/wait.h>

bool ZkProcess::Ptrace::isPtraceStopped(void) const
{
    if (p_state_info.signal_stopped.ptrace_stop >
            PTRACE_STOP_NOT_STOPPED && 
            p_state_info.signal_stopped.ptrace_stop < 
            PTRACE_STOP_PTRACE_EVENT ||
            p_state == PROCESS_STATE_STOPPED) {
        return true;
    }
    return false;
}

ZkProcess::Ptrace::Ptrace(const char **pathname , pid_t pid, u8 flags,
    ZkLog::Log *log)
    : p_pid(pid), p_flags(flags), p_log(log)
{
    if (ZK_CHECK_FLAGS(PTRACE_ATTACH_NOW, p_flags) &&
            ZK_CHECK_FLAGS(PTRACE_START_NOW, p_flags)){
        throw std::invalid_argument("flags ATTACH_NOW and START_NOW     \
                cannot be used at the same time");
    }
    /* if a pid and PTRACE_ATTACH_NOW is specified, attach to the pid */
    else if(ZK_CHECK_FLAGS(PTRACE_ATTACH_NOW, p_flags) && p_pid != 0){
        try{
            AttachToPorcess();
            if (p_state == PROCESS_STATE_FAILED)
                throw zkexcept::ptrace_error("ptrace attach failed\n");
            else if (p_state == PROCESS_STATE_EXITED)
                throw zkexcept::ptrace_error("child process exited\n");
        } catch(zkexcept::ptrace_error& e){
            std::cerr << e.what() << std::endl;
            std::exit(1);
        }
        p_memmap = std::make_shared<MemoryMap>(p_pid, 0);
    }
    /* if pathname is specified and pid is not,a process will be spawed */
    else if(ZK_CHECK_FLAGS(PTRACE_START_NOW, p_flags) && pathname != nullptr
            && p_pid == 0){
        try{
            StartProcess((char **)pathname);
            if(p_state == PROCESS_STATE_FAILED)
                throw zkexcept::ptrace_error("start process failed\n");
            else if (p_state == PROCESS_STATE_EXITED)
                throw zkexcept::ptrace_error("child process exited\n");
        } catch (zkexcept::ptrace_error& e){
            std::cerr << e.what() << std::endl;
            std::exit(1);
        }
        /*
         * StartProcess set p_pid so we can get the memory map of the
         * process
         */
        p_memmap = std::make_shared<MemoryMap>(p_pid, 0);
    }else {
        throw std::invalid_argument("invalid flag\n");
    }
}

ZkProcess::Ptrace::Ptrace(const char **pathname , pid_t pid, u8 flags)
    : p_pid(pid), p_flags(flags)
{
    if (ZK_CHECK_FLAGS(PTRACE_ATTACH_NOW, p_flags) &&
            ZK_CHECK_FLAGS(PTRACE_START_NOW, p_flags)){
        throw std::invalid_argument("flags ATTACH_NOW and START_NOW     \
                cannot be used at the same time");
    }
    /* if a pid and PTRACE_ATTACH_NOW is specified, attach to the pid */
    else if(ZK_CHECK_FLAGS(PTRACE_ATTACH_NOW, p_flags) && p_pid != 0){
        try{
            AttachToPorcess();
            if (p_state == PROCESS_STATE_FAILED)
                throw zkexcept::ptrace_error("ptrace attach failed\n");
            else if (p_state == PROCESS_STATE_EXITED)
                throw zkexcept::ptrace_error("child process exited\n");
        } catch(zkexcept::ptrace_error& e){
            std::cerr << e.what() << std::endl;
            std::exit(1);
        }
        p_memmap = std::make_shared<MemoryMap>(p_pid, 0);
    }
    /* if pathname is specified and pid is not,a process will be spawed */
    else if(ZK_CHECK_FLAGS(PTRACE_START_NOW, p_flags) && pathname != nullptr
            && p_pid == 0){
        try{
            StartProcess((char **)pathname);
            if(p_state == PROCESS_STATE_FAILED)
                throw zkexcept::ptrace_error("start process failed\n");
            else if (p_state == PROCESS_STATE_EXITED)
                throw zkexcept::ptrace_error("child process exited\n");
        } catch (zkexcept::ptrace_error& e){
            std::cerr << e.what() << std::endl;
            std::exit(1);
        }
        /* 
         * StartProcess set p_pid so we can get the memory map of the 
         * process 
         */
        p_memmap = std::make_shared<MemoryMap>(p_pid, 0);
    }else {
        throw std::invalid_argument("invalid flag\n");
    }
}

ZkProcess::Ptrace::~Ptrace()
{
    if(ZK_CHECK_FLAGS(PTRACE_ATTACH_NOW, p_flags) &&
            ZK_CHECK_FLAGS(PTRACE_START_NOW, p_flags))
        DetachFromProcess();
}

void ZkProcess::Ptrace::AttachToPorcess(void)
{
    if (ptrace(PTRACE_ATTACH, p_pid, nullptr, nullptr) < 0) {
        throw zkexcept::ptrace_error("ptrace attach failed\n");
    }
    WaitForProcess(0);
}


void ZkProcess::Ptrace::SeizeProcess(void)
{
//    if (ptrace(PTRACE_SEIZE, p_pid, nullptr, nullptr) < 0)
//      throw zkexcept::ptrace_error("ptrace seize failed\n");
    p_state = PROCESS_STATE_CONTINUED;
}


void ZkProcess::Ptrace::StartProcess(char **pathname)
{
    p_pid = fork();
    if(p_pid == 0){
        if(ZK_CHECK_FLAGS(p_flags, PTRACE_DISABLE_ASLR))
            personality(ADDR_NO_RANDOMIZE);
        if(ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0)
            throw zkexcept::ptrace_error("ptrace traceme failed\n");
        if(execvp(pathname[0], pathname) == -1)
            std::exit(EXIT_FAILURE);
    }
    else if(p_pid > 0) {
        WaitForProcess(0);
    }
    else
        throw zkexcept::process_error("forking failed\n");
}

void ZkProcess::Ptrace::DetachFromProcess(void)
{
    if(ptrace(PTRACE_DETACH, p_pid, nullptr, nullptr) < 0)
        throw zkexcept::ptrace_error("ptrace detach failed\n");
    p_state = PROCESS_STATE_DETACHED;
}

void ZkProcess::Ptrace::KillProcess(void)
{
    if (ptrace(PTRACE_KILL, p_pid, nullptr, nullptr) < 0)
        throw zkexcept::ptrace_error("ptrace kill failed\n");
    p_state = PROCESS_STATE_SIGNALED;
    p_state_info.signal_terminated.term_sig = SIGKILL; 
}

bool ZkProcess::Ptrace::ContinueProcess(bool pass_signal)
{
    RETURN_IF_EXITED(false)
    RETURN_IF_NOT_STOPPED(false)

    if (p_state_info.signal_stopped.ptrace_stop ==
            PTRACE_STOP_SIGNAL_DELIVERY) {
        if (ptrace(PTRACE_CONT, p_pid, nullptr,
                    p_state_info.signal_stopped.stop_sig) < 0) {
            throw zkexcept::ptrace_error("ptrace continue failed\n");
        }
    }
    else {
        if (ptrace(PTRACE_CONT, p_pid, nullptr, nullptr) < 0)
            throw zkexcept::ptrace_error("ptrace continue failed\n");
    }
    p_state = PROCESS_STATE_CONTINUED;
}

/*
ZkProcess::PROCESS_STATE ZkProcess::Ptrace::InterruptProcess(void)
{
    if (ptrace(PTRACE_INTERRUPT, p_pid, nullptr, nullptr) < 0)
        throw zkexcept::ptrace_error("ptrace interrupt failedb\n");
    
}
*/

/* find a way to extract ptrace-stop information from status
 * find a way to stop processes 
 */

void ZkProcess::Ptrace::WaitForProcess(int options)
{
    assert(p_pid != 0 && "Process ID is not set");
    int wstatus = 0;
    waitpid(p_pid, &wstatus, options);
    /* if child exited normally */
    if (WIFEXITED(wstatus)) {
        p_state_info.exited.exit_status = WEXITSTATUS(wstatus);
        p_state = PROCESS_STATE_EXITED;
        return;
    } 
    /* if child was terminated by a signal */
    else if (WIFSIGNALED(wstatus)) {
        p_state_info.signal_terminated.term_sig = WTERMSIG(wstatus);    
        p_state_info.signal_terminated.is_coredumped = WCOREDUMP(wstatus);
        p_state = PROCESS_STATE_SIGNALED;
        return;
    } 
    /* if child was stopped by a singal */
    else if (WIFSTOPPED(wstatus)) {
        p_state = PROCESS_STATE_STOPPED;
        p_state_info.signal_stopped.stop_sig = WSTOPSIG(wstatus);
        /* if the signal is a stop signal */
        if (p_state_info.signal_stopped.stop_sig == SIGSTOP ||
                p_state_info.signal_stopped.stop_sig == SIGTSTP ||
                p_state_info.signal_stopped.stop_sig == SIGTTOU ||
                p_state_info.signal_stopped.stop_sig ==  SIGTTIN) {
            /* 
             * if result of the query GETSETINGO is EINVAL or ESRCH 
             * it is a group stop.
             */ 
            siginfo_t siginfo; 
            if (ptrace(PTRACE_GETSIGINFO, p_pid, nullptr, &siginfo) < 0) {
                if (errno == EINVAL || errno ==  ESRCH) {
                    p_state_info.signal_stopped.ptrace_stop = 
                        PTRACE_STOP_GROUP;
                    return;
                }
            }
            /*
             * if status >> 16 ==  PTRACE_EVENT_STOP, it is a 
             * ptrace event
             */
            if (wstatus >> 16 ==  PTRACE_EVENT_STOP) {
                p_state_info.signal_stopped.ptrace_stop = 
                    PTRACE_STOP_PTRACE_EVENT;
                p_state_info.signal_stopped.ptrace_event = 
                    PTRACE_EVENT_STOP;
            }
        }
        /* if signal is a debug trap */
        else if (p_state_info.signal_stopped.stop_sig == SIGTRAP) {
            switch (wstatus >> 8) {
                case GET_PTRACE_EVENT_VALUE(PTRACE_EVENT_VFORK):
                    p_state_info.signal_stopped.ptrace_stop = 
                        PTRACE_STOP_PTRACE_EVENT;
                    p_state_info.signal_stopped.ptrace_event = 
                        PTRACE_EVENT_VFORK;
                    return;
                case GET_PTRACE_EVENT_VALUE(PTRACE_EVENT_FORK):
                    p_state_info.signal_stopped.ptrace_stop = 
                        PTRACE_STOP_PTRACE_EVENT;
                    p_state_info.signal_stopped.ptrace_event = 
                        PTRACE_EVENT_FORK;
                    return;
                case GET_PTRACE_EVENT_VALUE(PTRACE_EVENT_CLONE):
                    p_state_info.signal_stopped.ptrace_stop = 
                        PTRACE_STOP_PTRACE_EVENT;
                    p_state_info.signal_stopped.ptrace_event = 
                        PTRACE_EVENT_CLONE;
                    return;
                case GET_PTRACE_EVENT_VALUE(PTRACE_EVENT_VFORK_DONE):
                    p_state_info.signal_stopped.ptrace_stop = 
                        PTRACE_STOP_PTRACE_EVENT;
                    p_state_info.signal_stopped.ptrace_event = 
                        PTRACE_EVENT_VFORK_DONE;
                    return;
                case GET_PTRACE_EVENT_VALUE(PTRACE_EVENT_EXEC):
                    p_state_info.signal_stopped.ptrace_stop = 
                        PTRACE_STOP_PTRACE_EVENT;
                    p_state_info.signal_stopped.ptrace_event =
                        PTRACE_EVENT_EXEC;
                    return;
                case GET_PTRACE_EVENT_VALUE(PTRACE_EVENT_EXIT):
                    p_state_info.signal_stopped.ptrace_stop = 
                        PTRACE_STOP_PTRACE_EVENT;
                    p_state_info.signal_stopped.ptrace_event = 
                        PTRACE_EVENT_EXIT;
                    return;
                case GET_PTRACE_EVENT_VALUE(PTRACE_EVENT_SECCOMP):
                    p_state_info.signal_stopped.ptrace_stop = 
                        PTRACE_STOP_PTRACE_EVENT;
                    p_state_info.signal_stopped.ptrace_event = 
                        PTRACE_EVENT_SECCOMP;
                    return;
            }
            siginfo_t siginfo;
            if (ptrace(PTRACE_GETSIGINFO, p_pid, nullptr, &siginfo) < 0) 
                throw zkexcept::ptrace_error("ptrace getsiginfo failed");
            if (siginfo.si_code == SIGTRAP || siginfo.si_code == 
                    (SIGTRAP | 0x80)) {
                p_state_info.signal_stopped.ptrace_stop = 
                    PTRACE_STOP_SYSCALL;
                return;
            }
        }
        else {
            p_state_info.signal_stopped.ptrace_stop = 
                PTRACE_STOP_SIGNAL_DELIVERY;
            return;
        }
    }
    else if (WIFCONTINUED(wstatus)) {
        p_state = PROCESS_STATE_CONTINUED;
    }
    else {
        p_state = PROCESS_STATE_FAILED;
    }
}

/* generate a random address */
addr_t ZkProcess::Ptrace::GenerateAddress(int seed) const 
{
    std::mt19937_64 gen(seed);
    std::uniform_int_distribution<u64> distr(0, 0x7ffffffffffffff);

    return distr(gen);
}

bool ZkProcess::Ptrace::ReadProcess(void *buffer, addr_t address, size_t
        buffer_sz) 
{
    CHECKFLAGS_AND_ATTACH

    RETURN_IF_EXITED(false)
    RETURN_IF_NOT_STOPPED(false)

    addr_t addr = address;
    u8 *dst = (u8 *)buffer;
    addr_t data;
    for (int i = 0; i < (buffer_sz /  sizeof(addr_t)); addr+=sizeof(
                addr_t), dst+=sizeof(addr_t)){
        data = ptrace(PTRACE_PEEKTEXT, p_pid, addr, nullptr);
        if(data < 0)
            throw zkexcept::ptrace_error("ptrace peektext failed\n");
        *(addr_t *)dst = data;
    }

    CHECKFLAGS_AND_DETACH

    return false;
}

addr_t ZkProcess::Ptrace::WriteProcess(void *buffer, addr_t address, size_t 
        buffer_sz) 
{
    CHECKFLAGS_AND_ATTACH

    RETURN_IF_EXITED(0)
    RETURN_IF_NOT_STOPPED(0)

    addr_t addr = address;

    if (addr == 0x0){
        while (true){
            addr = GenerateAddress(buffer_sz);
            if (p_memmap->IsMapped(addr) ==  false) {
                break;
            }
        }
    }
    /* 
     * if buffer size is greater than the maximum size of data 
     * ptrace can write from a single call - (sizeof(addr_t)) 
     * and
     * can be evenly divide by that size 
     */
    if (buffer_sz > sizeof(addr_t) && (buffer_sz % sizeof(addr_t)) ==  0){
        u8 *src = (u8 *)buffer;
        for (int i = 0; i < (buffer_sz / sizeof(addr_t)); 
                addr+=sizeof(addr_t), 
                src+=sizeof(addr_t)){
            if (ptrace(PTRACE_POKETEXT, p_pid, addr, src)  < 0) {
                throw zkexcept::ptrace_error("ptrace poketext failed\n");
            }
        }
    }
    /* 
     * if buffer size is less than max size of ptace can write 
     */
    else if (buffer_sz < sizeof(addr_t)) {
        /* 
         * read what is at that address, and replace original data 
         */
        try{
            u64 o_buffer = 0x0;
            ReadProcess(&o_buffer, addr, sizeof(addr_t));
            o_buffer = (((o_buffer) & (0xffffffffffffffff << (buffer_sz 
                                * 8))) | o_buffer);     
            if (ptrace(PTRACE_POKETEXT, p_pid, addr, &o_buffer)  < 0) {
                throw zkexcept::ptrace_error("ptrace poketext failed");
            }
        } catch(zkexcept::ptrace_error& e){
            std::cerr << e.what();
            std::exit(1);
        }
    }
    else if (buffer_sz % sizeof(addr_t) != 0) {
        int count = buffer_sz / sizeof(addr_t);
        int remainder = buffer_sz % sizeof(addr_t);

        /* write sizeof(addr_t) size chunks */
        u8 *src = (u8 *)buffer;
        for (int i = 0; i < count; addr+=sizeof(addr_t), 
                src+=sizeof(addr_t)) {
            if(ptrace(PTRACE_POKETEXT, p_pid, addr, src)  < 0){
                throw zkexcept::ptrace_error("ptrace poketext failed\n");
            }
        }
        /* write remaining bytes */ 
        try{
            u64 o_buffer = 0x0;
            ReadProcess(&o_buffer, addr, sizeof(addr_t));
            o_buffer = (((o_buffer) & (0xffffffffffffffff << (remainder 
                                * 8))) | o_buffer);     
            if(ptrace(PTRACE_POKETEXT, p_pid, addr, &o_buffer)  < 0){
                throw zkexcept::ptrace_error("ptrace poketext failed\n");
            }
        } catch(zkexcept::ptrace_error& e){
            std::cerr << e.what();
            std::exit(1);
        }
    }

    CHECKFLAGS_AND_DETACH

    return addr;
}

bool ZkProcess::Ptrace::ReadRegisters(registers_t* registers)
{
    CHECKFLAGS_AND_ATTACH

    RETURN_IF_EXITED(false)
    RETURN_IF_NOT_STOPPED(false)

    if(ptrace(PTRACE_GETREGS, p_pid, nullptr, registers)  < 0)
        throw zkexcept::ptrace_error("ptrace getregs failed\n");

    CHECKFLAGS_AND_DETACH

    return true;
}

bool ZkProcess::Ptrace::WriteRegisters(registers_t* registers)
{
    if(!ZK_CHECK_FLAGS(PTRACE_ATTACH_NOW, p_flags) &&
            !ZK_CHECK_FLAGS(PTRACE_START_NOW, p_flags)) AttachToPorcess();

    RETURN_IF_EXITED(false)
    RETURN_IF_NOT_STOPPED(false)

    if(ptrace(PTRACE_SETREGS, p_pid, nullptr, registers) < 0)
        throw zkexcept::ptrace_error("ptrace setregs failed\n");

    if(!ZK_CHECK_FLAGS(PTRACE_ATTACH_NOW, p_flags) &&
            !ZK_CHECK_FLAGS(PTRACE_START_NOW, p_flags)) DetachFromProcess();
}

void *ZkProcess::Ptrace::ReplacePage(addr_t addr, void *buffer, int 
        buffer_size)
{
    if(!ZK_CHECK_FLAGS(PTRACE_ATTACH_NOW, p_flags) &&
            !ZK_CHECK_FLAGS(PTRACE_START_NOW, p_flags)) AttachToPorcess();

    RETURN_IF_EXITED(nullptr)
    RETURN_IF_NOT_STOPPED(nullptr)

    void *data = malloc(ZK_PAGE_ALIGN_UP(buffer_size));
    if (data == NULL) {
        throw std::runtime_error("failed allocate memory\n");
        return nullptr;
    }
    memset(data, 0, ZK_PAGE_ALIGN_UP(buffer_size));
    try { ReadProcess(data, addr, ZK_PAGE_ALIGN_UP(buffer_size)); }
    catch (zkexcept::ptrace_error& e) {
        std::cerr << e.what();
        std::exit(1);
    }

    try { WriteProcess(buffer, addr, buffer_size); }
    catch (zkexcept::ptrace_error& e) {
        std::cerr << e.what();
        std::exit(1);
    }

    u8 nop_array[ZK_PAGE_ALIGN_UP(buffer_size) - buffer_size];
    memset(nop_array, 0x90, sizeof(nop_array));
    try {
        WriteProcess(nop_array, addr+buffer_size, sizeof(nop_array));
    } catch (zkexcept::ptrace_error& e) {
        std::cerr << e.what();
        std::exit(1);
    }
    return data;
}

/*
 * Inject a small shellcode into an executable memory segment 
 * which calls mmap 
 * if protection is not null or something, inject another shellcode that 
 * calls mprotect
 */
void *ZkProcess::Ptrace::MemAlloc(void *mmap_shellcode, int protection, 
        int size)
{
    if(!ZK_CHECK_FLAGS(PTRACE_ATTACH_NOW, p_flags) &&
            !ZK_CHECK_FLAGS(PTRACE_START_NOW, p_flags)) AttachToPorcess();

    RETURN_IF_EXITED(nullptr)
    RETURN_IF_NOT_STOPPED(nullptr)

    Snapshot snapshot = Snapshot();
    snapshot.SaveSnapshot(*this, PROCESS_SNAP_FUNC);
    if (mmap_shellcode != nullptr){
        /* Write given shellcode to a random address */
        addr_t shellcode_addr = WriteProcess(mmap_shellcode, 0, size);
        registers_t regs;
        ReadRegisters(&regs);
        regs.rip = shellcode_addr;
        
    }
#ifdef __BITS_64__
    
#elif __BITS_32__
    
#endif
    return nullptr;
}
