#include "zkexcept.hh"
#include "zkproc.hh"
#include "zktypes.hh"
#include <stdexcept>
#include <sys/ptrace.h>
#include <cstring>

Process::Ptrace::Ptrace(const char **pathname , pid_t pid, u8 flags)
    :p_pid(pid), p_flags(flags)
{
    if (CHECK_FLAGS(PTRACE_ATTACH_NOW, p_flags) && CHECK_FLAGS(PTRACE_START_NOW, p_flags)){
        throw std::invalid_argument("flags ATTACH_NOW and START_NOW cannot be used at the \
                same time");
    }
    /* if a pid and PTRACE_ATTACH_NOW is specified, attach to the pid */
    else if(CHECK_FLAGS(PTRACE_ATTACH_NOW, p_flags) && p_pid != 0){
        try{
            AttachToPorcess();
        } catch(zkexcept::ptrace_error& e){
            std::cerr << e.what() << std::endl;
            std::exit(1);
        }
        p_memmap = std::make_shared<MemoryMap>(p_pid, 0);
    /* if pathname is specified and pid is not, a process will be spawed */
    }else if(CHECK_FLAGS(PTRACE_START_NOW, p_flags) && pathname != nullptr
            && p_pid == 0){
        try{
            PROCESS_STATE ret = StartProcess((char **)pathname);
            if(ret == PROCESS_STATE_EXITED || ret == PROCESS_STATE_FAILED)
                throw zkexcept::ptrace_error("start process failed\n");
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
        throw std::invalid_argument();
    }
}

Process::Ptrace::~Ptrace()
{
    if(CHECK_FLAGS(PTRACE_ATTACH_NOW, p_flags) || 
            CHECK_FLAGS(PTRACE_START_NOW, p_flags))
        DetachFromProcess();
}

void Process::Ptrace::AttachToPorcess(void) const
{
    if(ptrace(PTRACE_ATTACH, p_pid, nullptr, nullptr) < 0)
        throw zkexcept::ptrace_error("ptrace attach failed\n");

    PROCESS_STATE ret = WaitForProcess();
    if(ret == PROCESS_STATE_EXITED) throw zkexcept::ptrace_error();
    return;
}

void Process::Ptrace::DetachFromProcess(void) const
{
    if(ptrace(PTRACE_DETACH, p_pid, nullptr, nullptr) < 0)
        throw zkexcept::ptrace_error("ptrace detach failed\n");
}

Process::PROCESS_STATE Process::Ptrace::StartProcess(char **pathname)
{
    p_pid = fork();
    if(p_pid == 0){
        if(CHECK_FLAGS(p_flags, PTRACE_DISABLE_ASLR))
            personality(ADDR_NO_RANDOMIZE);
        if(ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0)
            throw zkexcept::ptrace_error("aslr disabling failed\n");
        if(execvp(pathname[0], pathname) == -1)
            std::exit(EXIT_FAILURE);
    }
    else if(p_pid > 0) {
        PROCESS_STATE ret = WaitForProcess();
        if(ret == PROCESS_STATE_EXITED) return PROCESS_STATE_EXITED;
        else if(ret == PROCESS_STATE_STOPPED) return PROCESS_STATE_STOPPED;
        else if(ret == PROCESS_STATE_SIGNALED) return PROCESS_STATE_SIGNALED;
        else if(ret == PROCESS_STATE_CONTINUED) 
            return PROCESS_STATE_CONTINUED;
        else return PROCESS_STATE_FAILED;
    }
    throw zkexcept::process_error("forking failed\n");
}

Process::PROCESS_STATE Process::Ptrace::WaitForProcess(void) const
{
    assert(p_pid != 0 && "Process ID is not set");
    int wstatus = 0;
    waitpid(p_pid, &wstatus, 0);
    if(WIFEXITED(wstatus)) return PROCESS_STATE_EXITED;
    else if(WIFSTOPPED(wstatus)) return PROCESS_STATE_STOPPED;
    else if(WIFSIGNALED(wstatus)) return PROCESS_STATE_SIGNALED;
    else if(WIFCONTINUED(wstatus)) return PROCESS_STATE_CONTINUED;

    return PROCESS_STATE_FAILED;
}

void Process::Ptrace::ReadProcess(void *buffer, addr_t address, size_t 
        buffer_sz) const
{
    /* if not already attached or started, attach */
    if(!CHECK_FLAGS(PTRACE_ATTACH_NOW, p_flags) || 
            !CHECK_FLAGS(PTRACE_START_NOW, p_flags)) AttachToPorcess();

    addr_t addr = address;
    u8 *dst = (u8 *)buffer;
    addr_t data;
    for (int i = 0; i < (buffer_sz /  sizeof(addr_t)); addr+=sizeof(addr_t)
            , dst+=sizeof(addr_t)){
        data = ptrace(PTRACE_PEEKTEXT, p_pid, addr, nullptr);
        if(data < 0)
            throw zkexcept::ptrace_error();
        *(addr_t *)dst = data;
    }
    if(!CHECK_FLAGS(PTRACE_ATTACH_NOW, p_flags) || 
            !CHECK_FLAGS(PTRACE_START_NOW, p_flags)) DetachFromProcess();
    return;
}

void Process::Ptrace::WriteProcess(void *buffer, addr_t address, size_t 
        buffer_sz) const
{
    if(!CHECK_FLAGS(PTRACE_ATTACH_NOW, p_flags) || 
            !CHECK_FLAGS(PTRACE_START_NOW, p_flags)) AttachToPorcess();

    u8 *src = (u8 *)buffer;
    addr_t addr = address;

    if (addr == 0x0){
        while (true){
            addr = GenerateAddress(buffer_sz);
            if (p_memmap->IsMapped(addr) ==  false) {
                break;
            }
        }
    }
    for (int i = 0; i < (buffer_sz / sizeof(addr_t)); addr+=sizeof(addr_t), 
            src+=sizeof(addr_t)){
        if(ptrace(PTRACE_POKETEXT, p_pid, addr, src)  < 0){
            throw zkexcept::ptrace_error();
        }
    }

    if(!CHECK_FLAGS(PTRACE_ATTACH_NOW, p_flags) ||
            !CHECK_FLAGS(PTRACE_START_NOW, p_flags)) DetachFromProcess();
    return;
}

void Process::Ptrace::ReadRegisters(registers_t* registers) const
{
    if(!CHECK_FLAGS(PTRACE_ATTACH_NOW, p_flags) || 
            !CHECK_FLAGS(PTRACE_START_NOW, p_flags)) AttachToPorcess();

    if(ptrace(PTRACE_GETREGS, p_pid, nullptr, registers)  < 0)
        throw zkexcept::ptrace_error();

    if(!CHECK_FLAGS(PTRACE_ATTACH_NOW, p_flags) || 
            !CHECK_FLAGS(PTRACE_START_NOW, p_flags)) DetachFromProcess();
}

void Process::Ptrace::WriteRegisters(registers_t* registers) const
{
    if(!CHECK_FLAGS(PTRACE_ATTACH_NOW, p_flags) || 
            !CHECK_FLAGS(PTRACE_START_NOW, p_flags)) AttachToPorcess();

    if(ptrace(PTRACE_SETREGS, p_pid, nullptr, registers) < 0)
        throw zkexcept::ptrace_error();

    if(!CHECK_FLAGS(PTRACE_ATTACH_NOW, p_flags) || 
            !CHECK_FLAGS(PTRACE_START_NOW, p_flags)) DetachFromProcess();
}

void *Process::Ptrace::ReplacePage(addr_t addr, void *buffer, int 
        buffer_size) const
{
    if(!CHECK_FLAGS(PTRACE_ATTACH_NOW, p_flags) || 
            !CHECK_FLAGS(PTRACE_START_NOW, p_flags)) AttachToPorcess();

    void *data = malloc(PAGE_ALIGN_UP(buffer_size));
    if (data == NULL) {
        throw std::runtime_error("failed allocate memory\n");
        return nullptr;
    }
    memset(data, 0, PAGE_ALIGN_UP(buffer_size));
    try { ReadProcess(data, addr, PAGE_ALIGN_UP(buffer_size)); }
    catch (zkexcept::ptrace_error& e) {
        std::cerr << e.what();
        std::exit(1);
    }

    try { WriteProcess(buffer, addr, buffer_size); }
    catch (zkexcept::ptrace_error& e) {
        std::cerr << e.what();
        std::exit(1);
    }

    u8 nop_array[PAGE_ALIGN_UP(buffer_size) - buffer_size];
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
void *Process::Ptrace::MemAlloc(void *mmap_shellcode, int protection, 
        int size)
{
    if(!CHECK_FLAGS(PTRACE_ATTACH_NOW, p_flags) || 
            !CHECK_FLAGS(PTRACE_START_NOW, p_flags)) AttachToPorcess();

    Snapshot snapshot;
    snapshot.SaveSnapshot();
    if (mmap_shellcode != nullptr){
        /* Write given shellcode to a random address */
        WriteProcess(mmap_shellcode, 0, size);
        /* Save a snapshot */
    }
#ifdef __BITS_64__
    
#elif __BITS_32__
    
#endif
}

