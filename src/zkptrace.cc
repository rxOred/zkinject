#include "zkexcept.hh"
#include "zkproc.hh"
#include <cstdlib>
#include <iostream>
#include <cstddef>
#include <memory>
#include <new>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/personality.h>
#include <sys/ptrace.h>

Process::Ptrace::Ptrace(const char **pathname , pid_t pid, registers_t& regs, u8 
        flags)
    :p_pid(pid), p_registers(regs), p_flags(flags)
{
    if(CHECK_FLAGS(PTRACE_ATTACH_NOW, p_flags) && p_pid != 0){
        try{
            AttachToPorcess();
        } catch(zkexcept::ptrace_error& e){
            std::cerr << e.what() << std::endl;
            std::exit(1);
        }
        p_memmap = std::make_shared<MemoryMap>(p_pid, 0);
    }else if(CHECK_FLAGS(PTRACE_START_NOW, p_flags) && pathname != nullptr){
        try{
            StartProcess((char **)pathname);
        } catch (zkexcept::ptrace_error& e){
            std::cerr << e.what() << std::endl;
            std::exit(1);
        }
        p_memmap = std::make_shared<MemoryMap>(p_pid, 0);
    }
}

void Process::Ptrace::AttachToPorcess(void) const
{
    if(ptrace(PTRACE_ATTACH, p_pid, nullptr, nullptr) < 0)
        throw zkexcept::ptrace_error("ptrace attach failed\n");

    PROCESS_STATE ret = WaitForProcess();
    if(CHECK_FLAGS(ret, PROCESS_STATE_EXITED))
        throw zkexcept::ptrace_error();

    return;
}

void Process::Ptrace::StartProcess(char **pathname)
{
    p_pid = fork();
    if(p_pid == -1)
        throw zkexcept::process_error("forking failed\n");

    else if(p_pid == 0){
        if(CHECK_FLAGS(p_flags, PTRACE_DISABLE_ASLR))
            personality(ADDR_NO_RANDOMIZE);
        if(ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0)
            throw zkexcept::ptrace_error("aslr disabling failed\n");
        if(execvp(pathname[0], pathname) == -1)
            std::exit(EXIT_FAILURE);
    }
    else {
        PROCESS_STATE ret = WaitForProcess();
    }
}

Process::Ptrace::PROCESS_STATE Process::Ptrace::WaitForProcess(void) const
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

template<class T> T Process::Ptrace::ReadProcess(addr_t address, size_t buffer_sz) 
    const
{
    T buffer = (T) malloc(buffer_sz);
    if(buffer == nullptr)
        throw std::bad_alloc();

    memset(buffer, 0, buffer_sz);
    
}

void Process::Ptrace::WriteProcess(void *buffer, addr_t address, size_t buffer_sz)
{
    u64 *src = (u64 *)buffer;
    addr_t addr = address;
    for (int i = 0; i < (buffer_sz /  sizeof(addr)); addr+=sizeof(addr_t), 
            src+=sizeof(addr_t)){
        if(ptrace(PTRACE_POKETEXT, p_pid, addr, src)  < 0){
            throw zkexcept::ptrace_error();
        }
    }
    return;
}

registers_t Process::Ptrace::ReadRegisters(void) const
{

}

void Process::Ptrace::WriteRegisters(registers_t& registers) const
{

}
