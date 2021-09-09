#include "zkproc.hh"
#include <iostream>
#include <cstddef>
#include <memory>
#include <new>
#include <sys/ptrace.h>

Process::Ptrace::Ptrace(const char *pathname , pid_t pid, registers_t& regs, u8 
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
            StartProcess(pathname);
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

    u8 ret = WaitForProcess();
    if(CHECK_FLAGS(ret, PROCESS_STATE_EXITED))
        throw zkexcept::ptrace_error();

    return;
}

pid_t Process::Ptrace::StartProcess(const char *pathname)
{
    pid_t pid = fork();
    if(pid == -1)
        throw zkexcept::process_error("forking failed\n");

    else if(pid == 0){
        if(CHECK_FLAGS(flag, ))
    }
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
