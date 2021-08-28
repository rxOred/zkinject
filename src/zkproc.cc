#include "zkproc.hh"
#include <cstdio>
#include <new>
#include <sched.h>
#include <iostream>
#include <sstream>
void Process::Proc::SetProcessId(pid_t pid)
{
    proc_id = pid;
}

pid_t Process::Proc::GetProcessId(void) const
{
    return proc_id;
}

Process::Proc::Proc(pid_t pid)
    :proc_id(pid), proc_baseaddr(0)
{
    SetMapPath();
    SetMemPath();
    SetCmdline();
    GetBaseAddress();
}

Process::Proc::~Proc()
{
    if(proc_mappath) free(proc_mappath);
    if(proc_mempath) free(proc_mempath);
    if(proc_cmdline) free(proc_cmdline);
}

void Process::Proc::SetMapPath(void)
{
    proc_mappath = (char *) calloc(PATH_LEN, sizeof(char));
    if(proc_mappath == nullptr)
        throw std::bad_alloc();

    if(proc_id == 0){
        sprintf(proc_mappath, "/proc/self/maps");
    } else {
        sprintf(proc_mappath, MAPPATH, proc_id);
    }
}

void Process::Proc::SetMemPath(void)
{
    proc_mempath = (char *) calloc(PATH_LEN, sizeof(char));
    if(proc_mempath == nullptr)
        throw std::bad_alloc();

    if(proc_id == 0){
        sprintf(proc_mempath, "/proc/self/maps");
    } else {
        sprintf(proc_mempath, MEMPATH, proc_id);
    }
}

void Process::Proc::SetCmdline(void)
{
    proc_cmdline = (char *) calloc(PATH_LEN, sizeof(char));
    if(proc_cmdline == nullptr)
        throw std::bad_alloc();

    if(proc_id == 0){
        sprintf(proc_cmdline, "/proc/self/maps");
    } else {
        sprintf(proc_cmdline, CMDLINE, proc_id);
    }
}

void Process::Proc::SetBaseAddress(void)
{
    assert(proc_mappath != nullptr && "map path is not set");

    Addr baseaddr;
    char addr_buf[ADDR_LEN];
    char *p = addr_buf;

    FILE *fh = fopen(proc_mappath, "r");
    if(!fh)
        throw zkexcept::file_not_found_error();

    for(int i = 0; i < ADDR_LEN; i++, p++){
        *p = fgetc(fh);
        assert(std::isalnum(*p) && "Invalid /proc file");
    }
    sscanf(addr_buf, "%lx", &baseaddr);
    proc_baseaddr = baseaddr;
}

Addr Process::Proc::GetBaseAddress(void) const
{
    return proc_baseaddr;
}

Addr Process::Proc::GetModuleBaseAddress(const char *module_name)
{
    assert(proc_mappath != nullptr && "map path is not set");
    char *addr_buf = (char *)calloc(sizeof(char), ADDR_LEN + 1);
    if(addr_buf == nullptr)
        throw std::bad_alloc();

    std::ifstream fh(proc_mappath);
    std::string line, word;
    const char *_word = nullptr;

    while(std::getline(fh, line)){
        std::stringstream ss(line);

        while(std::getline(ss, word, ' ')){
            _word = word.c_str();
            if(strcmp(_word, module_name) == 0){
                for(int j = 0; j < ADDR_LEN; j++){
                    addr_buf[j] = line[j];
                }
                addr_buf[ADDR_LEN] = '\0';
                Addr address = 0;
                sscanf(addr_buf, "%lx", &address);
                free(addr_buf);
                return address;
            }
        }
    }
    throw zkexcept::proc_file_error();
}
