#include "zkproc.hh"
#include "zktypes.hh"
#include <sched.h>

void Process::Proc::SetProcessId(pid_t pid)
{
    proc_id = pid;
}

pid_t Process::Proc::GetProcessId(void) const
{
    return proc_id;
}

/* useless whats below this comment */
Process::Proc::Proc(void)
    :proc_id(0), proc_baseaddr(0)
{}

Process::Proc::Proc(pid_t pid)
    :proc_id(pid), proc_baseaddr(0)
{
    SetMapPath(pid);
    SetMemPath(pid);
    SetCmdline(pid);
}

Addr Process::Proc::GetLoadAddress(void) const
{
    assert(proc_mappath != nullptr && "map path is not set");

    Addr baseaddr;
    char addr_buf[ADDR_LEN];
    char *p = addr_buf;

    FILE *fh = fopen(proc_mappath, "r");
    if(!fh)
        throw zkexcept::file_not_found_error();

    for(int i = 0; i < 16; i++, p++){
        *p = fgetc(fh);
        assert(std::isalnum(*p) && "Invalid /proc file");
    }
    sscanf(addr_buf, "%lx", &baseaddr);
    proc_baseaddr = baseaddr;
    return proc_baseaddr;
}

void Process::Proc::SetMapPath(pid_t pid)
{
    if(proc_id == 0)
        proc_id = pid;

    proc_mappath = (char *)calloc(sizeof(char), PATH_LEN);
    if(proc_mappath == nullptr)
        throw std::bad_alloc();

    std::sprintf(proc_mappath, "/proc/%d/maps", proc_id);
    assert(proc_mappath != nullptr && "pathname is not set");
}
