#include "zkproc.hh"

Process::Proc::Proc()
    :proc_pathname(nullptr), proc_id(0)
{}

Process::Proc::Proc(pid_t pid)
    :proc_pathname(nullptr), proc_id(pid)
{}

Addr Process::Proc::GetLoadAddress(void) const
{
    assert(proc_pathname != nullptr && "pathname is not set");

    u64 base_addr = 0;
    char addr_buf[ADDRSZ];
    char *p = addr_buf;

    FILE *fh = fopen(proc_pathname, "r");
    if(!fh)
        throw zkexcept::file_not_found_error();

    for(int i = 0; i < 16; i++, p++){
        *p = fgetc(fh);
        assert(std::isalnum(*p) && "Invalid /proc file");
    }
    sscanf(addr_buf, "%lx", &base_addr);
    return base_addr;
}

void Process::Proc::SetPathname(pid_t pid)
{
    if(proc_id == 0)
        proc_id = pid;

    proc_pathname = (char *)calloc(sizeof(char), PATHSZ);
    if(proc_pathname == nullptr)
        throw std::bad_alloc();

    std::sprintf(proc_pathname, "/proc/%d/maps", proc_id);
    assert(proc_pathname != nullptr && "pathname is not set");
}
