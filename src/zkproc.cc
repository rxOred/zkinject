#include "zkproc.hh"
#include <cstdio>

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
    SetMapPath(pid);
    SetMemPath(pid);
    SetCmdline(pid);
}

Process::Proc::~Proc()
{
    if(proc_mappath) free(proc_mappath);
    if(proc_mempath) free(proc_mempath);
    if(proc_cmdline) free(proc_cmdline);
}

void Process::Proc::SetMapPath(pid_t pid)
{
    proc_mappath = (char *) calloc(PATH_LEN, sizeof(char));
    if(proc_mappath == nullptr)
        throw std::bad_alloc();

    if(pid == 0){
        sprintf(proc_mappath, "/proc/self/maps");
    } else {
        sprintf(proc_mappath, MAPPATH, pid);
    }
}

Addr Process::Proc::GetBaseAddress(void)
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
    return proc_baseaddr;
}

Addr Process::Proc::GetModuleBaseAddress(const char *module_name)
{
    assert(proc_mappath != nullptr && "map path is not set");
    char addr_buf[ADDR_LEN];
    std::ifstream fh(proc_mappath);
    std::string line;
    const char *_line = nullptr;

    while(std::getline(fh, line)){
        _line = line.c_str();
        for(int i = 0; i < strlen(_line); i++){
            if(strcmp(&_line[i], module_name) == 0){
                for(int j = 0; j < ADDR_LEN; j++){
                    addr_buf[j] = _line[j];
                    Addr address;
                    sscanf(addr_buf, "%lx", &address);
                    return address;
                }
            }
        }
    }
    throw zkexcept::proc_file_error();
}
