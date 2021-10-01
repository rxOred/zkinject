#include "zkproc.hh"
#include "zkexcept.hh"
#include <cstdint>
#include <cstdio>

Process::MemoryMap::MemoryMap(pid_t pid, u8 flag)
    :mm_flags(flag)
{
    char buffer[24];
    if(pid != 0)
        std::sprintf(buffer, MAPPATH, pid);
    else
        std::sprintf(buffer, "/proc/self/maps");

    std::ifstream fh(buffer);
    std::string line, saddr, eaddr, permissions, name;
    addr_t _saddr, _eaddr;
    while(std::getline(fh, line)){
        std::stringstream ss(line);
        /* 00000- */
        std::getline(ss, saddr, '-');
        /* -00000 */
        std::getline(ss, eaddr, ' ');
        /* r--p */
        std::getline(ss, permissions, ' ');
        /* /path/to/file */
        while(std::getline(ss, line, '/')){
            std::getline(ss, name, '\n');
        }

        std::sscanf(saddr.c_str(), "%lx", &_saddr);
        std::sscanf(eaddr.c_str(), "%lx", &_eaddr);

        std::shared_ptr<page_t> page = std::make_shared<page_t>(_saddr, _eaddr, 
                permissions, name);
        mm_pageinfo.push_back(page);

        if(CHECK_FLAGS(MEMMAP_ONLY_BASE_ADDR, mm_flags)) break;
    }
}

std::shared_ptr<Process::page_t> Process::MemoryMap::GetModulePage(const char 
        *module_name) const
{
    for(auto const& x : mm_pageinfo){
        if(x->GetPageName().compare(module_name)){
            return x;
        }
    }
    throw zkexcept::page_not_found_error();
}

addr_t Process::MemoryMap::GetModuleBaseAddress(const char *module_name) const
{
    for(auto const& x : mm_pageinfo){
        if(x->GetPageName().compare(module_name)){
            return x->GetPageStartAddress();
        }
    }
    throw zkexcept::page_not_found_error();
}

addr_t Process::MemoryMap::GetModuleEndAddress(const char *module_name) const
{
    for(auto const& x: mm_pageinfo){
        if(x->GetPageName().compare(module_name)){
            return x->GetPageEndAddress();
        }
    }
    throw zkexcept::page_not_found_error();
}
