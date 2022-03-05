#include "zkproc.hh"
#include "zkexcept.hh"
#include "zkutils.hh"
#include <cstdint>
#include <cstdio>

ZkProcess::MemoryMap::MemoryMap(pid_t pid, u8 flag)
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
        /* /path/to/file || [stack/heap/vdso] */
        while(std::getline(ss, line, '/') || std::getline(ss, line, '[')){
            std::getline(ss, name, '\n');
        }

        std::sscanf(saddr.c_str(), "%lx", &_saddr);
        std::sscanf(eaddr.c_str(), "%lx", &_eaddr);

        std::shared_ptr<page_t> page = std::make_shared<page_t>(_saddr, 
                _eaddr, permissions, name);
        mm_pageinfo.push_back(page);

        if(CHECK_FLAGS(MEMMAP_ONLY_BASE_ADDR, mm_flags)) break;
    }
}

std::shared_ptr<ZkProcess::page_t> ZkProcess::MemoryMap::GetModulePage(
        const char *module_name) const
{
    for(auto const& x : mm_pageinfo){
        if(x->GetPageName().compare(module_name)){
            return x;
        }
    }
    throw zkexcept::page_not_found_error();
}

addr_t ZkProcess::MemoryMap::GetModuleBaseAddress(const char *module_name)
    const
{
    for(auto const& x : mm_pageinfo){
        if(x->GetPageName().compare(module_name)){
            return x->GetPageStartAddress();
        }
    }
    throw zkexcept::page_not_found_error();
}

addr_t ZkProcess::MemoryMap::GetModuleEndAddress(const char *module_name) 
    const
{
    for(auto const& x: mm_pageinfo){
        if(x->GetPageName().compare(module_name)){
            return x->GetPageEndAddress();
        }
    }
    throw zkexcept::page_not_found_error();
}

bool ZkProcess::MemoryMap::IsMapped(addr_t addr) const
{
    /* check if given address is kernel allocated */
    if (addr >= 0x7fffffffffffff){
        return true;
    }
    for(int i = 0; i < mm_pageinfo.size(); i++){
        if((addr & 0x000000000000ffff) == 
            mm_pageinfo[i]->GetPageStartAddress() ||
            (addr & 0x000000000000ffff) == 
            mm_pageinfo[i]->GetPageEndAddress()){
            return true;
        } 
    }
    return false;
}

