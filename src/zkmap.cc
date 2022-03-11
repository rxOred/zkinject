#include "zkprocess.hh"
#include "zkexcept.hh"
#include "zkutils.hh"
#include <cstdint>
#include <cstdio>
#include <regex>

ZkProcess::page_t::page_t(addr_t saddr, addr_t eaddr, std::string 
        permissions, std::string name)
    :page_saddr(saddr), page_eaddr(eaddr), page_permissions
     (permissions),page_name(name)
{}

ZkProcess::MemoryMap::MemoryMap(pid_t pid, u8_t flag)
    :mm_flags(flag)
{
    char buffer[24];
    if (pid != 0) {
        std::sprintf(buffer, MAPPATH, pid);
    } else {
        std::sprintf(buffer, "/proc/self/maps");
    }

    std::ifstream fh(buffer);
    std::string line, start_addr, end_addr, permissions, name = nullptr;
    addr_t s_addr = 0x0, e_addr = 0x0;
    std::smatch match;
    std::regex regex(R"([a-f0-9]+)-([a-f0-9]+) ([rxwp-]{4}) (.*) (\[|/.*\n)");
    while(std::getline(fh, line)) {
        std::regex_match(line, match, regex);
        start_addr = match.str(0);
        end_addr = match.str(1);
        permissions = match.str(2);
        if (match.size() == 5) {
            name = match.str(4);
        }

        std::sscanf(start_addr.c_str(), "%lx", &s_addr);
        std::sscanf(end_addr.c_str(), "%lx", &e_addr);

        auto page = std::make_shared<page_t>(s_addr, e_addr, permissions,
                name);
        mm_pageinfo.push_back(page);

        if(ZK_CHECK_FLAGS(MEMMAP_ONLY_BASE_ADDR, mm_flags)) break;
    }

    /*
    std::string line, saddr, eaddr, permissions, name;
    addr_t _saddr, _eaddr;
    while(std::getline(fh, line)){
        std::stringstream ss(line);

        std::getline(ss, saddr, '-');

        std::getline(ss, eaddr, ' ');

        std::getline(ss, permissions, ' ');

        while(std::getline(ss, line, '/') || std::getline(ss, line, '[')){
            std::getline(ss, name, '\n');
        }

    }
    */
}

std::shared_ptr<ZkProcess::page_t> ZkProcess::MemoryMap::GetModulePage(
        const char *module_name) const
{
    for(auto const& x : mm_pageinfo){
        if(x->GetPageName().compare(module_name)){
            return x;
        }
    }
    throw ZkExcept::page_not_found_error();
}

addr_t ZkProcess::MemoryMap::GetModuleBaseAddress(const char *module_name)
    const
{
    for(auto const& x : mm_pageinfo){
        if(x->GetPageName().compare(module_name)){
            return x->GetPageStartAddress();
        }
    }
    throw ZkExcept::page_not_found_error();
}

addr_t ZkProcess::MemoryMap::GetModuleEndAddress(const char *module_name) 
    const
{
    for(auto const& x: mm_pageinfo){
        if(x->GetPageName().compare(module_name)){
            return x->GetPageEndAddress();
        }
    }
    throw ZkExcept::page_not_found_error();
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
