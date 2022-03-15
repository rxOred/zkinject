#include "zkmap.hh"
#include "zkexcept.hh"
#include "zkutils.hh"
#include <cstdint>
#include <cstdio>
#include <optional>
#include <regex>
#include <fstream>

ZkProcess::page_t::page_t(addr_t saddr, addr_t eaddr, std::string 
        permissions, std::optional<std::string> name)
    :page_saddr(saddr), page_eaddr(eaddr), page_permissions
     (permissions),page_name(name)
{}

std::optional<std::string> ZkProcess::page_t::GetPageName(void) const
{
    return page_name.value_or("");
}

ZkProcess::MemoryMap::MemoryMap(pid_t pid)
{
    // FIXME make this a seperate method because this wont parse the 
    // whole memory map since program is not loaded yet, its ust the 
    // binary and the dynamic linker 

    // FIXME make this more c++ like
    char buffer[24];
    if (pid != 0) {
        std::sprintf(buffer, MAPPATH, pid);
    } else {
        std::sprintf(buffer, "/proc/self/maps");
    }

    std::ifstream fh(buffer);
    std::string line, start_addr, end_addr, permissions, name;
    addr_t s_addr = 0x0, e_addr = 0x0;
    std::smatch match;
    std::regex regex(R"(([a-f0-9]+)-([a-f0-9]+) ([rxwp-]{4}) (.*))",
        std::regex::optimize);
    // FIXME parses all the shit after permissions to same string

    // A small optimization - reserving vector space for segments
    // 4 for the PT_LOAD segments of the binary 
    // 5 for the PT_LOAD segments of the dynamic linker 
    // rest for the stack, heap, vdso and vvar
    mm_pageinfo.reserve(13);
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

        mm_pageinfo.emplace_back(s_addr, e_addr, permissions, name);
    }
}

std::optional<const ZkProcess::page_t> 
ZkProcess::MemoryMap::GetModulePage(const char *module_name) const
{
    for (auto const& x : mm_pageinfo) {
        if (x.GetPageName().value_or("").compare(module_name)) {
            return x;
        }
    }
    return {};
}

std::optional<addr_t> ZkProcess::MemoryMap::GetModuleStartAddress(
        const char *module_name) const
{
    for(auto const& x : mm_pageinfo){
        if (x.GetPageName().value_or("").compare(module_name)){
            return x.GetPageStartAddress();
        }
    }
    return {};
}

std::optional<addr_t> ZkProcess::MemoryMap::GetModuleEndAddress(
        const char *module_name) const
{
    for(auto const& x: mm_pageinfo){
        if(x.GetPageName().value_or("").compare(module_name)){
            return x.GetPageEndAddress();
        }
    }
    return {};
}

bool ZkProcess::MemoryMap::IsMapped(addr_t addr) const
{
    /* check if given address is kernel allocated */
    if (addr >= 0x7fffffffffffff){
        return true;
    }
    for(int i = 0; i < mm_pageinfo.size(); i++){
        if((addr & 0x000000000000ffff) == 
            mm_pageinfo[i].GetPageStartAddress() ||
            (addr & 0x000000000000ffff) == 
            mm_pageinfo[i].GetPageEndAddress()){
            return true;
        } 
    }
    return false;
}
