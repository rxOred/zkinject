#include "zkmemorymap.hh"

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <optional>
#include <regex>
#include <tuple>

#include "zkexcept.hh"
#include "zktypes.hh"
#include "zkutils.hh"

template <typename T>
void zkprocess::MemoryMap<T>::parse_memory_map() {
    char buffer[24];
    if (mm_pid != 0) {
        std::sprintf(buffer, MAPPATH, mm_pid);
    } else {
        std::sprintf(buffer, "/proc/self/maps");
    }

    std::ifstream fh(buffer);
    std::string line, start_addr, end_addr, permissions, name;
    typename T::addr_t s_addr = 0x0, e_addr = 0x0;
    std::smatch match;
    std::regex regex(R"(([a-f0-9]+)-([a-f0-9]+) ([rxwp-]{4}) (.*))",
                     std::regex::optimize);

    mm_pageinfo.reserve(13);

    while (std::getline(fh, line)) {
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

template <typename T>
std::vector<zkprocess::page_t<T>> zkprocess::MemoryMap<T>::get_memory_map()
    const {
    return mm_pageinfo;
}

template <typename T>
zkprocess::MemoryMap<T>::MemoryMap(pid_t pid) : mm_pid(pid) {
    std::cout << "calling memory map constructor" << std::endl;
}

template <typename T>
std::optional<std::tuple<typename T::addr_t, typename T::addr_t,
                         std::string, std::optional<std::string>>>
zkprocess::MemoryMap<T>::get_module_page(const char* module_name) const {
    for (auto const& x : mm_pageinfo) {
        if (x.get_page_name().compare(module_name)) {
            return std::make_tuple(
                x.get_page_start_address(), x.get_page_end_address(),
                x.get_page_permissions(), x.get_page_name());
        }
    }
    return {};
}

template <typename T>
std::optional<typename T::addr_t>
zkprocess::MemoryMap<T>::get_module_start_address(
    const char* module_name) const {
    for (auto const& x : mm_pageinfo) {
        if (x.get_page_name().compare(module_name)) {
            return x.get_page_start_address();
        }
    }
    return {};
}

template <typename T>
std::optional<typename T::addr_t>
zkprocess::MemoryMap<T>::get_module_end_address(
    const char* module_name) const {
    for (auto const& x : mm_pageinfo) {
        if (x.get_page_name().compare(module_name)) {
            return x.get_page_end_address();
        }
    }
    return {};
}

template <typename T>
bool zkprocess::MemoryMap<T>::is_mapped(typename T::addr_t addr) const {
    /* check if given address is kernel allocated */
    if (addr >= 0x7fffffffffffff) {
        return true;
    }
    for (int i = 0; i < mm_pageinfo.size(); i++) {
        if ((addr & 0x000000000000ffff) ==
                mm_pageinfo[i].get_page_start_address() ||
            (addr & 0x000000000000ffff) ==
                mm_pageinfo[i].get_page_end_address()) {
            return true;
        }
    }
    return false;
}

template class zkprocess::MemoryMap<x64>;
template class zkprocess::MemoryMap<x86>;
