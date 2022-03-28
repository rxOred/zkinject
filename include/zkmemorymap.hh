#ifndef ZKMAP_HH
#define ZKMAP_HH

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "zktypes.hh"

#define MAPPATH "/proc/%d/maps"
#define MEMPATH "/proc/%d/mem"
#define CMDLINE "/proc/%d/cmdline"

namespace zkprocess {
struct page_t {
public:
    page_t(addr_t saddr, addr_t eaddr, std::string permissions,
           std::optional<std::string> name = std::nullopt);
    page_t(const page_t&) = default;
    page_t(page_t&&) = default;

    inline addr_t GetPageStartAddress(void) const { return page_saddr; }
    inline addr_t GetPageEndAddress(void) const { return page_eaddr; }
    inline std::string GetPagePermissions(void) const {
        return page_permissions;
    }
    std::optional<std::string> GetPageName(void) const;

private:
    addr_t page_saddr;
    addr_t page_eaddr;
    std::string page_permissions;
    std::optional<std::string> page_name;
};

class MemoryMap {
public:
    MemoryMap(pid_t pid);

    std::optional<addr_t> GetModuleStartAddress(const char* module_name) const;
    std::optional<addr_t> GetModuleEndAddress(const char* module_name) const;

    std::optional<
        std::tuple<addr_t, addr_t, std::string, std::optional<std::string>>>
    GetModulePage(const char* module_name) const;

    inline const page_t& GetBasePage(void) const { return mm_pageinfo[0]; }
    inline const page_t& GetLastPage(void) const { return *mm_pageinfo.end(); }
    inline std::vector<page_t>::const_iterator GetIteratorBegin(void) const {
        return mm_pageinfo.begin();
    }
    inline std::vector<page_t>::const_iterator GetIteratorLast(void) const {
        return mm_pageinfo.end();
    }
    inline std::pair<std::vector<page_t>::const_iterator,
                     std::vector<page_t>::const_iterator>
    GetIteratorsBeginEnd(void) const {
        return std::make_pair(mm_pageinfo.begin(), mm_pageinfo.end());
    }
    inline addr_t GetBaseAddress(void) const {
        return mm_pageinfo[0].GetPageStartAddress();
    }
    inline addr_t GetBaseEndAddress(void) const {
        return mm_pageinfo[0].GetPageEndAddress();
    }
    inline std::vector<page_t> GetMemoryPages(void) const {
        return mm_pageinfo;
    }
    bool IsMapped(addr_t addr) const;

    // TODO virtualAlloc /protect
private:
    std::vector<page_t> mm_pageinfo;
};
};  // namespace zkprocess

#endif  // ZKMAP_HH
