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

template <typename T>
struct page_t {
public:
    page_t(typename T::addr_t saddr, typename T::addr_t eaddr,
           std::string permissions,
           std::optional<std::string> name = std::nullopt)
		:page_saddr(saddr),
		 page_eaddr(eaddr),
		 page_permissions(permissions),
		 page_name(name) {}
	
    page_t(const page_t&) = default;
    page_t(page_t&&) = default;

    inline typename T::addr_t get_page_start_address(void) const {
        return page_saddr;
    }
    inline typename T::addr_t get_page_end_address(void) const {
        return page_eaddr;
    }
    inline std::string get_page_permissions(void) const {
        return page_permissions;
    }
    inline std::string get_page_name(void) const {
		return page_name.value_or("");
	}

private:
    typename T::addr_t page_saddr;
    typename T::addr_t page_eaddr;
    std::string page_permissions;
    std::optional<std::string> page_name;
};

template <typename T>
class MemoryMap {
public:
    MemoryMap(pid_t pid);
    void parse_memory_map(void);
	std::vector<page_t<T>> get_memory_map(void) const;
    std::optional<typename T::addr_t> get_module_start_address(
        const char* module_name) const;
    std::optional<typename T::addr_t> get_module_end_address(
        const char* module_name) const;

    std::optional<std::tuple<typename T::addr_t, typename T::addr_t,
                             std::string, std::optional<std::string>>>
    get_module_page(const char* module_name) const;

    inline const page_t<T>& get_base_page(void) const {
        return mm_pageinfo[0];
    }
    inline const page_t<T>& get_end_page(void) const {
        return *mm_pageinfo.end();
    }
    inline typename std::vector<page_t<T>>::const_iterator get_iterator_begin(
        void) const {
        return mm_pageinfo.begin();
    }

    inline typename std::vector<page_t<T>>::const_iterator
    get_iterator_end(void) const {
        return mm_pageinfo.end();
    }
    inline std::pair<typename std::vector<page_t<T>>::const_iterator,
                     typename std::vector<page_t<T>>::const_iterator>
    get_interator_begin_end(void) const {
        return std::make_pair(mm_pageinfo.begin(), mm_pageinfo.end());
    }
    inline typename T::addr_t get_base_address(void) const {
        return mm_pageinfo[0].get_page_start_address();
    }
    inline typename T::addr_t get_base_end_address(void) const {
        return mm_pageinfo[0].get_page_end_address();
    }
    inline typename std::vector<page_t<T>> get_memory_pages(void) const {
        return mm_pageinfo;
    }
    bool is_mapped(typename T::addr_t addr) const;

    // TODO virtualAlloc, protect
private:
    std::vector<page_t<T>> mm_pageinfo;
    pid_t mm_pid;
};
};  // namespace zkprocess

#endif  // ZKMAP_HH
