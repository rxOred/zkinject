#ifndef ZKMAP_HH
#define ZKMAP_HH

#include "zktypes.hh"
#include <string>
#include <vector>
#include <memory>

#define MAPPATH     "/proc/%d/maps"
#define MEMPATH     "/proc/%d/mem"
#define CMDLINE     "/proc/%d/cmdline"

namespace ZkProcess {
    struct page_t {
        public:
            page_t(addr_t saddr, addr_t eaddr, std::string permissions,
                    std::string name);

            inline addr_t GetPageStartAddress(void) const
            {
                return page_saddr;
            }
            inline addr_t GetPageEndAddress(void) const
            {
                return page_eaddr;
            }
            inline std::string GetPagePermissions(void) const
            {
                return page_permissions;
            }
            inline std::string GetPageName(void) const
            {
                return page_name;
            }
        private:
            addr_t      page_saddr;
            addr_t      page_eaddr;
            std::string page_permissions;
            std::string page_name;
    };

    class MemoryMap  {
        public:
            MemoryMap(pid_t pid, u8_t flag);
            ~MemoryMap();

            addr_t GetModuleBaseAddress(const char *module_name) const;
            addr_t GetModuleEndAddress(const char *module_name) const;
            std::shared_ptr<page_t> GetModulePage(const char *module_name)
                const;

            inline std::shared_ptr<page_t> GetBasePage(void) const
            {
                return  mm_pageinfo[0];
            }
            inline std::shared_ptr<page_t> GetLastPage(void) const
            {
                return *mm_pageinfo.end();
            }
            inline std::vector<std::shared_ptr<page_t>>::const_iterator
            GetIteratorBegin(void) const
            {
                return mm_pageinfo.begin();
            }
            inline std::vector<std::shared_ptr<page_t>>::const_iterator
            GetIteratorLast(void) const
            {
                return mm_pageinfo.end();
            }
            inline std::pair<std::vector<std::shared_ptr<page_t>>::const_iterator,
                      std::vector<std::shared_ptr<page_t>>::const_iterator>
            GetIteratorsBeginEnd(void) const
            {
                return std::make_pair(mm_pageinfo.begin(), mm_pageinfo.end());
            }
            inline addr_t GetBaseAddress(void) const
            {
                return mm_pageinfo[0]->GetPageStartAddress();
            }
            inline addr_t GetBaseEndAddress(void) const
            {
                return mm_pageinfo[0]->GetPageEndAddress();
            }
            inline std::vector<std::shared_ptr<page_t>> GetMemoryPages(void) const
            {
                return mm_pageinfo;
            }
            bool IsMapped(addr_t addr) const;

           // TODO virtualAlloc /protect
         private:
            std::vector<std::shared_ptr<page_t>> mm_pageinfo;
    };
};

#endif // ZKMAP_HH
