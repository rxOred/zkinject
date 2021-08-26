#include <zkelf.hh>
#include <zkproc.hh>
#include <zktypes.hh>
#include <zkexcept.hh>
#include <sched.h>

namespace Hooks {

    class Hook{
        /* all basic things related to hooking */
        protected:
            int     h_symindex;
            void    *h_origaddr;
            void    *h_fakeaddr;
    };

    class ElfGotPltHook : public Hook, Binary::Elf{
        private:
            /* dynsym index of the symbol */
            int     h_symbol_index;
            /* section header table index of rel.plt and rel.dyn */
            int     h_relocplt_index;
            int     h_relocdyn_index;
            /* rel.plt section */
            Relocation  *h_relocdyn;
            Relocation  *h_relocplt;
        public:
            ElfGotPltHook(const char *pathname);
            void LoadRelocations(void);
            void HookFunc(const char *func_name, void *replace_addr, void *
                    base_addr);
            void UnhookFuction();
    };
}
