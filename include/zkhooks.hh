#ifndef ZKHOOKS_HH
#define ZKHOOKS_HHH

#include "zkelf.hh"
#include "zkproc.hh"
#include "zktypes.hh"
#include "zkexcept.hh"
#include <sched.h>
#include <optional>
#include <sys/ptrace.h>

namespace Hooks {

    class Hook{
        /* all basic things related to hooking */
        protected:
            int     h_symindex;
            void    *h_orig_addr;
            void    *h_fake_addr;
        public:
            Hook();
    };

    class ElfGotPltHook : public Hook, public Binary::Elf{
        private:
            /* dynsym index of the symbol */
            int         egph_symbol_index;
            /* section header table index of rel.plt and rel.dyn */
            int         egph_relocplt_index;
            int         egph_relocdyn_index;
            /* rel.plt section */
            Relocation  *egph_relocdyn;
            Relocation  *egph_relocplt;
            void LoadRelocations(void);
        public:
            ElfGotPltHook(const char *pathname);

            inline void SetSymbolIndex(int index)
            {
                egph_symbol_index = index;
            }

            bool CheckElfType() const override
            {
                if(GetElfType() == ET_DYN)
                    return true;
                return false;
            }

            inline int GetSymbolIndex(void) const
            {
                return egph_symbol_index;
            }

            inline int GetRelocPltIndex(void) const
            {
                return egph_relocplt_index;
            }

            inline int GetRelocDynIndex(void) const
            {
                return egph_relocdyn_index;
            }

            inline Relocation *GetRelocDyn(void) const
            {
                return egph_relocdyn;
            }

            inline Relocation *GetRelocPlt(void) const
            {
                return egph_relocplt;
            }

            Addr GetModuleBaseAddress(const char *module_name) const;
            void HookFunc(const char *func_name, void *fake_addr, void *
                    base_addr);
            void UnhookFuction();
    };

    class ProcGotPltHook : public Hook, public Process::Proc{
        private:
            ElfGotPltHook *elfhook;
        public:
            ProcGotPltHook(pid_t pid, const char *module_name);
            ~ProcGotPltHook();
            void HookFunc(const char *func_name, void *fake_addr, void *
                    base_addr);
    };
}

#endif /* ZKHOOKS_HH */
