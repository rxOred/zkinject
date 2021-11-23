#ifndef ZKHOOKS_HH
#define ZKHOOKS_HH

#include "zkelf.hh"
#include "zkproc.hh"
#include "zktypes.hh"
#include "zkexcept.hh"
#include <memory>
#include <sched.h>
#include <optional>
#include <sys/ptrace.h>

namespace Hooks {
    template<class T>
    class Hook{
        /* all basic things related to hooking */
        protected:
            int h_symindex;
            /* address of got */
            T   *h_addr;
            /* original address at h_addr */
            T   h_orig_addr;
            T   h_fake_addr;
        public:
            Hook();
    };

    class ElfGotPltHook : public Hook<addr_t>, public Binary::Elf{
        private:
            /* dynsym index of the symbol */
            int             egph_symbol_index;  // BUG useless
            /* section header table index of rel.plt and rel.dyn */
            int             egph_relocplt_index;
            int             egph_relocdyn_index;
            /* rel.plt section */
            relocation_t    *egph_relocdyn;
            /* rel.dyn section */
            relocation_t    *egph_relocplt;
            void LoadRelocations(void);
        public:
            ElfGotPltHook(const char *pathname);

            inline void SetSymbolIndex(int index)
            {
                egph_symbol_index = index;
            }

            bool CheckElfType() const 
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

            inline relocation_t *GetRelocDyn(void) const
            {
                return egph_relocdyn;
            }

            inline relocation_t *GetRelocPlt(void) const
            {
                return egph_relocplt;
            }
            addr_t GetModuleBaseAddress(const char *module_name) const;
            void HookFunc(const char *func_name, void *fake_addr, void 
                    *base_addr);
            void UnhookFuction();
    };

    class ProcGotPltHook : public Hook<addr_t>{
        private:
            pid_t pgph_pid;
            std::unique_ptr<Process::Ptrace> pgph_ptrace;
            std::unique_ptr<ElfGotPltHook> pgph_elfhook;
        public:
            /* 
             * pid is for ptrace, pathname is to parse the indicated binary 
             * using elf interface and retrieve relocation, dynamic and plt
             * section information
             */
            ProcGotPltHook(const char *pathname, pid_t pid);
            void HookFunc(const char *func_name, void *fake_addr, void 
                    *base_addr);
            void UnhookFunction() const;

            /* Get Process's base address */
            inline addr_t GetProcessBaseAddress(void) const
            {
                return pgph_ptrace->GetMemoryMap()->GetBaseAddress();
            }

            inline addr_t GetFunctionAddress(void) const {

            }
    };
}

#endif /* ZKHOOKS_HH */
