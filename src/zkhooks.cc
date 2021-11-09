#include "zkhooks.hh"
#include "zktypes.hh"
#include <new>
#include <zkexcept.hh>

template<class T>
Hooks::Hook<T>::Hook()
    :h_symindex(0), h_addr(nullptr), h_orig_addr(0), h_fake_addr(0)
{}

/*
 * Elf Got / Plt Hooking explaination
 * ==================================
 * 
 */

Hooks::ElfGotPltHook::ElfGotPltHook(const char *pathname)
    :Binary::Elf(pathname), egph_relocplt_index(0), egph_relocplt(nullptr) 
{
    /* There is no GOT / PLTs in statically linked binaries */
    if(CheckElfType()){
        LoadDynamicData();
        LoadRelocations();
    } else
        throw zkexcept::not_dyn_error();
}

void Hooks::ElfGotPltHook::LoadRelocations(void)
{
    u8 *memmap = (u8 *)elf_memmap;
#ifdef __BITS_64__
    try{
        egph_relocplt_index = GetSectionIndexbyName(RELOC_PLT);
    } catch(zkexcept::section_not_found_error& e){
        std::cerr << e.what();
        RemoveMap();
        std::abort();
    }
    egph_relocplt = (relocation_t *)&memmap[elf_shdr[egph_relocplt_index].
        sh_offset];
#elif __BITS_32__
    try{
        egph_relocdyn_index = GetSectionIndexbyName(RELOC_DYN);
    } catch(zkexcept::section_not_found_error& e){
        std::cerr << e.what();
        RemoveMap();
        std::abort();
    }
    egph_relocdyn = (relocation_t *)&memmap[elf_shdr[egph_relocdyn_index].
        sh_offset];
#endif
}

void Hooks::ElfGotPltHook::HookFunc(const char *func_name, void *fake_addr,
        void *base_addr)
{
    assert((egph_relocplt_index != 0 || egph_relocdyn_index != 0) && 
            "relocation section indexes are not set");
    h_fake_addr = (addr_t)fake_addr;
    try{
        h_symindex = GetDynSymbolIndexbyName(func_name);
    } catch (zkexcept::symbol_not_found_error& e){
        std::cerr << e.what();
        std::exit(1);
    }

#if defined __BITS_64__
    /* for position independant binaries */
    for (int i = 0; i < elf_shdr[egph_relocplt_index].sh_size / sizeof(relocation_t); 
            i++){
        if(h_symindex == ELF_R_SYM(egph_relocplt[i].r_info)){
            /*
             * convert void *base_addr to Addr *base_addr, add r_offset to 
             * it, basically result will point to global offset table's 
             * entry for func_name function's address (resolved or not).
             * by dereferencing that value, we can get original load address
             * of func_name symbol/function
             */ 
            h_addr = ((addr_t *)(((addr_t)base_addr) + (addr_t)egph_relocplt[i]
                        .r_offset));
            // NOTE h_origaddr = (void *)*addr;
            *(h_addr) = (addr_t)h_fake_addr;
            break;
        }
    }

#elif __BITS_32__ // NOTE change this to depend on file type
    /* for position dependant -m32 binaries */
    for (int i = 0; i < elf_shdr[egph_relocdyn_index].sh_size / 
            sizeof(Relocation); i++){
        if(h_symindex == ELF_R_SYM(egph_relocdyn[i].r_info)){
            /*
             * now, since rel.dyn section could contain many entries for same
             * symbol index, we should break just after the first match and 
             * we cant directly get the address like before because r_offset
             * contains the offset the linker should patch.
             */

            /*
             * position dependant code usually implements relocations with
             * R_XXX_PC32 reloaction type, which uses relative addresses.
             * algorithm for resolving those type of relocations is S + A - P
             * where S = symbols load address, A = addend, P = offset where 
             * relocation applies. call occurs with result of above expressi
             * - on + rip.
             */
            void *p = (void *)(((Addr *)base_addr) + egph_relocdyn[i].r_offset);
            /* getting S */
            if(h_orig_addr == 0){
                /* 
                 * origaddr =       | p |       +   | *p |     +  | addend | 
                 */
                h_orig_addr = (void *)((Addr *)p + (*(Addr *)p) + 
                        sizeof(u32));

                // NOTE mprotect needed to be fixed
                if(mprotect(p, sizeof(Addr), PROT_READ | PROT_WRITE) < 0)
                    throw zkexcept::permission_denied();
                *(Addr *)p = (Addr)((Addr)fake_addr - ((Addr)p + sizeof(u32))
                        );

                // NOTE another mprotect to restore permissions
            }
            break;
        }
    }
#endif
}

void Hooks::ElfGotPltHook::UnhookFuction()
{
    assert(h_symindex != 0 && (egph_relocplt_index != 0 || egph_relocdyn_index
            != 0) && "function may not be hooked");
#if defined __BITS64__
    for (int i = 0; i < elf_shdr[egph_relocplt_index].sh_size / sizeof(relocation_t);
            i++){
        if(h_symindex == ELF_R_SYM(egph_relocplt[i].r_info)){
            *(h_addr) = h_orig_addr
        }
    }
#elif __BITS32__
    for (int i = 0; i < elf_shdr[egph_relocdyn_index].sh_size / sizeof(relocation_t);
            i++){
        if(h_symindex == ELF_R_SYM(egph_relocdyn[i].r_info)){
            // NOTE big chunk of code here

        }
    }
#endif
}

/* get base address of a page / module */
addr_t Hooks::ElfGotPltHook::GetModuleBaseAddress(const char *module_name) 
    const
{
    addr_t address;
    Process::MemoryMap _map(0, 0);
    try{
        address = _map.GetModuleBaseAddress(module_name);
    }catch (zkexcept::page_not_found_error& e){
        std::cerr << e.what() << std::endl;
        std::exit(1);
    }
    return address;
}

/*
 * Process Got / Plt hooking explaination
 * ======================================
 *
 *
 */

/* pid is for ptrace, pathname is to parse the binary */
Hooks::ProcGotPltHook::ProcGotPltHook(const char *pathname, pid_t pid)
    :Hook(), pgph_pid(pid)
{
    try{
        if (pathname != nullptr) {
            pgph_elfhook = std::make_unique<ElfGotPltHook>(pathname);
            pgph_ptrace = std::make_unique<Process::Ptrace>(&pathname, pid,
                    Process::PTRACE_ATTACH_NOW);
        }
        else if (pid != 0 && pathname == nullptr){
            pgph_ptrace = std::make_unique<Process::Ptrace>(&pathname, pid, 
                Process::PTRACE_ATTACH_NOW);
            /* here we use memory map's help to get the path to binary */
            pgph_elfhook = std::make_unique<ElfGotPltHook>(pgph_ptrace->
                    GetProcessPathname().c_str());
        }
    } catch (zkexcept::not_dyn_error& e){
        std::cerr << e.what();
        std::exit(1);
    }
}

/*
 * not very different from ElfGotPltHook::HookFunc, instead of using pointers
 * this uses ptrace
 */
void Hooks::ProcGotPltHook::HookFunc(const char *func_name, void *fake_addr,
        void *base_addr)
{
    assert((pgph_elfhook->GetRelocDynIndex() != 0 || pgph_elfhook->
                GetRelocPltIndex() != 0) && "relocation sections are not set");
    h_fake_addr = (addr_t)fake_addr;
    try{
        h_symindex = pgph_elfhook->GetDynSymbolIndexbyName(func_name);
    } catch (zkexcept::symbol_not_found_error& e){
        std::cerr << e.what();
        std::exit(1);
    }

#ifdef __BITS_64__
    shdr_t relocplt_section = pgph_elfhook->GetSectionbyIndex(pgph_elfhook->
            GetRelocPltIndex());
    for(int i = 0; i < relocplt_section.sh_size / sizeof(relocation_t); i++){
        if(h_symindex == ELF_R_SYM(pgph_elfhook->GetRelocPlt()[i].r_info)){
            h_addr = ((addr_t *)((addr_t)base_addr) + (addr_t)pgph_elfhook->
                    GetRelocPlt()[i].r_offset);

#elif __BITS_32__ // NOTE for position dependant binaries
    Shdr relocdyn_section = elfhook->GetSectionbyIndex(elfhook->
            GetRelocDynIndex());
    for(int i = 0; i < relocdyn_section.sh_size / sizeof(Relocation); i++){
        if(h_symindex == ELF_R_SYM(elfhook->GetRelocDyn()[i].r_info)){
            h_addr = ((addr_t *)((addr_t )base_addr) + (addr_t)pgph_elfhook->
                    GetRelocDyn()[i].r_offset);
#endif

            try{
                pgph_ptrace->ReadProcess((void *)&h_orig_addr, (addr_t)h_addr, 
                        sizeof(addr_t));
                pgph_ptrace->WriteProcess((void *)h_fake_addr, (addr_t)h_addr, 
                        sizeof(addr_t));
            } catch (zkexcept::ptrace_error& e){
                std::cerr << e.what() << std::endl;
                std::exit(1);
            }
       }
    }
}

void Hooks::ProcGotPltHook::UnhookFunction() const
{
    assert(h_symindex != 0 && (pgph_elfhook->GetRelocDynIndex() != 0 || pgph_elfhook
                ->GetRelocPltIndex() != 0) && "relocation sections are not set");
    try{
        addr_t buffer;
        pgph_ptrace->ReadProcess((void *)&buffer, (addr_t)h_addr, sizeof(addr_t));
        if (buffer == h_fake_addr){
            pgph_ptrace->WriteProcess((void *)h_orig_addr, (addr_t)h_addr, sizeof(addr_t));
        }
    } catch (zkexcept::ptrace_error& e) {
        std::cerr << e.what() << std::endl;
        std::exit(1);
    }
}
