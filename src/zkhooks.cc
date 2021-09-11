#include "zkhooks.hh"

Hooks::Hook::Hook()
    :h_symindex(0), h_orig_addr(nullptr), h_fake_addr(nullptr)
{}

/*
 * Elf Got / Plt Hooking explaination
 * ==================================
 * 
 */

Hooks::ElfGotPltHook::ElfGotPltHook(const char *pathname)
    :Binary::Elf(pathname), egph_relocplt_index(0), egph_relocplt(nullptr) 
{
    if(CheckElfType()){
        LoadDynamicData();
        LoadRelocations();
    }
}

void Hooks::ElfGotPltHook::LoadRelocations(void)
{
    try{
        egph_relocplt_index = GetSectionIndexbyName(RELOC_PLT);
    } catch(zkexcept::section_not_found_error& e){
        egph_relocplt_index = GetSectionIndexbyAttr(RELOC_TYPE, SHF_ALLOC | 
                SHF_INFO_LINK);
        /* NOTE find out what is `I` in readelf -S output for rela.plt in */
        std::cerr << e.what();
        RemoveMap();
        std::abort();
    }
    u8 *memmap = (u8 *)elf_memmap;
    egph_relocplt = (relocation_t *)&memmap[elf_shdr[egph_relocplt_index].
        sh_offset];
    try{
        egph_relocdyn_index = GetSectionIndexbyName(RELOC_DYN);
    } catch(zkexcept::section_not_found_error& e){
        egph_relocplt_index = GetSectionIndexbyAttr(RELOC_TYPE, SHF_ALLOC);
        std::cerr << e.what();
        RemoveMap();
        std::abort();
    }
    egph_relocdyn = (relocation_t *)&memmap[elf_shdr[egph_relocdyn_index].
        sh_offset];
}

void Hooks::ElfGotPltHook::HookFunc(const char *func_name, void *fake_addr,
        void *base_addr)
{
    assert((egph_relocplt_index != 0 && egph_relocdyn_index != 0) && 
            "relocation section indexes are not set");
    h_fake_addr = fake_addr;
    try{
        h_symindex = GetDynSymbolIndexbyName(func_name);
    } catch (zkexcept::symbol_not_found_error& e){
        std::cerr << e.what();
        std::exit(1);
    }

#if defined __BITS_64__
    /* for position independant binaries */
    for (int i = 0; i < elf_shdr[egph_relocplt_index].sh_size / 
            sizeof(relocation_t)
            ; i++){
        if(h_symindex == ELF_R_SYM(egph_relocplt[i].r_info)){
            /*
             * convert void *base_addr to Addr *base_addr, add r_offset to 
             * it, basically result will point to global offset table's 
             * entry for func_name function's address (resolved or not).
             * by dereferencing that value, we can get original load address
             * of func_name symbol/function
             */ 
            addr_t *addr = ((addr_t *)(((addr_t)base_addr) + (addr_t)egph_relocplt[i]
                        .r_offset));
            // NOTE h_origaddr = (void *)*addr;
            *(addr) = (addr_t)h_fake_addr;
            break;
        }
    }

#elif __BITS_32__
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
    //make this thing usefull
    puts("hello");
}

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
Hooks::ProcGotPltHook::ProcGotPltHook(pid_t pid, const char *module_name)
    :Hook(), pgph_pid(pid)
{
    try{
        pgph_ptrace = std::make_shared<Process::Ptrace>(nullptr, pid, Process::
                PTRACE_ATTACH_NOW);
        pgph_elfhook = std::make_shared<ElfGotPltHook>(module_name);
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
    assert((pgph_elfhook->GetRelocDynIndex() != 0 && pgph_elfhook->
                GetRelocPltIndex() != 0) && "relocation sections are not set");
    h_fake_addr = fake_addr;
    try{
        pgph_elfhook->SetSymbolIndex(pgph_elfhook->GetDynSymbolIndexbyName
                (func_name));
    } catch (zkexcept::symbol_not_found_error& e){
        std::cerr << e.what();
        std::exit(1);
    }

#ifdef __BITS_64__
    shdr_t relocplt_section = pgph_elfhook->GetSectionbyIndex(pgph_elfhook->
            GetRelocPltIndex());
    for(int i = 0; i < relocplt_section.sh_size / sizeof(relocation_t); i++){
        if(h_symindex == ELF_R_SYM(pgph_elfhook->GetRelocPlt()[i].r_info)){

#elif __BITS_32__
    Shdr relocdyn_section = elfhook->GetSectionbyIndex(elfhook->
            GetRelocPltIndex());
    for(int i = 0; i < relocdyn_section.sh_size / sizeof(Relocation); i++){
        if(h_symindex == ELF_R_SYM(elfhook->GetRelocPlt()[i].r_info)){

#endif
            addr_t addr = (((addr_t)base_addr) + (addr_t)
                            pgph_elfhook->GetRelocPlt()[i].r_offset);
            try{
                h_orig_addr = pgph_ptrace->ReadProcess<void *>(addr, sizeof(
                        addr_t));
                pgph_ptrace->WriteProcess((void *)h_fake_addr, addr, sizeof(
                            addr_t));
            } catch (zkexcept::ptrace_error& e){
                std::cerr << e.what() << std::endl;
                std::exit(1);
            }
       }
    }
}
