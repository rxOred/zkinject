#include "zkhooks.hh"
#include "zkproc.hh"

/* API for PLT / GOT redirection */
Hooks::ElfGotPltHook::ElfGotPltHook(const char *pathname)
    :Binary::Elf(pathname), h_relocplt_index(0), h_relocplt(nullptr)
{
    u16 type = GetElfType();
    if(type != ET_DYN)
        throw zkexcept::not_dyn_error();

    LoadDynamicData();
    LoadRelocations();
}

void Hooks::ElfGotPltHook::LoadRelocations(void)
{
    try{
        h_relocplt_index = GetSectionIndexbyName(RELOC_PLT);
    } catch(zkexcept::section_not_found_error& e){
        h_relocplt_index = GetSectionIndexbyAttr(RELOC_TYPE, SHF_ALLOC | 
                SHF_INFO_LINK);
        /* NOTE find out what is `I` in readelf -S output for rela.plt in */
        std::cerr << e.what();
        RemoveMap();
        std::abort();
    }
    u8 *memmap = (u8 *)elf_memmap;
    h_relocplt = (Relocation *)&memmap[elf_shdr[h_relocplt_index].sh_offset];
    try{
        h_relocdyn_index = GetSectionIndexbyName(RELOC_DYN);
    } catch(zkexcept::section_not_found_error& e){
        h_relocplt_index = GetSectionIndexbyAttr(RELOC_TYPE, SHF_ALLOC);
        std::cerr << e.what();
        RemoveMap();
        std::abort();
    }
    h_relocdyn = (Relocation *)&memmap[elf_shdr[h_relocdyn_index].sh_offset];
}

void Hooks::ElfGotPltHook::HookFunc(const char *func_name, void *fake_addr,
        void *base_addr)
{
    assert((h_relocplt_index != 0 && h_relocdyn_index != 0) && "relocation      \
            section indexes are not set");
    h_fakeaddr = fake_addr;
    try{
        h_symindex = GetDynSymbolIndexbyName(func_name);
    } catch (zkexcept::symbol_not_found_error& e){
        std::cerr << e.what();
        std::exit(1);
    }

    /* for position independant binaries */
    for (int i = 0; i < elf_shdr[h_relocplt_index].sh_size / sizeof(Relocation)
            ; i++){
        if(h_symindex == ELF_R_SYM(h_relocplt[i].r_info)){
            /*
             * convert void *base_addr to Addr *base_addr, add r_offset to it, 
             * basically result will point to global offset table's entry for 
             * func_name function's address (resolved or not).
             * by dereferencing that value, we can get original load address of 
             * func_name symbol/function
             */ 
            Addr *addr = ((Addr *)(((Addr)base_addr) + (Addr)h_relocplt[i].
                        r_offset));
            //h_origaddr = (void *)*addr;
            *(addr) = (Addr)h_fakeaddr;
            break;
        }
    }
    /* for position dependant -m32 binaries */
    for (int i = 0; i < elf_shdr[h_relocdyn_index].sh_size / sizeof(Relocation);
            i++){
        if(h_symindex == ELF_R_SYM(h_relocdyn[i].r_info)){
            /*
             * now, since rel.dyn section could contain many entries for same 
             * symbol index, we should break just after the first match and 
             * we cant directly get the address like before because r_offset
             * contains the offset the linker should patch.
             */

            /*
             * position dependant code usually implements relocations with
             * R_XXX_PC32 reloaction type, which uses relative addresses.
             * algorithm for resolving those type of relocations is S + A - P,
             * where S = symbols load address, A = addend, P = offset where 
             * relocation applies. call occurs with result of above expression
             * + rip.
             */
            void *p = (void *)(((Addr *)base_addr) + h_relocdyn[i].r_offset);
            /* getting S */
            if(h_origaddr == 0){
                /* origaddr =       | p |       +   | *p |     +  | addend | */
                h_origaddr = (void *)((Addr *)p + (*(Addr *)p) + sizeof(u32));

                if(mprotect(p, sizeof(Addr), PROT_READ | PROT_WRITE) < 0)
                    throw zkexcept::permission_denied();
                *(Addr *)p = (Addr)((Addr)fake_addr - ((Addr)p + sizeof(u32)));
            }
            break;
        }
    }
}

void Hooks::ElfGotPltHook::UnhookFuction()
{
    //make this thing usefull
    puts("hello");
}

Addr Hooks::ElfGotPltHook::GetModuleBaseAddress(const char *module_name) const
{
    Addr address;
    Process::Proc proc(0);
    try{
        address = proc.GetModuleBaseAddress(module_name); 
    }catch(zkexcept::proc_file_error& e){
        std::cerr << e.what();
        std::exit(1);
    }
    return address;
}
