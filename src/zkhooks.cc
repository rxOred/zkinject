#include "zkelf.hh"

/* API for PLT / GOT redirection */

Binary::Hooking::Hooking(const char *target)
    :Elf(target), h_fakeaddr(0), h_origaddr(0), h_relocdyn(nullptr),
    h_relocplt(nullptr)
{
    u16 type = GetElfType();
    if(type != ET_DYN)
        throw zkexcept::not_dyn_error();

    LoadDynamicData();
    LoadRelocations();
}

void Binary::Hooking::LoadRelocations(void)
{
    int relocplt_index = 0, relocdyn_index = 0;
    try{
        relocplt_index = GetSectionIndexbyName(RELOC_PLT);
    } catch(zkexcept::section_not_found_error& e){
        relocplt_index = GetSectionIndexbyAttr(RELOC_TYPE, SHF_ALLOC | SHF_INFO_LINK);
        /* NOTE find out what is `I` in readelf -S output for rela.plt in */
        std::cerr << e.what();
        RemoveMap();
        std::abort();
    }
    u8 *memmap = (u8 *)elf_memmap;
    h_relocplt = (Relocation *)&memmap[elf_shdr[relocplt_index].sh_offset];
    try{
        relocdyn_index = GetSectionIndexbyName(RELOC_DYN);
    } catch(zkexcept::section_not_found_error& e){
        relocdyn_index = GetSectionIndexbyAttr(RELOC_TYPE, SHF_ALLOC);
        //find out what is AI in rela.plt
        std::cerr << e.what();
        RemoveMap();
        std::abort();
    }
    h_relocdyn = (Relocation *)&memmap[elf_shdr[relocdyn_index].sh_offset];
}

void Binary::Hooking::HookFunction(){

}

void Binary::Hooking::UnhookFuction(){

}
