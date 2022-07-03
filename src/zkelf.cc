#include "zkelf.hh"

#include <asm-generic/errno-base.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/types.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <memory>
#include <optional>
#include <utility>
#include <variant>

#include "zkexcept.hh"
#include "zklog.hh"
#include "zktypes.hh"
#include "zkutils.hh"

std::shared_ptr<zkelf::ZkElf> zkelf::load_elf_from_file(
    const char *path, elf_flags flags, std::optional<zklog::Log *> log) {
    auto pair = zkutils::open_file(path);
    elf_core *core = (elf_core *)pair.first;
    // check the magic number to validate the file
    zktypes::u8_t magic[4] = {0x7f, 0x44, 0x4c, 0x46};
    if (!zkutils::validate_magic_number<zktypes::u8_t, 4>(core->ei_magic,
                                                          magic)) {
        throw zkexcept::invalid_file_format_error();
    }

    std::shared_ptr<ZkElf> ptr =
        std::make_shared<ZkElf>(elf_flags::ELF_AUTO_SAVE, log);

    if (core->ei_class == (zktypes::u8_t)ei_class::ELFCLASS32) {
        ptr->elf_obj = ElfObj<x86>(pair.first, pair.second, path);
    } else if (core->ei_class == (zktypes::u8_t)ei_class::ELFCLASS64) {
        ptr->elf_obj = ElfObj<x64>(pair.first, pair.second, path);
    } else {
        throw zkexcept::invalid_file_type_error();
    }
    return ptr;
}

void zkelf::load_elf_from_memory(void) {
    // load from memory using ptrace
}

template <typename T>
zkelf::ElfObj<T>::ElfObj(void *map, std::size_t size,
                         std::variant<const char *, pid_t> s)
    : e_memory_map(map), e_map_size(size), e_source(s) {
    e_ehdr = (ehdr_t<T> *)map;
    e_phdrtab = (phdr_t<T> *)map + e_ehdr->elf_phoff;
    e_shdrtab = (shdr_t<T> *)map + e_ehdr->elf_shoff;
    if (e_ehdr->elf_shstrndx ==
            static_cast<zktypes::u16_t>(sh_n::SHN_UNDEF) ||
        e_ehdr->elf_shstrndx > e_ehdr->elf_shnum ||
        e_shdrtab[e_ehdr->elf_shstrndx].sh_offset > size) {
        e_is_stripped = true;
    } else {
        e_shstrtab =
            (strtab_t)map + e_shdrtab[e_ehdr->elf_shstrndx].sh_offset;
    }
}

template <typename T>
bool zkelf::ElfObj<T>::is_stripped(void) const {
    return e_is_stripped;
}

template <typename T>
void *zkelf::ElfObj<T>::get_memory_map(void) const {
    return e_memory_map;
}

template <typename T>
std::size_t zkelf::ElfObj<T>::get_map_size(void) const {
    return e_map_size;
}

template <typename T>
std::variant<const char *, pid_t> zkelf::ElfObj<T>::get_elf_source(
    void) const {
    return e_source;
}

template <typename T>
zkelf::ehdr_t<T> *zkelf::ElfObj<T>::get_elf_header(void) const {
    return e_ehdr;
}

template <typename T>
zkelf::phdr_t<T> *zkelf::ElfObj<T>::get_program_header_table(void) const {
    return e_phdrtab;
}

template <typename T>
zkelf::shdr_t<T> *zkelf::ElfObj<T>::get_section_header_table(void) const {
    return e_shdrtab;
}

template <typename T>
zkelf::strtab_t zkelf::ElfObj<T>::get_section_header_string_table(
    void) const {
    return e_shstrtab;
}

template <typename T>
zkelf::strtab_t zkelf::ElfObj<T>::get_string_table(void) const {
    return e_strtab;
}

template <typename T>
zkelf::strtab_t zkelf::ElfObj<T>::get_dynamic_string_table(void) const {
    return e_dynstr;
}

template <typename T>
zkelf::symtab_t<T> *zkelf::ElfObj<T>::get_symbol_table(void) const {
    return e_symtab;
}

template <typename T>
zkelf::symtab_t<T> *zkelf::ElfObj<T>::get_dynamic_symbol_table(
    void) const {
    return e_dynsym;
}

template <typename T>
zkelf::dynamic_t<T> *zkelf::ElfObj<T>::get_dynamic_section(void) const {
    return e_dynamic;
}

template <typename T>
zkelf::nhdr_t<T> *zkelf::ElfObj<T>::get_note_section(void) const {
    return e_nhdr;
}

/*
template <typename T>
std::array<zktypes::u8_t, zkelf::ELF_INDEX_ARRAY_SIZE>&
    zkelf::ElfObj<T>::get_section_index_array(void) {
    return elf_section_indexes;
}
*/

template <typename T>
decltype(auto) zkelf::ElfObj<T>::get_section_index_array(void) {
    return e_section_indexes;
}

template <typename T>
void zkelf::ElfObj<T>::set_stripped(bool b) {
    e_is_stripped = b;
}

// these structures are already assigned therefore we just replace those
// with new ones in the memory map
template <typename T>
void zkelf::ElfObj<T>::set_elf_header(void *new_ehdr) {
    memcpy(e_ehdr, new_ehdr, e_ehdr->elf_ehsize);
}

template <typename T>
void zkelf::ElfObj<T>::set_section_header_table(void *new_shdr) {
    memcpy(e_shdrtab, new_shdr, e_ehdr->elf_shentsize * e_ehdr->elf_shnum);
}

template <typename T>
void zkelf::ElfObj<T>::set_program_header_table(void *new_phdr) {
    memcpy(e_phdrtab, new_phdr, e_ehdr->elf_phentsize * e_ehdr->elf_phnum);
}

template <typename T>
void zkelf::ElfObj<T>::set_section_header_string_table(void *new_tab) {
    if (e_shstrtab != nullptr) {
        memcpy(
            (void *)&((zktypes::u8_t *)get_memory_map())
                [e_shdrtab[e_ehdr->elf_shstrndx].sh_offset],
            new_tab,
            ((zktypes::u8_t *)
                 get_memory_map())[e_shdrtab[e_ehdr->elf_shstrndx].sh_size]);
    } else {
        e_shstrtab = (strtab_t)new_tab;
    }
}

template <typename T>
void zkelf::ElfObj<T>::set_string_table(void *new_tab) {
    e_strtab = (strtab_t)new_tab;
}

template <typename T>
void zkelf::ElfObj<T>::set_dynamic_string_table(void *new_tab) {
    e_dynstr = (strtab_t)new_tab;
}

template <typename T>
void zkelf::ElfObj<T>::set_symbol_table(void *new_tab) {
    e_symtab = (symtab_t<T> *)new_tab;
}

template <typename T>
void zkelf::ElfObj<T>::set_dynamic_symbol_table(void *new_tab) {
    e_dynsym = (symtab_t<T> *)new_tab;
}

template <typename T>
void zkelf::ElfObj<T>::set_dynamic_section(void *new_dyn) {
    e_dynamic = (dynamic_t<T> *)new_dyn;
}

template <typename T>
void zkelf::ElfObj<T>::set_note_section(void *new_note) {
    e_nhdr = (nhdr_t<T> *)new_note;
}

zkelf::ZkElf::ZkElf(zkelf::elf_flags flags,
                    std::optional<zklog::Log *> log)
    : elf_flag(flags), elf_log(log) {}

bool zkelf::ZkElf::load_symbol_data(void) {
    std::array<zktypes::u8_t, ELF_INDEX_ARRAY_SIZE> indexes;
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        indexes = elf->get_section_index_array();
    } else {
        indexes = elf->get_section_index_array();
    }
    try {
        indexes[ELF_SYMTAB_INDEX] = get_section_index_by_name(".symtab");
    } catch (zkexcept::section_not_found_error &e) {
        try {
            indexes[ELF_SYMTAB_INDEX] =
                get_section_index_by_attr(s_type::SHT_SYMTAB, 0);
        } catch (zkexcept::section_not_found_error &e) {
            try {
                indexes[ELF_SYMTAB_INDEX] = get_section_index_by_attr(
                    s_type::SHT_SYMTAB,
                    static_cast<zktypes::u16_t>(sh_flags::SHF_ALLOC));
            } catch (zkexcept::section_not_found_error &e) {
                set_stripped();
                if (elf_log.has_value()) {
                    elf_log.value()->push_log(
                        "file does not have a .symtab section",
                        zklog::log_level::LOG_LEVEL_CRITICAL);
                    // return after setting some error code  malformed
                }
            }
        }
    }

    try {
        indexes[ELF_STRTAB_INDEX] = get_section_index_by_name(".strtab");
    } catch (zkexcept::section_not_found_error &e) {
        try {
            indexes[ELF_STRTAB_INDEX] =
                get_section_index_by_attr(s_type::SHT_STRTAB, 0);
        } catch (zkexcept::section_not_found_error &e) {
            try {
                indexes[ELF_STRTAB_INDEX] = get_section_index_by_attr(
                    s_type::SHT_STRTAB,
                    static_cast<zktypes::u16_t>(sh_flags::SHF_ALLOC));
            } catch (zkexcept::section_not_found_error &e) {
                set_stripped();
                if (elf_log.has_value()) {
                    elf_log.value()->push_log(
                        "file does not have a .strtab section",
                        zklog::log_level::LOG_LEVEL_CRITICAL);
                    // return after setting some error code  malformed
                }
            }
        }
    }
    zktypes::u8_t *map = (zktypes::u8_t *)get_memory_map();
    auto init_symbol_structs = [&](auto &elf) {
        // elf->set_symbol_table(symtab_t<x64> *new_tab)
        elf.set_symbol_table(
            &map[elf.get_section_header_table()[indexes[ELF_SYMTAB_INDEX]]
                     .sh_offset]);
        elf.set_string_table(
            &map[elf.get_section_header_table()[indexes[ELF_STRTAB_INDEX]]
                     .sh_offset]);
    };
    std::visit(init_symbol_structs, elf_obj);
    return true;
}

bool zkelf::ZkElf::load_dynamic_data(void) {
    if (get_elf_type() != e_type::ET_DYN) {
        if (elf_log.has_value()) {
            elf_log.value()->push_log(
                "file does not have dynamic data",
                zklog::log_level::LOG_LEVEL_CRITICAL,
                zklog::log_error_code::LOG_ERROR_INVALID_FILE_TYPE);
        }
        return false;
    }

    std::array<zktypes::u8_t, ELF_INDEX_ARRAY_SIZE> indexes;
    // retrieving index of the dynamic section
    try {
        indexes[ELF_DYNAMIC_INDEX] = get_section_index_by_name(".dynamic");
    } catch (zkexcept::section_not_found_error &e) {
        try {
            // dynamic section is of type SHF_DYNAMIC and flags SHF_WRITE |
            // SHF_ALLOC
            indexes[ELF_DYNAMIC_INDEX] = get_section_index_by_attr(
                s_type::SHT_DYNAMIC,
                (static_cast<zktypes::u16_t>(sh_flags::SHF_WRITE) |
                 static_cast<zktypes::u16_t>(sh_flags::SHF_ALLOC)));
        } catch (zkexcept::section_not_found_error &e) {
            if (elf_log.has_value()) {
                elf_log.value()->push_log(
                    "file does not have a .dynamic section",
                    zklog::log_level::LOG_LEVEL_CRITICAL,
                    zklog::log_error_code::LOG_ERROR_INVALID_FILE_TYPE);
                // return after setting some error code  malformed
            }
        }
    }
    // retrieving index of the dynsym section
    try {
        indexes[ELF_DYNSYM_INDEX] = get_section_index_by_name(".dynsym");
    } catch (zkexcept::section_not_found_error &e) {
        try {
            // dynsym section has type of SHT_DYNSYM and flags of SHF_ALLOC
            indexes[ELF_DYNSYM_INDEX] = get_section_index_by_attr(
                s_type::SHT_DYNSYM,
                static_cast<zktypes::u8_t>(sh_flags::SHF_ALLOC));
        } catch (zkexcept::section_not_found_error &e) {
            if (elf_log.has_value()) {
                elf_log.value()->push_log(
                    "file does not have a .dynsym section",
                    zklog::log_level::LOG_LEVEL_CRITICAL,
                    zklog::log_error_code::LOG_ERROR_INVALID_FILE_TYPE);
                // return after setting some error code malformed
            }
        }
    }
    try {
        indexes[ELF_DYNSTR_INDEX] = get_section_index_by_name(".dynstr");
    } catch (zkexcept::section_not_found_error &e) {
        try {
            // if failed to find index, we just load the string table
            indexes[ELF_DYNSTR_INDEX] = get_section_index_by_attr(
                s_type::SHT_STRTAB,
                static_cast<zktypes::u8_t>(sh_flags::SHF_ALLOC));
        } catch (zkexcept::section_not_found_error &e) {
            if (elf_log.has_value()) {
                elf_log.value()->push_log(
                    "file does not have a .dynstr section",
                    zklog::log_level::LOG_LEVEL_CRITICAL,
                    zklog::log_error_code::LOG_ERROR_INVALID_FILE_TYPE);
                // return true after setting some error code stripped
            }
        }
    }
    zktypes::u8_t *map = (zktypes::u8_t *)get_memory_map();
    auto init_dynamic_symbol_structs = [&](auto &elf) {
        // load dynamic section
        elf.set_dynamic_section(
            &map[elf.get_section_header_table()[indexes[ELF_DYNAMIC_INDEX]]
                     .sh_offset]);
        elf.set_dynamic_symbol_table(
            &map[elf.get_section_header_table()[indexes[ELF_DYNSYM_INDEX]]
                     .sh_offset]);
        // NOTE make sure dynsym.sh_link holds the index of the string
        // table
        indexes[ELF_DYNSTR_INDEX] =
            elf.get_section_header_table()[indexes[ELF_DYNSYM_INDEX]]
                .sh_link;
        elf.set_dynamic_string_table(
            &map[elf.get_section_header_table()[indexes[ELF_DYNSTR_INDEX]]
                     .sh_offset]);
    };
    std::visit(init_dynamic_symbol_structs, elf_obj);
    return true;
}

void *zkelf::ZkElf::get_memory_map(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        return elf->get_memory_map();
    }
    return std::get_if<ElfObj<x86>>(&elf_obj)->get_memory_map();
}

std::size_t zkelf::ZkElf::get_map_size(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        return elf->get_map_size();
    }
    return std::get_if<ElfObj<x86>>(&elf_obj)->get_map_size();
}

void zkelf::ZkElf::set_stripped(void) {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        elf->set_stripped(true);
    } else if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        elf->set_stripped(true);
    }
}

zkelf::ei_class zkelf::ZkElf::get_elf_class(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        return static_cast<zkelf::ei_class>(
            elf->get_elf_header()
                ->e_ident[static_cast<int>(zkelf::e_ident::EI_CLASS)]);
    }
    return static_cast<zkelf::ei_class>(
        std::get_if<ElfObj<x86>>(&elf_obj)
            ->get_elf_header()
            ->e_ident[static_cast<int>(zkelf::e_ident::EI_CLASS)]);
}

zkelf::ei_data zkelf::ZkElf::get_elf_encoding(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        return static_cast<zkelf::ei_data>(
            elf->get_elf_header()
                ->e_ident[static_cast<int>(zkelf::e_ident::EI_DATA)]);
    }
    return static_cast<zkelf::ei_data>(
        std::get_if<ElfObj<x86>>(&elf_obj)
            ->get_elf_header()
            ->e_ident[static_cast<int>(zkelf::e_ident::EI_DATA)]);
}

zkelf::ei_osabi zkelf::ZkElf::get_elf_osabi(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        return static_cast<zkelf::ei_osabi>(
            elf->get_elf_header()
                ->e_ident[static_cast<int>(zkelf::e_ident::EI_OSABI)]);
    }
    return static_cast<zkelf::ei_osabi>(
        std::get_if<ElfObj<x86>>(&elf_obj)
            ->get_elf_header()
            ->e_ident[static_cast<int>(zkelf::e_ident::EI_OSABI)]);
}

zkelf::e_type zkelf::ZkElf::get_elf_type(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        return elf->get_elf_header()->elf_type;
    }
    return std::get_if<ElfObj<x86>>(&elf_obj)->get_elf_header()->elf_type;
}

zkelf::e_machine zkelf::ZkElf::get_elf_machine(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        return elf->get_elf_header()->elf_machine;
    }
    return std::get_if<ElfObj<x86>>(&elf_obj)
        ->get_elf_header()
        ->elf_machine;
}

zkelf::e_version zkelf::ZkElf::get_elf_version(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        return elf->get_elf_header()->elf_version;
    }
    return std::get_if<ElfObj<x86>>(&elf_obj)
        ->get_elf_header()
        ->elf_version;
}

zktypes::u64_t zkelf::ZkElf::get_elf_entry_point(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        return elf->get_elf_header()->elf_entry;
    }
    return std::get_if<ElfObj<x86>>(&elf_obj)->get_elf_header()->elf_entry;
}

zktypes::u64_t zkelf::ZkElf::get_elf_phdr_offset(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        return elf->get_elf_header()->elf_phoff;
    }
    return std::get_if<ElfObj<x86>>(&elf_obj)->get_elf_header()->elf_phoff;
}

zktypes::u64_t zkelf::ZkElf::get_elf_shdr_offset(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        return elf->get_elf_header()->elf_shoff;
    }
    return std::get_if<ElfObj<x86>>(&elf_obj)->get_elf_header()->elf_shoff;
}

zktypes::u32_t zkelf::ZkElf::get_elf_flags(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        return elf->get_elf_header()->elf_flags;
    }
    return std::get_if<ElfObj<x86>>(&elf_obj)->get_elf_header()->elf_flags;
}

zktypes::u16_t zkelf::ZkElf::get_elf_header_size(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        return elf->get_elf_header()->elf_ehsize;
    }
    return std::get_if<ElfObj<x86>>(&elf_obj)
        ->get_elf_header()
        ->elf_ehsize;
}

zktypes::u16_t zkelf::ZkElf::get_elf_phdr_entry_size(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        return elf->get_elf_header()->elf_phentsize;
    }
    return std::get_if<ElfObj<x86>>(&elf_obj)
        ->get_elf_header()
        ->elf_phentsize;
}

zktypes::u16_t zkelf::ZkElf::get_elf_phdr_entry_count(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        return elf->get_elf_header()->elf_phnum;
    }
    return std::get_if<ElfObj<x86>>(&elf_obj)->get_elf_header()->elf_phnum;
}

zktypes::u16_t zkelf::ZkElf::get_elf_shdr_entry_size(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        return elf->get_elf_header()->elf_shentsize;
    }
    return std::get_if<ElfObj<x86>>(&elf_obj)
        ->get_elf_header()
        ->elf_shentsize;
}

zktypes::u16_t zkelf::ZkElf::get_elf_shdr_entry_count(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        return elf->get_elf_header()->elf_shnum;
    }
    return std::get_if<ElfObj<x86>>(&elf_obj)->get_elf_header()->elf_shnum;
}

zktypes::u16_t zkelf::ZkElf::get_elf_shdr_string_table_index(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        return elf->get_elf_header()->elf_shstrndx;
    }
    return std::get_if<ElfObj<x86>>(&elf_obj)
        ->get_elf_header()
        ->elf_shstrndx;
}

zktypes::u32_t zkelf::ZkElf::get_section_name_index(int shdr_index) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        return elf->get_section_header_table()[shdr_index].sh_name;
    }
    return std::get_if<ElfObj<x86>>(&elf_obj)
        ->get_section_header_table()[shdr_index]
        .sh_name;
}

zkelf::s_type zkelf::ZkElf::get_section_type(int shdr_index) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        return elf->get_section_header_table()[shdr_index].sh_type;
    }
    return std::get_if<ElfObj<x86>>(&elf_obj)
        ->get_section_header_table()[shdr_index]
        .sh_type;
}

zktypes::u64_t zkelf::ZkElf::get_section_flags(int shdr_index) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        return elf->get_section_header_table()[shdr_index].sh_flags;
    }
    return std::get_if<ElfObj<x86>>(&elf_obj)
        ->get_section_header_table()[shdr_index]
        .sh_flags;
}

zktypes::u64_t zkelf::ZkElf::get_section_address(int shdr_index) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        return elf->get_section_header_table()[shdr_index].sh_addr;
    }
    return std::get_if<ElfObj<x86>>(&elf_obj)
        ->get_section_header_table()[shdr_index]
        .sh_addr;
}

zktypes::u64_t zkelf::ZkElf::get_section_offset(int shdr_index) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        return elf->get_section_header_table()[shdr_index].sh_offset;
    }
    return std::get_if<ElfObj<x86>>(&elf_obj)
        ->get_section_header_table()[shdr_index]
        .sh_offset;
}

zktypes::u64_t zkelf::ZkElf::get_section_size(int shdr_index) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        return elf->get_section_header_table()[shdr_index].sh_size;
    }
    return std::get_if<ElfObj<x86>>(&elf_obj)
        ->get_section_header_table()[shdr_index]
        .sh_size;
}

zktypes::u64_t zkelf::ZkElf::get_section_address_alignment(
    int shdr_index) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        return elf->get_section_header_table()[shdr_index].sh_addralign;
    }
    return std::get_if<ElfObj<x86>>(&elf_obj)
        ->get_section_header_table()[shdr_index]
        .sh_addralign;
}

zktypes::u64_t zkelf::ZkElf::get_section_entry_size(int shdr_index) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        return elf->get_section_header_table()[shdr_index].sh_entsize;
    }
    return std::get_if<ElfObj<x86>>(&elf_obj)
        ->get_section_header_table()[shdr_index]
        .sh_entsize;
}

zktypes::u32_t zkelf::ZkElf::get_section_link(int shdr_index) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        return elf->get_section_header_table()[shdr_index].sh_link;
    }
    return std::get_if<ElfObj<x86>>(&elf_obj)
        ->get_section_header_table()[shdr_index]
        .sh_link;
}

zktypes::u32_t zkelf::ZkElf::get_section_info(int shdr_index) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        return elf->get_section_header_table()[shdr_index].sh_info;
    }
    return std::get_if<ElfObj<x86>>(&elf_obj)
        ->get_section_header_table()[shdr_index]
        .sh_info;
}

zkelf::p_type zkelf::ZkElf::get_segment_type(int phdr_index) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        return elf->get_program_header_table()[phdr_index].ph_type;
    }
    return std::get_if<ElfObj<x86>>(&elf_obj)
        ->get_program_header_table()[phdr_index]
        .ph_type;
}

zktypes::u64_t zkelf::ZkElf::get_segment_offset(int phdr_index) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        return elf->get_program_header_table()[phdr_index].ph_offset;
    }
    return std::get_if<ElfObj<x86>>(&elf_obj)
        ->get_program_header_table()[phdr_index]
        .ph_offset;
}

zktypes::u64_t zkelf::ZkElf::get_segment_vaddress(int phdr_index) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        return elf->get_program_header_table()[phdr_index].ph_vaddr;
    }
    return std::get_if<ElfObj<x86>>(&elf_obj)
        ->get_program_header_table()[phdr_index]
        .ph_vaddr;
}

zktypes::u64_t zkelf::ZkElf::get_segment_paddress(int phdr_index) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        return elf->get_program_header_table()[phdr_index].ph_paddr;
    }
    return std::get_if<ElfObj<x86>>(&elf_obj)
        ->get_program_header_table()[phdr_index]
        .ph_paddr;
}

zktypes::u32_t zkelf::ZkElf::get_segment_flags(int phdr_index) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        return elf->get_program_header_table()[phdr_index].ph_flags;
    }
    return std::get_if<ElfObj<x86>>(&elf_obj)
        ->get_program_header_table()[phdr_index]
        .ph_flags;
}

zktypes::u64_t zkelf::ZkElf::get_segment_file_size(int phdr_index) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        return elf->get_program_header_table()[phdr_index].ph_filesz;
    }
    return std::get_if<ElfObj<x86>>(&elf_obj)
        ->get_program_header_table()[phdr_index]
        .ph_filesz;
}

zktypes::u64_t zkelf::ZkElf::get_segment_memory_size(
    int phdr_index) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        return elf->get_program_header_table()[phdr_index].ph_memsz;
    }
    return std::get_if<ElfObj<x86>>(&elf_obj)
        ->get_program_header_table()[phdr_index]
        .ph_memsz;
}

zktypes::u64_t zkelf::ZkElf::get_segment_address_alignment(
    int phdr_index) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        return elf->get_program_header_table()[phdr_index].ph_align;
    }
    return std::get_if<ElfObj<x86>>(&elf_obj)
        ->get_program_header_table()[phdr_index]
        .ph_align;
}

int zkelf::ZkElf::get_section_index_by_name(const char *section_name) {
    auto compare_section_names = [&,
                                  section_name](const auto &elf) -> int {
        if (elf.is_stripped()) {
            if (elf_log.has_value()) {
                elf_log.value()->push_log(
                    "cannot find section header stirng table ",
                    zklog::log_level::LOG_LEVEL_CRITICAL);
            }
            throw zkexcept::section_not_found_error();
        } else {
            auto elfheader = elf.get_elf_header();
            auto shdrtab = elf.get_section_header_table();
            for (std::size_t i = 0; i < elfheader->elf_shnum; ++i) {
                if (!strcmp(&elf.get_section_header_string_table()
                                 [shdrtab[i].sh_name],
                            section_name)) {
                    return i;
                }
            }
        }
        throw zkexcept::section_not_found_error();
    };
    return std::visit(compare_section_names, elf_obj);
}

int zkelf::ZkElf::get_section_index_by_attr(s_type type,
                                            zktypes::u16_t flags) {
    auto compare_section_attributes = [&](const auto &elf) -> int {
        auto shdrtab = elf.get_section_header_table();
        for (auto i = 0; i < get_elf_shdr_entry_count(); ++i) {
            if (static_cast<zktypes::u32_t>(shdrtab[i].sh_type) ==
                    static_cast<zktypes::u32_t>(type) ||
                shdrtab[i].sh_flags == flags) {
                return i;
            }
        }
        throw zkexcept::section_not_found_error();
    };
    return std::visit(compare_section_attributes, elf_obj);
}

int zkelf::ZkElf::get_segment_index_by_attr(zkelf::p_type type,
                                            zktypes::u32_t flags) {
    auto compare_segment_attributes = [&](const auto &elf) -> int {
        auto phdrtab = elf.get_program_header_table();
        for (auto i = 0; i < get_elf_phdr_entry_count(); ++i) {
            if (static_cast<zktypes::u32_t>(phdrtab[i].ph_type) ==
                    static_cast<zktypes::u32_t>(type) ||
                phdrtab[i].ph_flags == flags) {
                return i;
            }
        }
        throw zkexcept::segment_not_found_error();
    };
    return std::visit(compare_segment_attributes, elf_obj);
}

int zkelf::ZkElf::get_symbol_index_by_name(const char *symbol_name) {
    auto compare_symbol_name = [&](auto &elf) -> int {
        if (elf.get_section_index_array()[ELF_SYMTAB_INDEX] == 0 ||
            elf.get_section_index_array()[ELF_STRTAB_INDEX] == 0) {
            return -1;  // bad ret
        }
        auto shdrtab = elf.get_section_header_table();
        auto symtab = elf.get_symbol_table();
        auto strtab = elf.get_string_table();
        for (auto i = 0;
             i <
             shdrtab[elf.get_section_index_array()[ELF_SYMTAB_INDEX]]
                     .sh_size /
                 shdrtab[elf.get_section_index_array()[ELF_SYMTAB_INDEX]]
                     .sh_entsize;
             ++i) {
            if (strcmp(&strtab[symtab[i].st_name], symbol_name) == 0) {
                return i;
            }
        }
        throw zkexcept::symbol_not_found_error();
    };
    return std::visit(compare_symbol_name, elf_obj);
}

int zkelf::ZkElf::get_dynamic_symbol_index_by_name(
    const char *symbol_name) {
    auto compare_symbol_name = [&](auto &elf) -> int {
        if (elf.get_section_index_array()[ELF_DYNSTR_INDEX] == 0 ||
            elf.get_section_index_array()[ELF_DYNSTR_INDEX] == 0) {
            return -1;  // TODO bad ret
        }
        auto shdrtab = elf.get_section_header_table();
        auto dynsym = elf.get_dynamic_symbol_table();
        auto dynstr = elf.get_dynamic_string_table();
        for (auto i = 0;
             i <
             shdrtab[elf.get_section_index_array()[ELF_DYNSYM_INDEX]]
                     .sh_size /
                 shdrtab[elf.get_section_index_array()[ELF_DYNSYM_INDEX]]
                     .sh_entsize;
             ++i) {
            if (strcmp(&dynstr[dynsym[i].st_name], symbol_name) == 0) {
                return i;
            }
        }
        throw zkexcept::symbol_not_found_error();
    };
    return std::visit(compare_symbol_name, elf_obj);
}

// setters
void zkelf::ZkElf::set_elf_type(e_type new_type) {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        elf->get_elf_header()->elf_type = new_type;
    } else if (auto elf = std::get_if<ElfObj<x86>>(&elf_obj)) {
        elf->get_elf_header()->elf_type = new_type;
    }
}

void zkelf::ZkElf::set_elf_machine(e_machine new_machine) {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        elf->get_elf_header()->elf_machine = new_machine;
    } else if (auto elf = std::get_if<ElfObj<x86>>(&elf_obj)) {
        elf->get_elf_header()->elf_machine = new_machine;
    }
}

void zkelf::ZkElf::set_elf_version(e_version new_version) {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        elf->get_elf_header()->elf_version = new_version;
    } else if (auto elf = std::get_if<ElfObj<x86>>(&elf_obj)) {
        elf->get_elf_header()->elf_version = new_version;
    }
}

void zkelf::ZkElf::set_elf_flags(zktypes::u32_t new_flags) {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        elf->get_elf_header()->elf_flags = new_flags;
    } else if (auto elf = std::get_if<ElfObj<x86>>(&elf_obj)) {
        elf->get_elf_header()->elf_flags = new_flags;
    }
}

void zkelf::ZkElf::set_elf_phdr_entry_count(zktypes::u16_t new_count) {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        elf->get_elf_header()->elf_phnum = new_count;
    } else if (auto elf = std::get_if<ElfObj<x86>>(&elf_obj)) {
        elf->get_elf_header()->elf_phnum = new_count;
    }
}

void zkelf::ZkElf::set_elf_shdr_entry_count(zktypes::u16_t new_count) {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        elf->get_elf_header()->elf_shnum = new_count;
    } else if (auto elf = std::get_if<ElfObj<x86>>(&elf_obj)) {
        elf->get_elf_header()->elf_shnum = new_count;
    }
}

void zkelf::ZkElf::set_elf_shdr_string_table_index(
    zktypes::u16_t new_index) {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        elf->get_elf_header()->elf_shstrndx = new_index;
    } else if (auto elf = std::get_if<ElfObj<x86>>(&elf_obj)) {
        elf->get_elf_header()->elf_shstrndx = new_index;
    }
}

void zkelf::ZkElf::set_section_name_index(int shdr_index,
                                          zktypes::u32_t new_index) {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        elf->get_section_header_table()[shdr_index].sh_name = new_index;
    } else {
        elf->get_section_header_table()[shdr_index].sh_name = new_index;
    }
}

void zkelf::ZkElf::set_section_type(int shdr_index, s_type new_type) {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        elf->get_section_header_table()[shdr_index].sh_type = new_type;
    } else {
        elf->get_section_header_table()[shdr_index].sh_type = new_type;
    }
}

void zkelf::ZkElf::set_section_link(int shdr_index,
                                    zktypes::u32_t new_link) {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        elf->get_section_header_table()[shdr_index].sh_link = new_link;
    } else {
        elf->get_section_header_table()[shdr_index].sh_link = new_link;
    }
}

void zkelf::ZkElf::set_section_info(int shdr_index,
                                    zktypes::u32_t new_info) {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        elf->get_section_header_table()[shdr_index].sh_info = new_info;
    } else {
        elf->get_section_header_table()[shdr_index].sh_info = new_info;
    }
}

void zkelf::ZkElf::set_segment_type(int phdr_index, p_type new_type) {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        elf->get_program_header_table()[phdr_index].ph_type = new_type;
    } else {
        elf->get_program_header_table()[phdr_index].ph_type = new_type;
    }
}

void zkelf::ZkElf::set_segment_flags(int phdr_index,
                                     zktypes::u32_t new_flags) {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
        elf->get_program_header_table()[phdr_index].ph_flags = new_flags;
    } else {
        elf->get_program_header_table()[phdr_index].ph_flags = new_flags;
    }
}

void *zkelf::ZkElf::elf_read(off_t read_offset,
                             size_t size) const noexcept {
    auto e_read = [&read_offset, &size](const auto &elf) -> void * {
        zktypes::u8_t *map = (zktypes::u8_t *)elf.get_memory_map();
        zktypes::u8_t *buffer =
            (zktypes::u8_t *)calloc(size, sizeof(zktypes::u8_t));
        if (buffer == nullptr) throw std::bad_alloc();

        for (int i = read_offset; i < read_offset + size; i++) {
            buffer[i] = map[i];
        }
        return buffer;
    };
    return std::visit(e_read, elf_obj);
}

void zkelf::ZkElf::elf_write(void *buffer, off_t write_offset,
                             size_t size) const noexcept {
    auto e_write = [&buffer, &write_offset, &size](const auto &elf) {
        zktypes::u8_t *map = (zktypes::u8_t *)elf.get_memory_map();
        zktypes::u8_t *src = (zktypes::u8_t *)buffer;
        for (int i = 0; i < write_offset + size; i++) {
            src[i] = map[i];
        }
        // auto_save_map();
    };
    std::visit(e_write, elf_obj);
}

struct save {
    void *memory_map;
    std::size_t size;

    void operator()(const char *path) {
        remove(path);
        zkutils::save_memory_map(path, memory_map, size);
    }
    void operator()(pid_t pid) {
        // TODO write to the process somehow lol
    }
};

// make this static or something idk
void zkelf::ZkElf::save_source(void) const noexcept {
    if (ZK_CHECK_FLAGS(
            static_cast<zktypes::u8_t>(elf_flag),
            static_cast<zktypes::u8_t>(elf_flags::ELF_AUTO_SAVE))) {
        // std::visit(save{}, elf_source);
    }
}

/*
void zkelf::ZkElf::set_section_data_by_index(int index, void *new_data,
                                             std::size_t size) {}

void zkelf::ZkElf::set_section_data_by_name(const char *section_name,
                                            void *new_data,
                                            std::size_t size) {
    int index = 0;
    try {
        index = get_section_index_by_name(section_name);
    } catch (zkexcept::section_not_found_error &e) {
        // failed;
    }

    if (auto elf = std::get_if<ElfObj<x64>>(&elf_obj)) {
    } else if (auto elf = std::get_if<ElfObj<x86>>(&elf_obj)) {
    }
}
*/

/*
template <typename T>
void zkelf::ElfObj<T>::set_section_data(int section_index, void *new_data,
                                        std::size_t size) {
    auto org_offset = e_shdrtab[section_index].sh_offset;
    auto org_size = e_shdrtab[section_index].sh_size;
    if (org_size == size) {
        // if size new_data and size of the section is same, we simply
        // overwrite section data with new_data
        elf_write(new_data, org_offset, size);
    } else if (org_size < size) {
        // if section size is less than size, we move data located after
        // the section and make space for our data. + we dont have to care
        // about section alignment since this is just on the disk
        auto remaining_size = size - org_size;
        void *remainig_data =
            elf_read(org_offset + org_size,
                     get_map_size() - (org_offset + org_size));
        elf_write(new_data + org_size, org_offset + org_size,
                  remaining_size);
        elf_write(remainig_data, org_offset + size,
                  get_map_size() - (org_offset + org_size));

        // go through section headers and increase the offsets
        set_map_size(get_map_size() + (remaining_size));
    } else {
        // if section size is greater than size, we simply write new_data
        // and memset 0 the rest
        elf_write(new_data, org_offset, size);
        zktypes::u8_t null_array[org_size - size] = {0};
        elf_write(null_array, org_offset + size, org_size - size);
    }
}
*/

template class zkelf::ElfObj<x86>;
template class zkelf::ElfObj<x64>;

/*
void ZkElf::Elf::autoSaveMemMap(void) const {
    if (elf_flags == ELF_AUTO_SAVE) {
    remove(GetPathname());
    ZkUtils::save_memory_map(GetPathname(), GetMemoryMap(),
                    GetElfSize());
    }
}
*/
/*
// TODO narrow down errno to report user about the error that caused
expection
// TODO replace asserts with return codes

ZkElf::Elf::Elf(ZkElf::ELF_FLAGS flags)
    :elf_flags(flags), elf_log(nullptr)
{}

ZkElf::Elf::Elf(const char *pathname, ZkElf::ELF_FLAGS flags,
std::optinal <ZkLog::Log *>log) :elf_pathname(pathname),
elf_flags(flags), elf_log(log)
{
    try{
        OpenElf();
        return;
    } catch (std::exception& e) {
        std::cerr << e.what();
        std::exit(1);
    }
}


ZkElf::Elf::~Elf()
{
    if (elf_flags == ELF_SAVE_AT_EXIT) {
        ZkUtils::save_memory_map(GetPathname(), GetMemoryMap(),
                GetElfSize());
    }
    try{
        RemoveMap();
    } catch(std::exception& e){
        std::cout << e.what();
        std::abort();
    }
}

bool ZkElf::Elf::OpenElf(void)
{
    assert(elf_pathname != nullptr && "pathname is not specified");
    if (elf_pathname == nullptr) {
        if (elf_log.has_value())
            elf_log.value()->PushLog("pathname is not specified",
                             ZkLog::LOG_LEVEL_ERROR);
        return false;
    }

    int fd = open(elf_pathname, O_RDONLY);
    if(fd < 0)
        throw ZkExcept::file_not_found_error();

    struct stat st;
    if(fstat(fd, &st) < 0)
        throw std::runtime_error("fstat failed");

    SetElfSize(st.st_size);
    try {
        loadFile(fd);
    } catch (std::exception& ex) {
        std::cerr << ex.what() << std::endl;
        std::exit(1);
    }

    return true;
}

// load the elf binary into memory, parse most essential headers
void ZkElf::Elf::loadFile(int fd)
{
    elf_memmap = mmap(nullptr, GetElfSize(), PROT_READ | PROT_WRITE,
            MAP_PRIVATE, fd, 0);
    if(elf_memmap == MAP_FAILED){
        throw std::runtime_error("mmap failed\n");
    }
    if (close(fd) < 0) {
        throw std::runtime_error("close failed\n");
    }
    elf_ehdr = (ehdr_t *)elf_memmap;
    assert(VerifyElf() != true && "File is not an Elf binary");

    u8_t *m = (u8_t *)elf_memmap;
    assert(elf_ehdr->e_phoff < elf_size &&
            "Anomaly detected in program header offset");
    elf_phdr = (phdr_t *)&m[elf_ehdr->e_phoff];
        assert(elf_ehdr->e_shoff < elf_size &&
            "Anomaly detected in section header offset");
    elf_shdr = (shdr_t *)&m[elf_ehdr->e_shoff];


    int symtab_index = 0;
    try{
        symtab_index = GetSectionIndexbyName(".symtab");
        elf_section_indexes[ELF_SYMTAB_INDEX] = symtab_index;
    } catch (ZkExcept::section_not_found_error& e){
        std::cerr << e.what();
        std::exit(1);
    }
    u8_t *memmap = (u8_t *)elf_memmap;
    elf_symtab = (symtab_t *)&memmap[elf_shdr[symtab_index].sh_offset];
    elf_section_indexes[ELF_STRTAB_INDEX] =
elf_shdr[symtab_index].sh_link; elf_strtab =
(strtab_t)&memmap[elf_shdr[elf_section_indexes
        [ELF_STRTAB_INDEX]].sh_offset];
}

bool ZkElf::Elf::LoadDynamicData(void)
{
    if (GetElfType() != ET_DYN) {
        if (elf_log.has_value())
            elf_log.value()->PushLog("file does not have dynamic data",
                         ZkLog::LOG_LEVEL_ERROR);
        return false;
    }
    int dynamic_index = 0;
    try{
        dynamic_index = GetSectionIndexbyName(".dynamic");
        elf_section_indexes[ELF_DYNAMIC_INDEX] = dynamic_index;
    } catch (ZkExcept::section_not_found_error& e){
        std::cerr << e.what();
        std::exit(1);
    }

    u8_t *memmap = (u8_t *)elf_memmap;
    elf_dynamic = (dynamic_t
*)&memmap[elf_shdr[dynamic_index].sh_offset];
    elf_section_indexes[ELF_DYNSTR_INDEX] = elf_shdr[dynamic_index].
        sh_link;
    elf_dynstr = (strtab_t) &memmap[elf_shdr[elf_section_indexes
        [ELF_DYNSTR_INDEX]]
        .sh_offset];
    int dynsym_index = 0;
    try{
        dynsym_index = GetSectionIndexbyName(".dynsym");
        elf_section_indexes[ELF_DYNSYM_INDEX] = dynsym_index;
    } catch (ZkExcept::section_not_found_error& e){
        std::cerr << e.what();
        std::exit(1);
    }

    elf_dynsym = (symtab_t *)&memmap[elf_shdr[dynsym_index].sh_offset];
    return true;
}

bool ZkElf::Elf::VerifyElf(void) const
{
    if(elf_ehdr->e_ident[0] != 0x7f || elf_ehdr->e_ident[1] != 0x45 ||
            elf_ehdr->e_ident[2] != 0x4c || elf_ehdr->e_ident[4] !=
0x46)
    {
        return false;
    }

#ifdef __BITS_64__
    if(elf_ehdr->e_ident[EI_CLASS] == ELFCLASS32) {
        return false;
    }

#elif __BITS32__
    if(elf_ehdr->e_ident[EI_CLASS] == ELFCLASS64) {
        return false;
    }
#endif
    return true;
}

void ZkElf::Elf::RemoveMap(void)
{
    assert(elf_memmap != nullptr && "memory is not mapped to unmap");
    if(munmap(elf_memmap, elf_size) < 0)
        throw std::runtime_error("munmap failed");

    elf_memmap = nullptr;
}

int ZkElf::Elf::GetSegmentIndexbyAttr(u32_t type, u32_t flags, u32_t
        prev_flags) const
{
    for(int i = 0; i < elf_ehdr->e_phnum; i++){
        if(elf_phdr[i].p_type == type && elf_phdr[i].p_flags == flags){
            if(prev_flags != 0){
                if(elf_phdr[i - 1].p_flags == prev_flags)
                    return i;
            } else
                return i;
        }
    }
    throw ZkExcept::segment_not_found_error();
}

int ZkElf::Elf::GetSectionIndexbyAttr(u32_t type, u32_t flags) const
{
    for(int i = 0; i < elf_ehdr->e_shnum; i++){
        if(elf_shdr[i].sh_type == type && elf_shdr[i].sh_flags ==
                flags) {
            return i;
        }
    }
    throw ZkExcept::section_not_found_error();
}

// duh you cant get a segment by name

int ZkElf::Elf::GetSectionIndexbyName(const char *name) const
{
    if(elf_ehdr->e_shstrndx == 0) {
        throw ZkExcept::stripped_binary_error("section header string \
                table not found");
    }
    strtab_t memmap = (strtab_t)elf_memmap;
    strtab_t shstrtab =
&memmap[elf_shdr[elf_ehdr->e_shstrndx].sh_offset]; for(int i = 0; i<
elf_ehdr->e_shnum; i++){ if(strcmp(&shstrtab[elf_shdr[i].sh_name],
name) == 0){ return i;
        }
    }
    throw ZkExcept::section_not_found_error();
}

int ZkElf::Elf::GetSymbolIndexbyName(const char *name)
    const
{
    int index = elf_section_indexes[ELF_SYMTAB_INDEX];
    for(int i = 0; i < elf_shdr[index].sh_size / sizeof(symtab_t);
i++){ if(strcmp(&elf_strtab[elf_symtab[i].st_name], name) == 0){ return
i;
        }
    }
    throw ZkExcept::symbol_not_found_error();
}

int ZkElf::Elf::GetDynSymbolIndexbyName(const char *name)
    const
{
    assert(elf_section_indexes[ELF_DYNSYM_INDEX] != 0 &&
            "dynamic sections are not parsed\n");
    int index = elf_section_indexes[ELF_DYNSTR_INDEX];
    for(int i = 0; i < elf_shdr[index].sh_size / sizeof(symtab_t);
i++){ if(strcmp(&elf_dynstr[elf_dynsym[i].st_name], name) == 0){ return
i;
        }
    }
    throw ZkExcept::symbol_not_found_error();
}



void ZkElf::Elf::SetElfType(u16_t new_type)
{
    elf_ehdr->e_type = new_type;
    autoSaveMemMap();
}

void ZkElf::Elf::SetElfMachine(u16_t new_machine)
{
    elf_ehdr->e_machine = new_machine;
    autoSaveMemMap();
}

void ZkElf::Elf::SetElfVersion(u32_t new_version)
{
    elf_ehdr->e_version = new_version;
    autoSaveMemMap();
}

void ZkElf::Elf::SetElfEntryPoint(addr_t new_entry)
{
    elf_ehdr->e_entry = new_entry;
    autoSaveMemMap();
}

void ZkElf::Elf::SetElfPhdrOffset(off_t new_offset)
{
    elf_ehdr->e_phoff = new_offset;
    autoSaveMemMap();
}

void ZkElf::Elf::SetElfShdrOffset(off_t new_offset)
{
    elf_ehdr->e_shoff = new_offset;
    autoSaveMemMap();
}

void ZkElf::Elf::SetElfFlags(u32_t new_flags)
{
    elf_ehdr->e_flags = new_flags;
    autoSaveMemMap();
}

void ZkElf::Elf::SetPhdrCount(u16_t new_count)
{
    elf_ehdr->e_phnum = new_count;
    autoSaveMemMap();
}

void ZkElf::Elf::SetShdrCount(u16_t new_count)
{
    elf_ehdr->e_shnum = new_count;
    autoSaveMemMap();
}

void ZkElf::Elf::SetShstrndx(u16_t new_index)
{
    elf_ehdr->e_shstrndx = new_index;
    autoSaveMemMap();
}

void ZkElf::Elf::SetElfHeader(ehdr_t *new_ehdr)
{
    memcpy(elf_ehdr, new_ehdr, GetElfHeaderSize());
    autoSaveMemMap();
}

void ZkElf::Elf::SetSectionNameIndex(int shdr_index, int new_index)
{
    elf_shdr[shdr_index].sh_name = new_index;
    autoSaveMemMap();
}
void ZkElf::Elf::SetSectionType(int shdr_index, u32_t new_type)
{
    elf_shdr[shdr_index].sh_type = new_type;
    autoSaveMemMap();
}
void ZkElf::Elf::SetSectionAddress(int shdr_index, addr_t new_addr)
{
    elf_shdr[shdr_index].sh_addr = new_addr;
    autoSaveMemMap();
}
void ZkElf::Elf::SetSectionOffset(int shdr_index, off_t new_offset)
{
    elf_shdr[shdr_index].sh_offset = new_offset;
    autoSaveMemMap();
}

template <typename T>
void ZkElf::Elf::SetSectionSize(int shdr_index, T t)
{
    if constexpr (std::is_same<u64_t, T>::value ||
            std::is_same<u32_t, T>::value) {
        elf_shdr[shdr_index].sh_size = t;
        autoSaveMemMap();
    }
}

template <typename T>
void ZkElf::Elf::SetSectionAddressAlign(int shdr_index, T t)
{
    if (std::is_same<u64_t, T>::value ||
            std::is_same<u32_t, T>::value ) {
        elf_shdr[shdr_index].sh_addralign = t;
        autoSaveMemMap();
    }
}

template <typename T>
void ZkElf::Elf::SetSectionEntrySize(int shdr_index, T t)
{
    if (std::is_same<u64_t, T>::value ||
            std::is_same<u32_t, T>::value) {
        elf_shdr[shdr_index].sh_entsize = t;
        autoSaveMemMap();
    }
}
// remove tjos
#ifdef __x86_64__
void ZkElf::Elf::SetSectionSize(int shdr_index, u64_t new_size)
{
    elf_shdr[shdr_index].sh_size = new_size;
    autoSaveMemoryMap();
}
void ZkElf::Elf::SetSectionAddressAlign(int shdr_index, u64_t
new_address_align)
{
    elf_shdr[shdr_index].sh_addralign = new_address_align;
    autoSaveMemoryMap();
}
void ZkElf::Elf::SetSectionEntrySize(int shdr_index, u64_t new_size)
{
    elf_shdr[shdr_index].sh_entsize = new_size;
    autoSaveMemoryMap();
}

#elif __i386__
void ZkElf::Elf::SetSectionSize(int shdr_index, u32 new_size)
{
    elf_shdr[shdr_index].sh_size = new_size;
    autoSaveMemoryMap();
}
void ZkElf::Elf::SetSectionAddressAlign(int shdr_index, u32
new_address_align)
{
    elf_shdr[shdr_index].sh_addralign = new_address_align;
    autoSaveMemoryMap();
}
void ZkElf::Elf::SetSectionEntrySize(int shdr_index, u32 new_size)
{
    elf_shdr[shdr_index].sh_entsize = new_size;
    autoSaveMemoryMap();
}

#endif
// remove this

void ZkElf::Elf::SetSectionHeader(int shdr_index, shdr_t *new_shdr)
{
    memcpy(&elf_shdr[shdr_index], new_shdr, GetElfShdrEntrySize());
    autoSaveMemMap();
}

void ZkElf::Elf::SetSectionData(int shdr_index, void *data)
{
    auto offset = GetSectionOffset(shdr_index);
    memcpy(((u8_t *)GetMemoryMap() + offset), data, GetSectionSize(
                shdr_index));
    autoSaveMemMap();
}

void ZkElf::Elf::SetSegmentType(int phdr_index, u32_t new_type)
{
    elf_phdr[phdr_index].p_type = new_type;
    autoSaveMemMap();

}
void ZkElf::Elf::SetSegmentOffset(int phdr_index, off_t new_offset)
{
    elf_phdr[phdr_index].p_offset = new_offset;
    autoSaveMemMap();
}
void ZkElf::Elf::SetSegmentVAddress(int phdr_index, addr_t new_address)
{
    elf_phdr[phdr_index].p_vaddr = new_address;
    autoSaveMemMap();
}
void ZkElf::Elf::SetSegmentPAddress(int phdr_index, addr_t new_address)
{
    elf_phdr[phdr_index].p_paddr = new_address;
    autoSaveMemMap();
}
void ZkElf::Elf::SetSegmentFlags(int phdr_index, u32_t new_flags)
{
    elf_phdr[phdr_index].p_flags = new_flags;
    autoSaveMemMap();
}

template <typename T>
void ZkElf::Elf::SetSegmentFileSize(int phdr_index, T t)
{
    if (std::is_same<u64_t, T>::value || std::is_same<u32_t, T>::value)
{ elf_phdr[phdr_index].p_filesz = t; autoSaveMemMap();
    }
}

template <typename T>
void ZkElf::Elf::SetSegmentMemorySize(int phdr_index, T t)
{
    if (std::is_same<u64_t, T>::value || std::is_same<u32_t, T>::value)
{ elf_phdr[phdr_index].p_memsz = t; autoSaveMemMap();
    }
}

template <typename T>
void ZkElf::Elf::SetSegmentAlignment(int phdr_index, T t)
{
    if (std::is_same<u64_t, T>::value || std::is_same<u32_t, T>::value)
{ elf_phdr[phdr_index].p_align = t; autoSaveMemMap();
    }
}

// remove this
#ifdef __x86_64__
void ZkElf::Elf::SetSegmentFileSize(int phdr_index, u64_t new_size)
{
    elf_phdr[phdr_index].p_filesz = new_size;
    autoSaveMemMap();
}
void ZkElf::Elf::SetSegmentMemorySize(int phdr_index, u64_t new_size)
{
    elf_phdr[phdr_index].p_memsz = new_size;
    autoSaveMemMap();
}
void ZkElf::Elf::SetSegmentAlignment(int phdr_index, u64_t
new_alignment)
{
    elf_phdr[phdr_index].p_align = new_alignment;
    autoSaveMemMap();
}
#elif __i386__
void ZkElf::Elf::SetSegmentFileSize(int phdr_index, u32 new_size)
{
    elf_phdr[phdr_index].p_filesz = new_size;
    autoSaveMemoryMap();
}
void ZkElf::Elf::SetSegmentMemorySize(int phdr_index, u32 new_size)
{
    elf_phdr[phdr_index].p_memsz = new_size;
    autoSaveMemoryMap();
}
void ZkElf::Elf::SetSegmentAlignment(int phdr_index, u32 new_alignment)
{
    elf_phdr[phdr_index].p_align = new_alignment;
    autoSaveMemoryMap();
}
#endif
// remove


void ZkElf::Elf::SetSegmentHeader(int phdr_index, phdr_t *new_phdr)
{
    memcpy(&elf_phdr[phdr_index], new_phdr, sizeof(phdr_t));
    autoSaveMemMap();
}

void ZkElf::Elf::SetSegmentData(int phdr_index, void *data)
{
    auto offset = GetSegmentOffset(phdr_index);
    memcpy(((u8_t *)GetMemoryMap() + offset), data,
            GetSegmentFileSize(phdr_index));
    autoSaveMemMap();
}

void *ZkElf::Elf::ElfRead(off_t readoff, size_t size) const
{
    u8_t *buffer = (u8_t *)calloc(size, sizeof(u8_t));
    if(buffer == nullptr)
        throw std::bad_alloc();

    u8_t *memmap = (u8_t *)elf_memmap;
    for(int i = readoff; i < readoff + size; i++){
        buffer[i] = memmap[i];
    }
    return buffer;
}

void ZkElf::Elf::ElfWrite(void *buffer, off_t writeoff, size_t size)
    const
{
    u8_t *memmap = (u8_t *)elf_memmap;
    u8_t *_buffer = (u8_t *)buffer;
    for(int i = 0; i < writeoff + size; i++){
        _buffer[i] = memmap[i];
    }
    autoSaveMemMap();
}

void ZkElf::Elf::autoSaveMemMap(void) const
{
    if (elf_flags == ELF_AUTO_SAVE) {
        remove(GetPathname());
        ZkUtils::save_memory_map(GetPathname(), GetMemoryMap(),
                GetElfSize());
    }
}
*/
