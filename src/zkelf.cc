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

// default is to load elf with elf_read_only
std::shared_ptr<zkelf::ZkElf> zkelf::load_elf_from_file(
    const char *path, std::optional<zklog::ZkLog *> log) {
    auto pair = zkutils::open_file(path, false);
    auto *core = (elf_core *)pair.first;
    // check the magic number to validate the file
    zktypes::u8_t magic[4] = {0x7f, 0x45, 0x4c, 0x46};
    if (!zkutils::validate_magic_number<zktypes::u8_t, 4>(core->ei_magic,
                                                          magic)) {
        throw zkexcept::invalid_file_format_error();
    }

    if (core->ei_class == (zktypes::u8_t)ei_class::ELFCLASS32) {
        std::shared_ptr<ZkElf> ptr = std::make_shared<ZkElf>(
            ElfObj<x86>((void *)pair.first, pair.second, path),
            elf_read_only{}, log);
        return ptr;
    } else if (core->ei_class == (zktypes::u8_t)ei_class::ELFCLASS64) {
        std::shared_ptr<ZkElf> ptr = std::make_shared<ZkElf>(
            ElfObj<x64>((void *)pair.first, pair.second, path),
            elf_read_only{}, log);
        return ptr;
    } else {
        throw zkexcept::invalid_file_type_error();
    }
}

// default is to load elf with elf_read_write and ELF_AUTO_SAVE
std::shared_ptr<zkelf::ZkElf> zkelf::load_elf_writable_from_file(
    const char *path, std::optional<elf_save_options> save_options,
    std::optional<zklog::ZkLog *> log) {
    auto pair = zkutils::open_file(path, true);
    auto *core = (elf_core *)pair.first;
    // check the magic number to validate the file
    zktypes::u8_t magic[4] = {0x7f, 0x45, 0x4c, 0x46};
    if (!zkutils::validate_magic_number<zktypes::u8_t, 4>(core->ei_magic,
                                                          magic)) {
        throw zkexcept::invalid_file_format_error();
    }

    if (core->ei_class == (zktypes::u8_t)ei_class::ELFCLASS32) {
        std::shared_ptr<ZkElf> ptr = std::make_shared<ZkElf>(
            ElfObj<x86>((void *)pair.first, pair.second, path),
            elf_read_write{elf_save_options::ELF_AUTO_SAVE}, log);
        return ptr;
    } else if (core->ei_class == (zktypes::u8_t)ei_class::ELFCLASS64) {
        std::shared_ptr<ZkElf> ptr = std::make_shared<ZkElf>(
            ElfObj<x64>((void *)pair.first, pair.second, path),
            elf_read_write{elf_save_options::ELF_AUTO_SAVE}, log);
        return ptr;
    } else {
        throw zkexcept::invalid_file_type_error();
    }
}

// TODO for this we need an instrace of ptrace
void zkelf::load_elf_from_memory() {
    // load from memory using ptrace
}

template <typename T>
zkelf::ElfObj<T>::ElfObj(void *map, std::size_t size,
                         std::variant<const char *, pid_t> s)
    : e_memory_map(map), e_map_size(size), e_source(s) {
    e_ehdr = (ehdr_t<T> *)e_memory_map;
    e_phdrtab =
        (phdr_t<T> *)((zktypes::u8_t *)e_memory_map + e_ehdr->elf_phoff);
    e_shdrtab =
        (shdr_t<T> *)((zktypes::u8_t *)e_memory_map + e_ehdr->elf_shoff);
    if (e_ehdr->elf_shstrndx ==
            static_cast<zktypes::u16_t>(sh_n::SHN_UNDEF) ||
        e_ehdr->elf_shstrndx > e_ehdr->elf_shnum ||
        e_shdrtab[e_ehdr->elf_shstrndx].sh_offset > size) {
        e_is_stripped = true;
    } else {
        e_shstrtab = (strtab_t)e_memory_map +
                     e_shdrtab[e_ehdr->elf_shstrndx].sh_offset;
    }
}

template <typename T>
bool zkelf::ElfObj<T>::is_stripped() const {
    return e_is_stripped;
}

template <typename T>
void *zkelf::ElfObj<T>::get_memory_map() const {
    return e_memory_map;
}

template <typename T>
std::size_t zkelf::ElfObj<T>::get_map_size() const {
    return e_map_size;
}

template <typename T>
std::variant<const char *, pid_t> zkelf::ElfObj<T>::get_elf_source()
    const {
    return e_source;
}

template <typename T>
zkelf::ehdr_t<T> *zkelf::ElfObj<T>::get_elf_header() const {
    return e_ehdr;
}

template <typename T>
zkelf::phdr_t<T> *zkelf::ElfObj<T>::get_program_header_table() const {
    return e_phdrtab;
}

template <typename T>
zkelf::shdr_t<T> *zkelf::ElfObj<T>::get_section_header_table() const {
    return e_shdrtab;
}

template <typename T>
zkelf::strtab_t zkelf::ElfObj<T>::get_section_header_string_table() const {
    return e_shstrtab;
}

template <typename T>
zkelf::strtab_t zkelf::ElfObj<T>::get_string_table() const {
    return e_strtab;
}

template <typename T>
zkelf::strtab_t zkelf::ElfObj<T>::get_dynamic_string_table() const {
    return e_dynstr;
}

template <typename T>
zkelf::symtab_t<T> *zkelf::ElfObj<T>::get_symbol_table() const {
    return e_symtab;
}

template <typename T>
zkelf::symtab_t<T> *zkelf::ElfObj<T>::get_dynamic_symbol_table() const {
    return e_dynsym;
}

template <typename T>
zkelf::dynamic_t<T> *zkelf::ElfObj<T>::get_dynamic_section() const {
    return e_dynamic;
}

template <typename T>
zkelf::nhdr_t<T> *zkelf::ElfObj<T>::get_note_section() const {
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
decltype(auto) zkelf::ElfObj<T>::get_section_index_array() {
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
        memcpy((void *)&((zktypes::u8_t *)get_memory_map())
                   [e_shdrtab[e_ehdr->elf_shstrndx].sh_offset],
               new_tab,
               ((zktypes::u8_t *)get_memory_map())
                   [e_shdrtab[e_ehdr->elf_shstrndx].sh_size]);
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

zkelf::ZkElf::ZkElf(std::variant<ElfObj<x64>, ElfObj<x86>> obj,
                    std::variant<elf_read_only, elf_read_write> options,
                    std::optional<zklog::ZkLog *> log)
    : elf_file_options(options), elf_object(obj), elf_log(log) {}

bool zkelf::ZkElf::load_symbol_data() {
    std::array<zktypes::u8_t, ELF_INDEX_ARRAY_SIZE> indexes{};
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object))
        indexes = elf->get_section_index_array();
    else {
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
    std::visit(init_symbol_structs, elf_object);
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
    std::visit(init_dynamic_symbol_structs, elf_object);
    return true;
}

void *zkelf::ZkElf::get_memory_map(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return elf->get_memory_map();
    }
    return std::get_if<ElfObj<x86>>(&elf_object)->get_memory_map();
}

std::size_t zkelf::ZkElf::get_map_size(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return elf->get_map_size();
    }
    return std::get_if<ElfObj<x86>>(&elf_object)->get_map_size();
}

bool zkelf::ZkElf::is_stripped(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return elf->is_stripped();
    }
    return std::get_if<ElfObj<x86>>(&elf_object)->is_stripped();
}

void zkelf::ZkElf::set_stripped(void) {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        elf->set_stripped(true);
    } else if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        elf->set_stripped(true);
    }
}

zkelf::ei_class zkelf::ZkElf::get_elf_class(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return static_cast<zkelf::ei_class>(
            elf->get_elf_header()
                ->e_ident[static_cast<int>(zkelf::e_ident::EI_CLASS)]);
    }
    return static_cast<zkelf::ei_class>(
        std::get_if<ElfObj<x86>>(&elf_object)
            ->get_elf_header()
            ->e_ident[static_cast<int>(zkelf::e_ident::EI_CLASS)]);
}

zkelf::ei_data zkelf::ZkElf::get_elf_encoding(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return static_cast<zkelf::ei_data>(
            elf->get_elf_header()
                ->e_ident[static_cast<int>(zkelf::e_ident::EI_DATA)]);
    }
    return static_cast<zkelf::ei_data>(
        std::get_if<ElfObj<x86>>(&elf_object)
            ->get_elf_header()
            ->e_ident[static_cast<int>(zkelf::e_ident::EI_DATA)]);
}

zkelf::ei_osabi zkelf::ZkElf::get_elf_osabi(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return static_cast<zkelf::ei_osabi>(
            elf->get_elf_header()
                ->e_ident[static_cast<int>(zkelf::e_ident::EI_OSABI)]);
    }
    return static_cast<zkelf::ei_osabi>(
        std::get_if<ElfObj<x86>>(&elf_object)
            ->get_elf_header()
            ->e_ident[static_cast<int>(zkelf::e_ident::EI_OSABI)]);
}

zkelf::e_type zkelf::ZkElf::get_elf_type(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return elf->get_elf_header()->elf_type;
    }
    return std::get_if<ElfObj<x86>>(&elf_object)
        ->get_elf_header()
        ->elf_type;
}

zkelf::e_machine zkelf::ZkElf::get_elf_machine(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return elf->get_elf_header()->elf_machine;
    }
    return std::get_if<ElfObj<x86>>(&elf_object)
        ->get_elf_header()
        ->elf_machine;
}

zkelf::e_version zkelf::ZkElf::get_elf_version(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return elf->get_elf_header()->elf_version;
    }
    return std::get_if<ElfObj<x86>>(&elf_object)
        ->get_elf_header()
        ->elf_version;
}

zktypes::u64_t zkelf::ZkElf::get_elf_entry_point(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return elf->get_elf_header()->elf_entry;
    }
    return std::get_if<ElfObj<x86>>(&elf_object)
        ->get_elf_header()
        ->elf_entry;
}

zktypes::u64_t zkelf::ZkElf::get_elf_phdr_offset(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return elf->get_elf_header()->elf_phoff;
    }
    return std::get_if<ElfObj<x86>>(&elf_object)
        ->get_elf_header()
        ->elf_phoff;
}

zktypes::u64_t zkelf::ZkElf::get_elf_shdr_offset(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return elf->get_elf_header()->elf_shoff;
    }
    return std::get_if<ElfObj<x86>>(&elf_object)
        ->get_elf_header()
        ->elf_shoff;
}

zktypes::u32_t zkelf::ZkElf::get_elf_flags(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return elf->get_elf_header()->elf_flags;
    }
    return std::get_if<ElfObj<x86>>(&elf_object)
        ->get_elf_header()
        ->elf_flags;
}

zktypes::u16_t zkelf::ZkElf::get_elf_header_size(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return elf->get_elf_header()->elf_ehsize;
    }
    return std::get_if<ElfObj<x86>>(&elf_object)
        ->get_elf_header()
        ->elf_ehsize;
}

zktypes::u16_t zkelf::ZkElf::get_elf_phdr_entry_size(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return elf->get_elf_header()->elf_phentsize;
    }
    return std::get_if<ElfObj<x86>>(&elf_object)
        ->get_elf_header()
        ->elf_phentsize;
}

zktypes::u16_t zkelf::ZkElf::get_elf_phdr_entry_count(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return elf->get_elf_header()->elf_phnum;
    }
    return std::get_if<ElfObj<x86>>(&elf_object)
        ->get_elf_header()
        ->elf_phnum;
}

zktypes::u16_t zkelf::ZkElf::get_elf_shdr_entry_size(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return elf->get_elf_header()->elf_shentsize;
    }
    return std::get_if<ElfObj<x86>>(&elf_object)
        ->get_elf_header()
        ->elf_shentsize;
}

zktypes::u16_t zkelf::ZkElf::get_elf_shdr_entry_count(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return elf->get_elf_header()->elf_shnum;
    }
    return std::get_if<ElfObj<x86>>(&elf_object)
        ->get_elf_header()
        ->elf_shnum;
}

zktypes::u16_t zkelf::ZkElf::get_elf_shdr_string_table_index(void) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return elf->get_elf_header()->elf_shstrndx;
    }
    return std::get_if<ElfObj<x86>>(&elf_object)
        ->get_elf_header()
        ->elf_shstrndx;
}

zktypes::u32_t zkelf::ZkElf::get_section_name_index(int shdr_index) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return elf->get_section_header_table()[shdr_index].sh_name;
    }
    return std::get_if<ElfObj<x86>>(&elf_object)
        ->get_section_header_table()[shdr_index]
        .sh_name;
}

zkelf::s_type zkelf::ZkElf::get_section_type(int shdr_index) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return elf->get_section_header_table()[shdr_index].sh_type;
    }
    return std::get_if<ElfObj<x86>>(&elf_object)
        ->get_section_header_table()[shdr_index]
        .sh_type;
}

zktypes::u64_t zkelf::ZkElf::get_section_flags(int shdr_index) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return elf->get_section_header_table()[shdr_index].sh_flags;
    }
    return std::get_if<ElfObj<x86>>(&elf_object)
        ->get_section_header_table()[shdr_index]
        .sh_flags;
}

zktypes::u64_t zkelf::ZkElf::get_section_address(int shdr_index) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return elf->get_section_header_table()[shdr_index].sh_addr;
    }
    return std::get_if<ElfObj<x86>>(&elf_object)
        ->get_section_header_table()[shdr_index]
        .sh_addr;
}

zktypes::u64_t zkelf::ZkElf::get_section_offset(int shdr_index) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return elf->get_section_header_table()[shdr_index].sh_offset;
    }
    return std::get_if<ElfObj<x86>>(&elf_object)
        ->get_section_header_table()[shdr_index]
        .sh_offset;
}

zktypes::u64_t zkelf::ZkElf::get_section_size(int shdr_index) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return elf->get_section_header_table()[shdr_index].sh_size;
    }
    return std::get_if<ElfObj<x86>>(&elf_object)
        ->get_section_header_table()[shdr_index]
        .sh_size;
}

zktypes::u64_t zkelf::ZkElf::get_section_address_alignment(
    int shdr_index) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return elf->get_section_header_table()[shdr_index].sh_addralign;
    }
    return std::get_if<ElfObj<x86>>(&elf_object)
        ->get_section_header_table()[shdr_index]
        .sh_addralign;
}

zktypes::u64_t zkelf::ZkElf::get_section_entry_size(int shdr_index) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return elf->get_section_header_table()[shdr_index].sh_entsize;
    }
    return std::get_if<ElfObj<x86>>(&elf_object)
        ->get_section_header_table()[shdr_index]
        .sh_entsize;
}

zktypes::u32_t zkelf::ZkElf::get_section_link(int shdr_index) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return elf->get_section_header_table()[shdr_index].sh_link;
    }
    return std::get_if<ElfObj<x86>>(&elf_object)
        ->get_section_header_table()[shdr_index]
        .sh_link;
}

zktypes::u32_t zkelf::ZkElf::get_section_info(int shdr_index) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return elf->get_section_header_table()[shdr_index].sh_info;
    }
    return std::get_if<ElfObj<x86>>(&elf_object)
        ->get_section_header_table()[shdr_index]
        .sh_info;
}

zkelf::p_type zkelf::ZkElf::get_segment_type(int phdr_index) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return elf->get_program_header_table()[phdr_index].ph_type;
    }
    return std::get_if<ElfObj<x86>>(&elf_object)
        ->get_program_header_table()[phdr_index]
        .ph_type;
}

zktypes::u64_t zkelf::ZkElf::get_segment_offset(int phdr_index) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return elf->get_program_header_table()[phdr_index].ph_offset;
    }
    return std::get_if<ElfObj<x86>>(&elf_object)
        ->get_program_header_table()[phdr_index]
        .ph_offset;
}

zktypes::u64_t zkelf::ZkElf::get_segment_vaddress(int phdr_index) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return elf->get_program_header_table()[phdr_index].ph_vaddr;
    }
    return std::get_if<ElfObj<x86>>(&elf_object)
        ->get_program_header_table()[phdr_index]
        .ph_vaddr;
}

zktypes::u64_t zkelf::ZkElf::get_segment_paddress(int phdr_index) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return elf->get_program_header_table()[phdr_index].ph_paddr;
    }
    return std::get_if<ElfObj<x86>>(&elf_object)
        ->get_program_header_table()[phdr_index]
        .ph_paddr;
}

zktypes::u32_t zkelf::ZkElf::get_segment_flags(int phdr_index) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return elf->get_program_header_table()[phdr_index].ph_flags;
    }
    return std::get_if<ElfObj<x86>>(&elf_object)
        ->get_program_header_table()[phdr_index]
        .ph_flags;
}

zktypes::u64_t zkelf::ZkElf::get_segment_file_size(int phdr_index) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return elf->get_program_header_table()[phdr_index].ph_filesz;
    }
    return std::get_if<ElfObj<x86>>(&elf_object)
        ->get_program_header_table()[phdr_index]
        .ph_filesz;
}

zktypes::u64_t zkelf::ZkElf::get_segment_memory_size(
    int phdr_index) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return elf->get_program_header_table()[phdr_index].ph_memsz;
    }
    return std::get_if<ElfObj<x86>>(&elf_object)
        ->get_program_header_table()[phdr_index]
        .ph_memsz;
}

zktypes::u64_t zkelf::ZkElf::get_segment_address_alignment(
    int phdr_index) const {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        return elf->get_program_header_table()[phdr_index].ph_align;
    }
    return std::get_if<ElfObj<x86>>(&elf_object)
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
    return std::visit(compare_section_names, elf_object);
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
    return std::visit(compare_section_attributes, elf_object);
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
    return std::visit(compare_segment_attributes, elf_object);
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
    return std::visit(compare_symbol_name, elf_object);
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
    return std::visit(compare_symbol_name, elf_object);
}

// setters
void zkelf::ZkElf::set_elf_type(e_type new_type) {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        elf->get_elf_header()->elf_type = new_type;
    } else if (auto elf = std::get_if<ElfObj<x86>>(&elf_object)) {
        elf->get_elf_header()->elf_type = new_type;
    }
    CHECKFLAGS_AND_SAVE
}

void zkelf::ZkElf::set_elf_machine(e_machine new_machine) {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        elf->get_elf_header()->elf_machine = new_machine;
    } else if (auto elf = std::get_if<ElfObj<x86>>(&elf_object)) {
        elf->get_elf_header()->elf_machine = new_machine;
    }
    CHECKFLAGS_AND_SAVE
}

void zkelf::ZkElf::set_elf_version(e_version new_version) {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        elf->get_elf_header()->elf_version = new_version;
    } else if (auto elf = std::get_if<ElfObj<x86>>(&elf_object)) {
        elf->get_elf_header()->elf_version = new_version;
    }
    CHECKFLAGS_AND_SAVE
}

void zkelf::ZkElf::set_elf_flags(zktypes::u32_t new_flags) {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        elf->get_elf_header()->elf_flags = new_flags;
    } else if (auto elf = std::get_if<ElfObj<x86>>(&elf_object)) {
        elf->get_elf_header()->elf_flags = new_flags;
    }
    CHECKFLAGS_AND_SAVE
}

void zkelf::ZkElf::set_elf_phdr_entry_count(zktypes::u16_t new_count) {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        elf->get_elf_header()->elf_phnum = new_count;
    } else if (auto elf = std::get_if<ElfObj<x86>>(&elf_object)) {
        elf->get_elf_header()->elf_phnum = new_count;
    }
    CHECKFLAGS_AND_SAVE
}

void zkelf::ZkElf::set_elf_shdr_entry_count(zktypes::u16_t new_count) {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        elf->get_elf_header()->elf_shnum = new_count;
    } else if (auto elf = std::get_if<ElfObj<x86>>(&elf_object)) {
        elf->get_elf_header()->elf_shnum = new_count;
    }
    CHECKFLAGS_AND_SAVE
}

void zkelf::ZkElf::set_elf_shdr_string_table_index(
    zktypes::u16_t new_index) {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        elf->get_elf_header()->elf_shstrndx = new_index;
    } else if (auto elf = std::get_if<ElfObj<x86>>(&elf_object)) {
        elf->get_elf_header()->elf_shstrndx = new_index;
    }
    CHECKFLAGS_AND_SAVE
}

void zkelf::ZkElf::set_section_name_index(int shdr_index,
                                          zktypes::u32_t new_index) {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        elf->get_section_header_table()[shdr_index].sh_name = new_index;
    } else {
        elf->get_section_header_table()[shdr_index].sh_name = new_index;
    }
    CHECKFLAGS_AND_SAVE
}

void zkelf::ZkElf::set_section_type(int shdr_index, s_type new_type) {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        elf->get_section_header_table()[shdr_index].sh_type = new_type;
    } else {
        elf->get_section_header_table()[shdr_index].sh_type = new_type;
    }
    CHECKFLAGS_AND_SAVE
}

void zkelf::ZkElf::set_section_link(int shdr_index,
                                    zktypes::u32_t new_link) {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        elf->get_section_header_table()[shdr_index].sh_link = new_link;
    } else {
        elf->get_section_header_table()[shdr_index].sh_link = new_link;
    }
    CHECKFLAGS_AND_SAVE
}

void zkelf::ZkElf::set_section_info(int shdr_index,
                                    zktypes::u32_t new_info) {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        elf->get_section_header_table()[shdr_index].sh_info = new_info;
    } else {
        elf->get_section_header_table()[shdr_index].sh_info = new_info;
    }
    CHECKFLAGS_AND_SAVE
}

void zkelf::ZkElf::set_segment_type(int phdr_index, p_type new_type) {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        elf->get_program_header_table()[phdr_index].ph_type = new_type;
    } else {
        elf->get_program_header_table()[phdr_index].ph_type = new_type;
    }
    CHECKFLAGS_AND_SAVE
}

void zkelf::ZkElf::set_segment_flags(int phdr_index,
                                     zktypes::u32_t new_flags) {
    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
        elf->get_program_header_table()[phdr_index].ph_flags = new_flags;
    } else {
        elf->get_program_header_table()[phdr_index].ph_flags = new_flags;
    }
    CHECKFLAGS_AND_SAVE
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
    auto p = std::visit(e_read, elf_object);
    CHECKFLAGS_AND_SAVE
    return p;
}

void zkelf::ZkElf::elf_write(void *buffer, off_t write_offset,
                             size_t size) const noexcept {
    auto e_write = [&buffer, &write_offset, &size](const auto &elf) {
        zktypes::u8_t *map = (zktypes::u8_t *)elf.get_memory_map();
        zktypes::u8_t *src = (zktypes::u8_t *)buffer;
        for (int i = 0; i < write_offset + size; i++) {
            src[i] = map[i];
        }
    };
    std::visit(e_write, elf_object);
    CHECKFLAGS_AND_SAVE
}

struct save {
    void *memory_map = nullptr;
    std::size_t size = 0;

    save(void *m, std::size_t s) : memory_map(m), size(s) {}

    void operator()(const char *path) {
        remove(path);
        zkutils::save_memory_map(path, memory_map, size);
    }
    void operator()(pid_t pid) {
        // TODO write to a running process somehow lol
        // options available :
        // use zkptrace::write_process -- requires zkptrace instance
    }
};

template <class... Ts>
struct overload : Ts... {
    using Ts::operator()...;
};
template <class... Ts>
overload(Ts...) -> overload<Ts...>;

void zkelf::ZkElf::save_source() const noexcept {
    if (auto elf = std::get_if<zkelf::ElfObj<x64>>(&elf_object)) {
        std::visit(save{elf->get_memory_map(), elf->get_map_size()},
                   elf->get_elf_source());
    } else {
        std::visit(save{elf->get_memory_map(), elf->get_map_size()},
                   elf->get_elf_source());
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

    if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
    } else if (auto elf = std::get_if<ElfObj<x86>>(&elf_object)) {
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
