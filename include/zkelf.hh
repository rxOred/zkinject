#ifndef ZKELF_HH
#define ZKELF_HH

#include <assert.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <type_traits>
#include <variant>

#include "zkexcept.hh"
#include "zklog.hh"
#include "zktypes.hh"
#include "zkutils.hh"

#define CHECKFLAGS_AND_SAVE                                               \
    if (auto p = std::get_if<zkelf::elf_read_write>(&elf_file_options)) { \
        if (ZK_CHECK_FLAGS(                                               \
                static_cast<zktypes::u8_t>(                               \
                    zkelf::elf_save_options::ELF_AUTO_SAVE),              \
                static_cast<zktypes::u8_t>(p->save_options))) {           \
            save_source();                                                \
            if (elf_log.has_value()) {                                    \
                elf_log.value()->push_log(                                \
                    "auto saving...", zklog::log_level::LOG_LEVEL_DEBUG); \
            }                                                             \
        }                                                                 \
    } else {                                                              \
        if (elf_log.has_value()) {                                        \
            elf_log.value()->push_log(                                    \
                "changes will not be reflected in the file",              \
                zklog::log_level::LOG_LEVEL_DEBUG);                       \
        }                                                                 \
    }

namespace zkelf {

// architecture of the elf
enum class ei_class : zktypes::u8_t {
    ELFCLASSNONE = 0,
    ELFCLASS32 = 1,  // 32 bit
    ELFCLASS64 = 2   // 64 bit
};

// data encoding of processor-specific data in the elf
enum class ei_data : zktypes::u8_t {
    ELFDATANONE = 0,
    ELFDATA2LSB,  // little endian
    ELFDATA2MSB   // big endian
};

// operating system and abi which the elf is targeted
enum class ei_osabi : zktypes::u8_t {
    ELFOSABI_NONE = 0,
    ELFOSABI_SYSV = 0,
    ELFOSABI_HPUX,
    ELFOSABI_NETBSD,
    ELFOSABI_GNU,
    ELFOSABI_LINUX = ELFOSABI_GNU,
    ELFOSABI_SOLARIS = 6,
    ELFOSABI_AIX,
    ELFOSABI_IRIX,
    ELFOSABI_FREEBSD,
    ELFOSABI_TRU64,
    ELFOSABI_MODESTO,
    ELFOSABI_OPENBSD,
    ELFOSABI_ARM_AEABI = 64,
    ELFOSABI_ARM = 97,
    ELFOSABI_STANDALONE = 255
};

// first 16 bytes of the elf
enum class e_ident : zktypes::u8_t {
    EI_MAG0 = 0,
    EI_MAG1,
    EI_MAG2,
    EI_MAG3,
    EI_CLASS,
    EI_DATA,
    EI_VERSION,
    EI_OSABI,
    EI_ABIVERSION,
    EI_PAD
    // padding of 7 bytes
};

// type of the elf binary
enum class e_type : zktypes::u16_t {
    ET_NONE = 0,
    ET_REL,
    ET_EXEC,
    ET_DYN,
    ET_CORE,
    ET_NUM,
    ET_LOOS = 0xfe00,
    ET_HIOS = 0xfeff,
    ET_LOPROC = 0xff00,
    ET_HIPROC = 0xffff
};

// architecture of the elf in detail
enum class e_machine : zktypes::u16_t {
    EM_NONE = 0,         /* No machine */
    EM_M32,              /* AT&T WE 32100 */
    EM_SPARC,            /* SUN SPARC */
    EM_386,              /* Intel 80386 */
    EM_68K,              /* Motorola m68k family */
    EM_88K,              /* Motorola m88k family */
    EM_860 = 7,          /* Intel 80860 */
    EM_MIPS,             /* MIPS R3000 big-endian */
    EM_PARISC = 15,      /* HPPA */
    EM_SPARC32PLUS = 18, /* Sun's "v8plus" */
    EM_PPC = 20,         // PowerPC */
    EM_PPC64,            // PowerPC 64-bit */
    EM_S390,             // IBM s390
    EM_ARM = 40,         // ARM
    EM_SPARCV9 = 43,     // SPARC v9 64 bit
    EM_IA_64 = 50,       // Intel Merced */
    EM_X86_64 = 62,      // AMD x86-64 architecture
    EM_AVR = 83,         // Atmel AVR 8-bit microcontroller
    EM_BPF = 247
};

enum class e_version : zktypes::u32_t { EV_NONE = 0, EV_CURRENT, EV_NUM };

// elf header
template <typename T = x64>
struct ehdr_t {
    typename T::u8_t e_ident[16];
    e_type elf_type;
    e_machine elf_machine;
    e_version elf_version;
    typename T::addr_t elf_entry;
    typename T::off_t elf_phoff;
    typename T::off_t elf_shoff;
    typename T::u32_t elf_flags;
    typename T::u16_t elf_ehsize;
    typename T::u16_t elf_phentsize;
    typename T::u16_t elf_phnum;
    typename T::u16_t elf_shentsize;
    typename T::u16_t elf_shnum;
    typename T::u16_t elf_shstrndx;
};

// type of the segment
enum class p_type : zktypes::u32_t {
    PT_NULL = 0,
    PT_LOAD,
    PT_DYNAMIC,
    PT_INTERP,
    PT_NOTE,
    PT_SHLIB,
    PT_PHDR,
    PT_LOPROC,
    PT_HIPROC,
    PT_GNU_STACK,
};

// permissions of the segment
enum class p_flags : zktypes::u32_t { PF_X, PF_W, PF_R };

// program header
template <typename T = x64>
struct phdr_t;

// program header x64
template <>
struct phdr_t<x64> {
    p_type ph_type;
    x64::u32_t ph_flags;
    x64::off_t ph_offset;
    x64::addr_t ph_vaddr;
    x64::addr_t ph_paddr;
    x64::u64_t ph_filesz;
    x64::u64_t ph_memsz;
    x64::u64_t ph_align;
};

// program header x86
template <>
struct phdr_t<x86> {
    p_type ph_type;
    x86::off_t ph_offset;
    x86::addr_t ph_vaddr;
    x86::addr_t ph_paddr;
    x86::u32_t ph_filesz;
    x86::u32_t ph_memsz;
    x86::u32_t ph_flags;
    x86::u32_t ph_align;
};

enum class sh_n : zktypes::u16_t {
    SHN_UNDEF = 0,
    SHN_LORESERVE = 0xff00,
    SHN_LOPROC = 0xff00,
    SHN_BEFORE = 0xff00,
    SHN_AFTER = 0xff01,
    SHN_HIPROC = 0xff1f,
    SHN_LOOS = 0xff20,
    SHN_HIOS = 0xff3f,
    SHN_ABS = 0xfff1,
    SHN_COMMON = 0xfff2,
    SHN_XINDEX = 0xffff,
    SHN_HIRESERVE = 0xffff,

};

enum class s_type : zktypes::u32_t {
    SHT_NULL = 0,
    SHT_PROGBITS,
    SHT_SYMTAB,
    SHT_STRTAB,
    SHT_RELA,
    SHT_HASH,
    SHT_DYNAMIC,
    SHT_NOTE,
    SHT_NOBITS,
    SHT_REL,
    SHT_SHLIB,
    SHT_DYNSYM,
    SHT_INIT_ARRAY = 14,
    SHT_FINI_ARRAY,
    SHT_PREINIT_ARRAY,
    SHT_GROUP,
    SHT_SYMTAB_SHNDX,
    SHT_NUM,
    SHT_LOOS = 0x60000000,
    SHT_GNU_ATTRIBUTES = 0x6ffffff5,
    SHT_GNU_HASH = 0x6ffffff6,
    SHT_GNU_LIBLIST = 0x6ffffff7,
    SHT_CHECKSUM = 0x6ffffff8,
    SHT_LOSUNW = 0x6ffffffa,
    SHT_SUNW_move = 0x6ffffffa,
    SHT_SUNW_COMDAT = 0x6ffffffb,
    SHT_SUNW_syminfo = 0x6ffffffc,
    SHT_GNU_verdef = 0x6ffffffd,
    SHT_GNU_verneed = 0x6ffffffe,
    SHT_GNU_versym = 0x6fffffff,
    SHT_HISUNW = 0x6fffffff,
    SHT_HIOS = 0x6fffffff,
    SHT_LOPROC = 0x70000000,
    SHT_HIPROC = 0x7fffffff,
    SHT_LOUSER = 0x80000000,
    SHT_HIUSER = 0x8fffffff,
};

enum class sh_flags : zktypes::u16_t {
    SHF_WRITE = (1 << 0),
    SHF_ALLOC = (1 << 1),
    SHF_EXECINSTR = (1 << 2),
    SHF_MERGE = (1 << 4),
    SHF_STRINGS = (1 << 5),
    SHF_INFO_LINK = (1 << 6),
    SHF_LINK_ORDER = (1 << 7),
    SHF_OS_NONCONFORMING = (1 << 8),
    SHF_GROUP = (1 << 9),
    SHF_TLS = (1 << 10),
    SHF_COMPRESSED = (1 << 11)
};

template <typename T = x64>
struct shdr_t {
    typename T::u32_t sh_name;
    s_type sh_type;
    typename T::addr_t sh_flags;
    typename T::addr_t sh_addr;
    typename T::off_t sh_offset;
    typename T::addr_t sh_size;
    typename T::u32_t sh_link;
    typename T::u32_t sh_info;
    typename T::addr_t sh_addralign;
    typename T::addr_t sh_entsize;
};

using strtab_t = char *;

enum class st_info : zktypes::u8_t {
    STT_NOTYPE = 0,
    STT_OBJECT,
    STT_FUNC,
    STT_SECTION,
    STT_FILE,
    STT_COMMON,
    STT_TLS,
    STT_NUM,
    STT_LOOS = 10,
    STT_GNU_IFUNC = 10,
    STT_HIOS = 12,
    STT_LOPROC,
    STT_HIPROC = 15
};

enum class st_other : zktypes::u8_t {
    STV_DEFAULT = 0,
    STV_INTERNAL,
    STV_HIDDEN,
    STV_PROTECTED,
};

// symbol table
template <typename T = x64>
struct symtab_t;

template <>
struct symtab_t<x64> {
    x64::u32_t st_name;
    x64::u8_t st_info;
    x64::u8_t st_other;
    x64::u16_t st_shndx;
    x64::addr_t st_value;
    x64::u64_t st_size;
};

template <>
struct symtab_t<x86> {
    x86::u32_t st_name;
    x86::addr_t st_value;
    x86::u32_t st_size;
    x86::u8_t st_info;
    x86::u8_t st_other;
    x86::u16_t st_shndx;
};

// there are two relocation structures - rela , rel
// one structure has an addend that should be added when
// calculating relocatable field, `rip relative addressing`
template <typename T = x64, bool have_addend = false>
struct relocation_t;

template <typename T>
struct relocation_t<T, false> {
    // offset where the relocation should be applied
    typename T::addr_t r_offset;
    // symtable index and type of relocation
    typename T::addr_t r_info;
};

template <typename T>
struct relocation_t<T, true> {
    // offset where the relocation should be applied
    typename T::addr_t r_offset;
    // symtable index and type of relocation
    typename T::addr_t r_info;
    // constant addend used to compute relative offset
    typename T::saddr_t r_addend;
};

enum class d_tag : zktypes::u32_t {
    DT_NULL = 0,
    DT_NEEDED,
    DT_PLTRELSZ,
    DT_PLTGOT,
    DT_HASH,
    DT_STRTAB,
    DT_SYMTAB,
    DT_RELA,
    DT_RELASZ,
    DT_RELAENT,
    DT_STRSZ,
    DT_SYMENT,
    DT_INIT,
    DT_FINI,
    DT_SONAME,
    DT_RPATH,
    DT_SYMBOLIC,
    DT_REL,
    DT_RELSZ,
    DT_RELENT,
    DT_PLTREL,
    DT_DEBUG,
    DT_TEXTREL,
    DT_JMPREL,
    DT_BIND_NOW,
    DT_INIT_ARRAY,
    DT_FINI_ARRAY,
    DT_INIT_ARRAYSZ,
    DT_FINI_ARRAYSZ,
    DT_RUNPATH,
    DT_FLAGS,
    DT_ENCODING,
    DT_PREINIT_ARRAY,
    DT_PREINIT_ARRAYSZ,
    DT_SYMTAB_SHNDX,
    DT_NUM,
    DT_LOOS = 0x6000000d,
    DT_HIOS = 0x6ffff000,
    DT_LOPROC = 0x70000000,
    DT_HIPROC = 0x7fffffff
};

template <typename T = x64>
struct dynamic_t {
    typename T::saddr_t d_tag;
    union {
        typename T::addr_t d_val;
        typename T::addr_t d_ptr;
    } d_un;
};

// NOTE enum class for n_type
// this structure is used by the gnu toolchain to pass information to
// the C library. may have some juicy information which can be later used
// for hooking.
//
template <typename T = x64>
struct nhdr_t {
    typename T::u32_t n_namesz;
    typename T::u32_t n_descsz;
    typename T::u32_t n_type;
};

struct elf_core {
    zktypes::u8_t ei_magic[4];
    zktypes::u8_t ei_class;
    zktypes::u8_t reserved[2];
    zktypes::u8_t ei_osabi;
};

// indexes for common elf sections
enum elf_shdr_indexes : short {
    ELF_SYMTAB_INDEX = 0,
    ELF_STRTAB_INDEX,
    ELF_DYNAMIC_INDEX,
    ELF_DYNSYM_INDEX,
    ELF_DYNSTR_INDEX,
    ELF_INDEX_ARRAY_SIZE
};

// internal base class that represent a single elf binary extracted from a
// file or memory map of another process. contains all the internal data
// structures of the elf binary such as header tabls, string tables and
// symbols contains external information such as path/pid, memory map and
// the size only parses basic data structures such as elf header and two
// header tables. derived class should implement code required to parse
// other data if required.
template <typename T = x64>
class ElfObj {
public:
    ElfObj() = delete;
    ElfObj(void *map, std::size_t size,
           std::variant<const char *, pid_t> s);
    ~ElfObj() = default;

    [[nodiscard]] bool is_stripped() const;

    [[nodiscard]] void *get_memory_map() const;
    [[nodiscard]] std::size_t get_map_size() const;
    [[nodiscard]] std::variant<const char *, pid_t> get_elf_source() const;

    [[nodiscard]] ehdr_t<T> *get_elf_header() const;
    [[nodiscard]] phdr_t<T> *get_program_header_table() const;
    [[nodiscard]] shdr_t<T> *get_section_header_table() const;

    [[nodiscard]] strtab_t get_section_header_string_table() const;
    [[nodiscard]] strtab_t get_string_table() const;
    [[nodiscard]] strtab_t get_dynamic_string_table() const;
    [[nodiscard]] symtab_t<T> *get_symbol_table() const;
    [[nodiscard]] symtab_t<T> *get_dynamic_symbol_table() const;
    [[nodiscard]] dynamic_t<T> *get_dynamic_section() const;
    [[nodiscard]] nhdr_t<T> *get_note_section() const;
    decltype(auto) get_section_index_array();

    void set_stripped(bool b);
    void set_elf_header(void *new_ehdr);
    void set_section_header_table(void *new_shdr);
    void set_program_header_table(void *new_phdr);

    void set_section_header_string_table(void *new_tab);
    void set_string_table(void *new_tab);
    void set_dynamic_string_table(void *new_tab);
    void set_symbol_table(void *new_tab);
    void set_dynamic_symbol_table(void *new_tab);
    void set_dynamic_section(void *new_dyn);
    void set_note_section(void *new_note);

private:
    // essential sections of an elf binary
    ehdr_t<T> *e_ehdr = nullptr;
    phdr_t<T> *e_phdrtab = nullptr;
    shdr_t<T> *e_shdrtab = nullptr;

    // below sections can be stripped off from the elf
    // if shstrtab cannot be parsed, binary is stripped
    strtab_t e_shstrtab = nullptr;
    strtab_t e_strtab = nullptr;
    strtab_t e_dynstr = nullptr;
    symtab_t<T> *e_symtab = nullptr;
    symtab_t<T> *e_dynsym = nullptr;
    dynamic_t<T> *e_dynamic = nullptr;
    nhdr_t<T> *e_nhdr = nullptr;

    bool e_is_stripped = false;
    void *e_memory_map;  // NOTE not the process memory map, just the
                         // buffer that holds the elf file
    std::size_t e_map_size;
    std::variant<const char *, pid_t> e_source;
    std::array<zktypes::u8_t, ELF_INDEX_ARRAY_SIZE> e_section_indexes;
};

struct elf_read_only {};

enum class elf_save_options : zktypes::u8_t {
    ELF_AUTO_SAVE = 1,
    ELF_SAVE_AT_EXIT,
    ELF_NO_SAVE,
};

struct elf_read_write {
    elf_save_options save_options;
};

enum class elf_options : zktypes::u8_t {
    ELF_AUTO_SAVE = 1,
    ELF_SAVE_AT_EXIT,
    ELF_NO_SAVE
};

// a more generalized interface to interact with ElfObj. provides
// functionality to load sections and segment which are not parsed by
// ElfObj by default
class ZkElf {
public:
    ZkElf(std::variant<ElfObj<x64>, ElfObj<x86>> obj,
          std::variant<elf_read_only, elf_read_write> options =
              elf_read_only{},
          std::optional<zklog::ZkLog *> log = std::nullopt);
    ZkElf(const ZkElf &) = delete;
    ZkElf(ZkElf &&) = delete;

    ~ZkElf() {
        if (auto p = std::get_if<elf_read_write>(&elf_file_options)) {
            if (p->save_options == elf_save_options::ELF_SAVE_AT_EXIT) {
                save_source();
            }
        }
    }

    // internals
    bool load_dynamic_data();
    bool load_symbol_data();

    // we can return void *
    [[nodiscard]] void *get_memory_map() const;
    [[nodiscard]] std::size_t get_map_size() const;
    [[nodiscard]] bool is_stripped() const;

    [[nodiscard]] ei_class get_elf_class() const;
    [[nodiscard]] ei_data get_elf_encoding() const;
    [[nodiscard]] ei_osabi get_elf_osabi() const;
    [[nodiscard]] e_type get_elf_type() const;
    [[nodiscard]] e_machine get_elf_machine() const;
    [[nodiscard]] e_version get_elf_version() const;
    [[nodiscard]] zktypes::u64_t get_elf_entry_point() const;
    [[nodiscard]] zktypes::u64_t get_elf_phdr_offset() const;
    [[nodiscard]] zktypes::u64_t get_elf_shdr_offset() const;
    [[nodiscard]] zktypes::u32_t get_elf_flags() const;
    [[nodiscard]] zktypes::u16_t get_elf_header_size() const;
    [[nodiscard]] zktypes::u16_t get_elf_phdr_entry_size() const;
    [[nodiscard]] zktypes::u16_t get_elf_phdr_entry_count() const;
    [[nodiscard]] zktypes::u16_t get_elf_shdr_entry_size() const;
    [[nodiscard]] zktypes::u16_t get_elf_shdr_entry_count() const;
    [[nodiscard]] zktypes::u16_t get_elf_shdr_string_table_index() const;

    [[nodiscard]] zktypes::u32_t get_section_name_index(
        int shdr_index) const;
    [[nodiscard]] s_type get_section_type(int shdr_index) const;
    [[nodiscard]] zktypes::u64_t get_section_flags(int shdr_index) const;
    [[nodiscard]] zktypes::u64_t get_section_address(int shdr_index) const;
    [[nodiscard]] zktypes::u64_t get_section_offset(int shdr_index) const;
    [[nodiscard]] zktypes::u64_t get_section_size(int shdr_index) const;
    [[nodiscard]] zktypes::u64_t get_section_address_alignment(
        int shdr_index) const;
    [[nodiscard]] zktypes::u64_t get_section_entry_size(
        int shdr_index) const;
    [[nodiscard]] zktypes::u32_t get_section_link(int shdr_index) const;
    [[nodiscard]] zktypes::u32_t get_section_info(int shdr_index) const;

    [[nodiscard]] p_type get_segment_type(int phdr_index) const;
    [[nodiscard]] zktypes::u64_t get_segment_offset(int phdr_index) const;
    [[nodiscard]] zktypes::u64_t get_segment_vaddress(
        int phdr_index) const;
    [[nodiscard]] zktypes::u64_t get_segment_paddress(
        int phdr_index) const;
    [[nodiscard]] zktypes::u32_t get_segment_flags(int phdr_index) const;
    [[nodiscard]] zktypes::u64_t get_segment_file_size(
        int phdr_index) const;
    [[nodiscard]] zktypes::u64_t get_segment_memory_size(
        int phdr_index) const;
    [[nodiscard]] zktypes::u64_t get_segment_address_alignment(
        int phdr_index) const;

    int get_section_index_by_name(const char *section_name);
    int get_section_index_by_attr(s_type type, zktypes::u16_t flags);
    int get_segment_index_by_attr(p_type type, zktypes::u32_t flags);
    int get_symbol_index_by_name(const char *symbol_name);
    int get_dynamic_symbol_index_by_name(const char *symbol_name);

    // TODO get symbol and note table stub
    // TODO get headers

    // setters

    // TODO void set_elf_size(std::size_t new_size);
    void set_stripped();
    void set_elf_type(e_type new_type);
    void set_elf_machine(e_machine new_machine);
    void set_elf_version(e_version new_version);
    void set_elf_flags(zktypes::u32_t new_flags);

    template <typename T = x64::addr_t>
    void set_elf_entry_point(T new_entry) {
        static_assert(std::is_integral_v<T>,
                      "new entry should be an integer");
        if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
            elf->get_elf_header()->elf_entry = new_entry;
        } else {
            elf->get_elf_header()->elf_entry = new_entry;
        }
        CHECKFLAGS_AND_SAVE
    }

    template <typename T = x64::off_t>
    void set_elf_phdr_offset(T new_offset) {
        static_assert(std::is_integral_v<T>,
                      "new ph offset should be an integral");
        if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
            elf->get_elf_header()->elf_phoff = new_offset;
        } else {
            elf->get_elf_header()->elf_phoff = new_offset;
        }
        CHECKFLAGS_AND_SAVE
    }

    template <typename T = x64::off_t>
    void set_elf_shdr_offset(T new_offset) {
        static_assert(std::is_integral_v<T>,
                      "new sh offset should be an integral");
        if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
            elf->get_elf_header()->elf_shoff = new_offset;
        } else {
            elf->get_elf_header()->elf_shoff = new_offset;
        }
        CHECKFLAGS_AND_SAVE
    }
    void set_elf_phdr_entry_count(zktypes::u16_t new_count);
    void set_elf_shdr_entry_count(zktypes::u16_t new_count);
    void set_elf_shdr_string_table_index(zktypes::u16_t new_index);

    void set_elf_header(void *new_ehdr) {
        if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
            elf->set_elf_header(new_ehdr);
        } else {
            elf->set_elf_header(new_ehdr);
        }
        CHECKFLAGS_AND_SAVE
    }

    void set_section_name_index(int shdr_index, zktypes::u32_t new_index);
    void set_section_type(int shdr_index, s_type new_type);

    template <typename T = x64::addr_t>
    void set_section_address(int shdr_index, T new_addr) {
        static_assert(std::is_integral_v<T>,
                      "new section address should be an integral");
        if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
            elf->get_section_header_table()[shdr_index].sh_addr = new_addr;
            new_addr;
        } else {
            elf->get_section_header_table()[shdr_index].sh_addr = new_addr;
            new_addr;
        }
        CHECKFLAGS_AND_SAVE
    }
    template <typename T = x64::off_t>
    void set_section_offset(int shdr_index, T new_offset) {
        static_assert(std::is_integral_v<T>,
                      "new section offset should be an integral");
        if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
            elf->get_section_header_table()[shdr_index].sh_offset =
                new_offset;
        } else {
            elf->get_section_header_table()[shdr_index].sh_offset =
                new_offset;
        }
        CHECKFLAGS_AND_SAVE
    }

    template <typename T = x64::addr_t>
    void set_section_size(int shdr_index, T new_size) {
        static_assert(std::is_integral_v<T>,
                      "new section size should be an integral");
        if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
            elf->get_section_header_table()[shdr_index].sh_size = new_size;
        } else {
            elf->get_section_header_table()[shdr_index].sh_size = new_size;
        }
        CHECKFLAGS_AND_SAVE
    }

    template <typename T = x64::addr_t>
    void set_section_address_alignment(int shdr_index, T new_addralign) {
        static_assert(std::is_integral_v<T>,
                      "new ph offset should be an integral");
        if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
            elf->get_section_header_table()[shdr_index].sh_addralign =
                new_addralign;
        } else {
            elf->get_section_header_table()[shdr_index].sh_addralign =
                new_addralign;
        }
        CHECKFLAGS_AND_SAVE
    }

    void set_section_link(int shdr_index, zktypes::u32_t new_link);
    void set_section_info(int shdr_index, zktypes::u32_t new_info);

    template <typename T,
              std::enable_if_t<std::is_same<shdr_t<x64>, T>::value ||
                                   std::is_same<shdr_t<x86>, T>::value,
                               bool> = true>
    void set_section_header_table(T *new_shdr) {
        if constexpr (std::is_same_v<T, shdr_t<x64>>) {
            std::get_if<ElfObj<x64>>(&elf_object)
                ->set_section_header_table(new_shdr);
        } else if constexpr (std::is_same_v<T, shdr_t<x86>>) {
            std::get_if<ElfObj<x86>>(&elf_object)
                ->set_section_header_table(new_shdr);
        }
        CHECKFLAGS_AND_SAVE
    }

    // TODO
    template <typename T = shdr_t<x64> *>
    void set_section_header(int shdr_index, T new_shdr) {}

    void set_section_data(int shdr_index, void *data);

    void set_segment_type(int phdr_index, p_type new_type);

    template <typename T = x64::off_t>
    void set_segment_offset(int phdr_index, T new_offset) {
        static_assert(std::is_integral_v<T>,
                      "new segment offset should be an integral");
        if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
            elf->get_program_header_table()[phdr_index].ph_offset =
                new_offset;
        } else {
            elf->get_program_header_table()[phdr_index].ph_offset =
                new_offset;
        }
        CHECKFLAGS_AND_SAVE
    }

    template <typename T = x64::addr_t>
    void set_segment_vaddress(int phdr_index, T new_address) {
        static_assert(std::is_integral_v<T>,
                      "new ph offset should be an integral");
        if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
            elf->get_program_header_table()[phdr_index].ph_vaddr =
                new_address;
        } else {
            elf->get_program_header_table()[phdr_index].ph_vaddr =
                new_address;
        }
        CHECKFLAGS_AND_SAVE
    }
 
    template <typename T = x64::addr_t>
    void set_segment_paddress(int phdr_index, T new_address) {
        static_assert(std::is_integral_v<T>,
                      "new segment address should be an integral");
        if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
            elf->get_program_header_table()[phdr_index].ph_paddr =
                new_address;
        } else {
            elf->get_program_header_table()[phdr_index].ph_paddr =
                new_address;
        }
		CHECKFLAGS_AND_SAVE
    }

    void set_segment_flags(int phdr_index, zktypes::u32_t new_flags);
    void set_segment_file_size(int phdr_index, uint new_filesz);
    void set_segment_memory_size(int phdr_index, uint new_memsz); 
    void set_segment_alignment(int phdr_index, uint new_alignment);
		
	template <typename T,
			  std::enable_if_t<std::is_same<phdr_t<x64>, T>::value ||
							   std::is_same<phdr_t<x86>, T>::value, bool> = true>
    void set_program_header_table(T *new_phdr) {
        if (auto elf = std::get_if<ElfObj<x64>>(&elf_object)) {
            elf->set_program_header_table(new_phdr);
        } else {
            elf->set_program_header_table(new_phdr);
        }
    }

    // TODO
    template <typename T = phdr_t<x64> *>
    void set_program_header(int phdr_index, T new_phdr);
    void set_segment_data(int phdr_index, void *data);

    void *elf_read(off_t read_offset, std::size_t size) const noexcept;
    void elf_write(void *buffer, off_t write_offset,
                   std::size_t size) const noexcept;

    void save_source() const noexcept;

    friend std::shared_ptr<ZkElf> load_elf_from_file(
        const char *path, std::optional<elf_options> options,
        std::optional<zklog::ZkLog *> log);

    friend std::shared_ptr<ZkElf> load_elf_writable_from_file(
        const char *path, std::optional<elf_save_options> save_options,
        std::optional<zklog::ZkLog *> log);

    friend void load_elf_from_memory();

private:
    std::variant<elf_read_only, elf_read_write> elf_file_options;
    std::optional<zklog::ZkLog *> elf_log;
    std::variant<ElfObj<x64>, ElfObj<x86>> elf_object;
};

std::shared_ptr<ZkElf> load_elf_from_file(
    const char *path, std::optional<zklog::ZkLog *> log = std::nullopt);

std::shared_ptr<ZkElf> load_elf_writable_from_file(
    const char *path,
    std::optional<elf_save_options> save_options =
        elf_save_options::ELF_AUTO_SAVE,
    std::optional<zklog::ZkLog *> log = std::nullopt);

void load_elf_from_memory();
};  // namespace zkelf

#endif  // ZKELF_HH
