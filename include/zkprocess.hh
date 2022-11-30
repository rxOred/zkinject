#ifndef ZKPROCESS_HH
#define ZKPROCESS_HH

#include <memory>
#include <optional>
#include <variant>

#include "zkelf.hh"
#include "zklog.hh"
#include "zkmemorymap.hh"
#include "zkptrace.hh"
#include "zksnapshot.hh"
#include "zktypes.hh"
// #include "zksnapshot.hh"
#include "zksignal.hh"

namespace zkprocess {

// this class defines everything that a process owns
class ZkProcess {
public:
private:
public:
    ZkProcess(std::shared_ptr<zkelf::ZkElf> elf,
              std::variant<std::shared_ptr<Ptrace<x64>>,
                           std::shared_ptr<Ptrace<x86>>>
                  p,
              std::variant<std::shared_ptr<MemoryMap<x64>>,
                           std::shared_ptr<MemoryMap<x86>>>
                  mm);
    std::shared_ptr<zkelf::ZkElf> p_elf;
    std::variant<std::shared_ptr<Ptrace<x64>>,
                 std::shared_ptr<Ptrace<x86>>>
        p_ptrace;
    std::variant<std::shared_ptr<MemoryMap<x64>>,
                 std::shared_ptr<MemoryMap<x86>>>
        p_memory_map;
    // std::variant<Snapshot<x64>, Snapshot<x86>> p_snapshot;

    void parse_memory_map() {
        if (auto mm = std::get_if<std::shared_ptr<MemoryMap<x64>>>(
                &p_memory_map)) {
            mm->get()->parse_memory_map();
        } else if (auto mm = std::get_if<std::shared_ptr<MemoryMap<x86>>>(
                       &p_memory_map)) {
            mm->get()->parse_memory_map();
        }
    }

    [[nodiscard]] zkelf::ZkElf* get_elf() const { return p_elf.get(); }

    [[nodiscard]] zkelf::ei_class get_process_arch() const {
        return p_elf->get_elf_class();
    }

    [[nodiscard]] Ptrace<x64>* get_ptrace_if_x64() const {
        if (auto p =
                std::get_if<std::shared_ptr<Ptrace<x64>>>(&p_ptrace)) {
            return p->get();
        } else {
            return nullptr;
        }
    }

    [[nodiscard]] Ptrace<x86>* get_ptrace_if_x86() const {
        if (auto p =
                std::get_if<std::shared_ptr<Ptrace<x86>>>(&p_ptrace)) {
            return p->get();
        } else {
            return nullptr;
        }
    }

    [[nodiscard]] MemoryMap<x64>* get_memory_map_if_x64() const {
        if (auto m = std::get_if<std::shared_ptr<MemoryMap<x64>>>(
                &p_memory_map)) {
            puts("is 64");
            return m->get();
        } else {
            return nullptr;
        }
    }

    [[nodiscard]] MemoryMap<x86>* get_memory_map_if_x86() const {
        if (auto m = std::get_if<std::shared_ptr<MemoryMap<x86>>>(
                &p_memory_map)) {
            puts("is 86");
            return m->get();
        } else {
            return nullptr;
        }
    }
    /*
        const Snapshot<x64>* get_snapshot_if_x64(void) const {
            return std::get_if<Snapshot<x64>>(&p_snapshot);
        }

        const Snapshot<x86>* get_snapshot_if_x86(void) const {
            return std::get_if<Snapshot<x86>>(&p_snapshot);
        }
    /*
    TODO
        auto get_module_page(const char * module_name) const {
            if (auto mm = std::get_if<MemoryMap<x64>>(&p_memory_map)) {
                return mm->get_module_page(module_name);
            }
            return
    std::get_if<MemoryMap<x86>>(&p_memory_map)->get_module_page(module_name);
        }
    */

    friend std::shared_ptr<ZkProcess> load_process_from_file(
        char* const* path, std::optional<zklog::ZkLog*> log);
};

std::shared_ptr<ZkProcess> load_process_from_file(
    char* const* path, std::optional<zklog::ZkLog*> log);
}  // namespace zkprocess

#endif  // ZKPROCESS_HH
