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
//#include "zksnapshot.hh"
#include "zksignal.hh"

namespace zkprocess {

// this class defines everything that a process owns
class ZkProcess {
public:
private:
public:	
    ZkProcess();
    std::shared_ptr<zkelf::ZkElf> p_elf;
    std::variant<Ptrace<x64>, Ptrace<x86>> p_ptrace;
    std::variant<MemoryMap<x64>, MemoryMap<x86>> p_memory_map;
	std::variant<Snapshot<x64>, Snapshot<x86>> p_snapshot;
    
    void parse_memory_map(void) {
        if (auto mm = std::get_if<MemoryMap<x64>>(&p_memory_map)) {
            mm->parse_memory_map();
        } else if (auto mm = std::get_if<MemoryMap<x86>>(&p_memory_map)) {
            mm->parse_memory_map();
        }
    }

    zkelf::ZkElf* get_elf(void) const {
        return p_elf.get();
    }

    zkelf::ei_class get_process_arch(void) const {
        return p_elf->get_elf_class();
    }

// TODO do not return consts 
    const Ptrace<x64>* get_ptrace_if_x64(void) const {
        return std::get_if<Ptrace<x64>>(&p_ptrace);
    }

    const Ptrace<x86>* get_ptrace_if_x86(void) const {
        return std::get_if<Ptrace<x86>>(&p_ptrace);
    }

    const MemoryMap<x64>* get_memory_map_if_x64(void) const {
        return std::get_if<MemoryMap<x64>>(&p_memory_map);
    }

    const MemoryMap<x86>* get_memory_map_if_x86(void) const {
        auto mm = std::get_if<MemoryMap<x86>>(&p_memory_map);
    }

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
        return std::get_if<MemoryMap<x86>>(&p_memory_map)->get_module_page(module_name);
    }
*/

    friend std::shared_ptr<ZkProcess> load_process_from_file(
        char* const* path);
};

std::shared_ptr<ZkProcess> load_process_from_file(
    char* const* path, std::optional<zklog::ZkLog *> log);
}  // namespace zkprocess

#endif  // ZKPROCESS_HH
