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

    decltype(auto) memory_map(void) {
        if (auto mm = std::get_if<MemoryMap<x64>>(&p_memory_map)) {
            return mm;
        }
        return std::get_if<MemoryMap<x86>>(&p_memory_map));
    }

    friend std::shared_ptr<ZkProcess> load_process_from_file(
        char* const* path);
};

std::shared_ptr<ZkProcess> load_process_from_file(
    char* const* path, std::optional<zklog::ZkLog *> log);
}  // namespace zkprocess

#endif  // ZKPROCESS_HH
