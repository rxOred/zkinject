#include "zkprocess.hh"

#include <sched.h>

#include <memory>
#include <utility>
#include <variant>

#include "zkelf.hh"
#include "zklog.hh"
#include "zkmemorymap.hh"
#include "zkptrace.hh"
#include "zksnapshot.hh"
#include "zktypes.hh"

zkprocess::ZkProcess::ZkProcess(
    std::shared_ptr<zkelf::ZkElf> elf,
    std::variant<std::shared_ptr<Ptrace<x64>>,
                 std::shared_ptr<Ptrace<x86>>>
        p,
    std::variant<std::shared_ptr<MemoryMap<x64>>,
                 std::shared_ptr<MemoryMap<x86>>>
        mm)
    : p_elf(std::move(elf)),
      p_ptrace(std::move(p)),
      p_memory_map(std::move(mm)) {}

// Reads the given elf file and parses it. uses returning data to 
// create a new process which is both readable and writable.
std::shared_ptr<zkprocess::ZkProcess> zkprocess::load_process_from_file(
    char* const* path, std::optional<zklog::ZkLog*> log) {
    // parse the elf binary and get the required architecture
    auto p_elf = zkelf::load_elf_from_file(path[0], log);
    // if ELFCLASS is (64, 32), create process components for (x64, x86)
    zkelf::ei_class arch = p_elf->get_elf_class();
    if (arch == zkelf::ei_class::ELFCLASS64) {
        auto p_ptrace =
            std::make_shared<Ptrace<x64>>(path, PTRACE_DISABLE_ASLR, log);
        auto p_memory_map =
            std::make_shared<MemoryMap<x64>>(p_ptrace->get_pid());
        auto ptr =
            std::make_shared<ZkProcess>(p_elf, p_ptrace, p_memory_map);
        return ptr;
    } else if (arch == zkelf::ei_class::ELFCLASS32) {
        auto p_ptrace =
            std::make_shared<Ptrace<x86>>(path, PTRACE_DISABLE_ASLR, log);
        auto p_memory_map =
            std::make_shared<MemoryMap<x86>>(p_ptrace->get_pid());
        auto ptr =
            std::make_shared<ZkProcess>(p_elf, p_ptrace, p_memory_map);
        return ptr;
    }
    return nullptr;
}

// void zkprocess::load_process_from_pid(pid_t pid) {}
