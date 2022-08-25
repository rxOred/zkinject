#include "zkprocess.hh"

#include <sched.h>

#include <memory>
#include <variant>

#include "zkelf.hh"
#include "zklog.hh"
#include "zkmemorymap.hh"
#include "zkptrace.hh"
#include "zksnapshot.hh"
#include "zktypes.hh"

zkprocess::ZkProcess::ZkProcess(std::shared_ptr<zkelf::ZkElf> elf, 
        std::variant<Ptrace<x64>, Ptrace<x86>> p, 
        std::variant<MemoryMap<x64>, MemoryMap<x86>> mm)
        :p_elf(elf), p_ptrace(p), p_memory_map(mm) {}

std::shared_ptr<zkprocess::ZkProcess> zkprocess::load_process_from_file(
    char* const* path, std::optional<zklog::ZkLog *> log) {
    // parse the elf binary and get the required architecture
    auto p_elf = zkelf::load_elf_from_file(
        path[0], zkelf::elf_flags::ELF_NO_SAVE, log);
    // if ELFCLASS is (64, 32), create process components for (x64, x86)
    zkelf::ei_class arch = p_elf->get_elf_class();
    if (arch == zkelf::ei_class::ELFCLASS64) {
        auto p_ptrace = Ptrace<x86>(path, PTRACE_DISABLE_ASLR, log);
        auto p_memory_map =
            MemoryMap<x86>(p_ptrace.get_pid());
        auto ptr = std::make_shared<ZkProcess>(p_elf, p_ptrace, p_memory_map);
        return ptr;
    } else if (arch == zkelf::ei_class::ELFCLASS32) {
        auto p_ptrace = Ptrace<x64>(path, PTRACE_DISABLE_ASLR, log);
        auto p_memory_map =
            MemoryMap<x64>(p_ptrace.get_pid());
        auto ptr = std::make_shared<ZkProcess>(p_elf, p_ptrace, p_memory_map);
        return ptr;
    }
    return nullptr;
}

//void zkprocess::load_process_from_pid(pid_t pid) {}
