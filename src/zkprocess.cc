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

std::shared_ptr<zkprocess::ZkProcess> zkprocess::load_process_from_file(
    char* const* path, std::optional<zklog::ZkLog *> log) {
    // parse the elf binary and get the required architecture
    auto ptr = std::make_shared<ZkProcess>();
    ptr->p_elf = zkelf::load_elf_from_file(
        path[0], zkelf::elf_flags::ELF_NO_SAVE, log);
    zkelf::ei_class arch = ptr->p_elf->get_elf_class();
    // if ELFCLASS is (64, 32), create process components for (x64, x86)
    if (arch == zkelf::ei_class::ELFCLASS64) {
        ptr->p_ptrace = Ptrace<x86>(path, PTRACE_DISABLE_ASLR, log);
        ptr->p_memory_map =
            MemoryMap<x86>(std::get<Ptrace<x86>>(ptr->p_ptrace).get_pid());
    } else if (arch == zkelf::ei_class::ELFCLASS32) {
        ptr->p_ptrace = Ptrace<x64>(path, PTRACE_DISABLE_ASLR, log);
        ptr->p_memory_map =
            MemoryMap<x64>(std::get<Ptrace<x64>>(ptr->p_ptrace).get_pid());
    }
	return ptr;
}

//void zkprocess::load_process_from_pid(pid_t pid) {}
