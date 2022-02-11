#include "zkexcept.hh"
#include "zkproc.hh"
#include "zktypes.hh"
#include <stdexcept>
#include <sys/ptrace.h>
#include <cstring>

bool Process::Snapshot::SaveSnapshot(Process::Ptrace &ptrace, u8 flags)
{
    registers_t *regs = nullptr;
    void *stack = nullptr;
    void *instr = nullptr;

    if (CHECK_FLAGS(PROCESS_SNAP_ALL, flags)) {
        regs = (registers_t *)calloc(sizeof(registers_t), 1);
        if (regs ==  nullptr) {
            throw std::runtime_error("failed to allocate memory\n");
        }
        ptrace.ReadRegisters(regs);

        stack = calloc(sizeof(u8), 1024);
        if (stack ==  nullptr) {
            throw std::runtime_error("failed to allocate memory\n");
        }
        try { ptrace.ReadProcess(stack, regs->rsp, 1024); }
        catch (zkexcept::ptrace_error& e) {
            std::cerr << e.what();
            std::exit(1);
        }

        instr = calloc(sizeof(u8), 64);
        if (instr ==  nullptr) {
            throw std::runtime_error("failed to allocate memory\n");
        }
        try { ptrace.ReadProcess(instr, regs->rip, 64); }
        catch (zkexcept::ptrace_error& e) {
            std::cerr << e.what();
            std::exit(1);
        }
    }

    if (CHECK_FLAGS(PROCESS_SNAP_FUNC, flags)) {
        regs = (registers_t *)calloc(sizeof(registers_t), 1);
        if (regs ==  nullptr) {
            throw std::runtime_error("failed to allocate memory\n");
        }
        ptrace.ReadRegisters(regs);

        int stack_frame_sz = regs->rbp - regs->rsp;
        stack = calloc(sizeof(u8), stack_frame_sz);
        if (stack ==  nullptr) {
            throw std::runtime_error("failed to allocate memory\n");
        }
        try { ptrace.ReadProcess(stack, regs->rsp, stack_frame_sz); }
        catch (zkexcept::ptrace_error& e) {
            std::cerr << e.what();
            std::exit(1);
        }

        instr = calloc(sizeof(u8), 64);
        if (instr ==  nullptr) {
            throw std::runtime_error("failed to allocate memory\n");
        }
        try { ptrace.ReadProcess(instr, regs->rip, 64); }
        catch (zkexcept::ptrace_error& e) {
            std::cerr << e.what();
            std::exit(1);
        }
    }

    ProcessSnapshot *snapshot = new ProcessSnapshot(flags, regs, stack,
            instr);
    snapshot->SetNext(snap_state);
    snap_state = snapshot;

    return true;
}

bool Process::Snapshot::RestoreSnapshot(Process::Ptrace &ptrace)
{
    ProcessSnapshot *curr = snap_state;
    snap_state = curr->GetNext();
    ptrace.WriteRegisters(curr->GetRegisters());
}
