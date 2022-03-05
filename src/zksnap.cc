#include "zkexcept.hh"
#include "zkproc.hh"
#include "zkutils.hh"
#include "zktypes.hh"
#include <stdexcept>
#include <sys/ptrace.h>
#include <cstring>

/* BUG - this may not work */

bool ZkProcess::Snapshot::SaveSnapshot(ZkProcess::Ptrace &ptrace, u8 flags)
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

        stack = calloc(sizeof(u8), DEFAULT_SNAPSHOT_STACK_SZ);
        if (stack ==  nullptr) {
            throw std::runtime_error("failed to allocate memory\n");
        }
        try { ptrace.ReadProcess(stack, regs->rsp, 
                DEFAULT_SNAPSHOT_STACK_SZ); }
        catch (zkexcept::ptrace_error& e) {
            std::cerr << e.what();
            std::exit(1);
        }

        instr = calloc(sizeof(u8), DEFAULT_SNAPSHOT_INSTR);
        if (instr ==  nullptr) {
            throw std::runtime_error("failed to allocate memory\n");
        }
        try { ptrace.ReadProcess(instr, regs->rip, 
                DEFAULT_SNAPSHOT_INSTR); }
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

        instr = calloc(sizeof(u8), DEFAULT_SNAPSHOT_INSTR);
        if (instr ==  nullptr) {
            throw std::runtime_error("failed to allocate memory\n");
        }
        try { ptrace.ReadProcess(instr, regs->rip, 
                DEFAULT_SNAPSHOT_INSTR); }
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

bool ZkProcess::Snapshot::RestoreSnapshot(ZkProcess::Ptrace &ptrace)
{
    ProcessSnapshot *curr = snap_state;
    snap_state = curr->GetNext();

    registers_t *regs = curr->GetRegisters();
    ptrace.WriteRegisters(curr->GetRegisters());
    if (CHECK_FLAGS(PROCESS_SNAP_ALL, curr->GetFlags()))
        ptrace.WriteProcess(curr->GetStack(), regs->rsp, 
                DEFAULT_SNAPSHOT_STACK_SZ);
    else {
        int stack_frame_sz = regs->rbp - regs->rsp;
        ptrace.WriteProcess(curr->GetStack(), regs->rsp, stack_frame_sz);
    }
    ptrace.WriteProcess(curr->GetInstructions(), regs->rip, 
            DEFAULT_SNAPSHOT_INSTR);


    return true;
}
