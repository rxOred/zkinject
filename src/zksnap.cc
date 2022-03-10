#include "zkexcept.hh"
#include "zkprocess.hh"
#include "zkutils.hh"
#include "zktypes.hh"
#include <memory>
#include <stdexcept>
#include <sys/ptrace.h>
#include <cstring>

/* BUG - this may not work */
ZkProcess::snapshot_t::snapshot_t(u8 flags, registers_t *regs, 
        void *stack, void *instr)
    :ps_flags(flags), ps_registers(regs), 
    ps_instructions(instr), ps_stack(stack)
{}

ZkProcess::snapshot_t::~snapshot_t()
{
    if (ps_registers) { free(ps_registers); }
    if (ps_instructions) { free(ps_instructions); }
    if (ps_stack) { free(ps_stack); }
}

ZkProcess::Snapshot::Snapshot(int count)
{
    if (count > 0 || count <= 10) {
        s_count = count;
    }
}

ZkProcess::Snapshot::~Snapshot()
{
    for (int i = 0; i < s_count; i++) {
        s_snapshots.front().reset();
        s_snapshots.pop();
    }
}

bool ZkProcess::Snapshot::SaveSnapshot(ZkProcess::Ptrace &ptrace, u8 flags)
{
    registers_t *regs = nullptr;
    void *stack = nullptr;
    void *instr = nullptr;

    /*
    if (s_snapshots.size() + 1 > s_count) {
        s_snapshots.back().reset();
        s_snapshots.
    }
    */
    if (ZK_CHECK_FLAGS(PROCESS_SNAP_ALL, flags)) {
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

    if (ZK_CHECK_FLAGS(PROCESS_SNAP_FUNC, flags)) {
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

    std::shared_ptr<snapshot_t> snapshot = 
        std::make_shared<snapshot_t>(flags, regs, stack, instr); 
    s_snapshots.push(snapshot);

    return true;
}

bool ZkProcess::Snapshot::RestoreSnapshot(ZkProcess::Ptrace &ptrace)
{
    if (s_snapshots.empty()) {
        return false;
    }

    registers_t *regs = s_snapshots.front()->GetRegisters();
    ptrace.WriteRegisters(s_snapshots.front()->GetRegisters());
    if (ZK_CHECK_FLAGS(PROCESS_SNAP_ALL, s_snapshots.front()->GetFlags()))
    {
        ptrace.WriteProcess(s_snapshots.front()->GetStack(), regs->rsp, 
                DEFAULT_SNAPSHOT_STACK_SZ);
    }
    else {
        int stack_frame_sz = regs->rbp - regs->rsp;
        ptrace.WriteProcess(s_snapshots.front()->GetStack(), regs->rsp, 
                stack_frame_sz);
    }
    ptrace.WriteProcess(s_snapshots.front()->GetInstructions(), regs->rip,
            DEFAULT_SNAPSHOT_INSTR);

    s_snapshots.front().reset();
    s_snapshots.pop();

    return true;
}
