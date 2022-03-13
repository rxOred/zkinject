#include "zkexcept.hh"
#include "zksnapshot.hh"
#include "zkutils.hh"
#include "zktypes.hh"
#include "zkprocess.hh"
#include <memory>
#include <stdexcept>
#include <sys/ptrace.h>
#include <cstring>
#include <functional>

#include <iostream>

// BUG - this may not work
ZkProcess::snapshot_t::snapshot_t(u8_t flags, registers_t *regs, 
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

ZkProcess::Snapshot::Snapshot(ZkProcess::Ptrace& ptrace, int count)
    :s_ptrace(ptrace), s_log(nullptr)
{
    if (count > 0 || count <= 10) {
        s_count = count;
    }
}

ZkProcess::Snapshot::Snapshot(ZkProcess::Ptrace& ptrace, ZkLog::Log *log)
    :s_ptrace(ptrace), s_log(log)
{}

ZkProcess::Snapshot::Snapshot(ZkProcess::Ptrace& ptrace, int count,
        ZkLog::Log *log)
    :s_ptrace(ptrace), s_log(log)
{
    if (count > 0 || count <= 10) {
        if (s_log != nullptr) {
            s_log->PushLog(
                "snapshot count cannot be less than 0 or greater than 10",
                ZkLog::LOG_LEVEL_DEBUG);
        }
        s_count = count;
    }
}

ZkProcess::Snapshot::~Snapshot()
{
    for (int i = 0; i < s_snapshots.size(); i++) {
        s_snapshots.front().reset();
        s_snapshots.pop();
    }
}

void print_registers(registers_t *regs)
{
    std::cout << "---------------------------------------" << std::endl;
    std::cout << "print registers from zkinject" << std::endl;
    std::cout << "rax : " << std::hex << regs->rax << std::endl;
    std::cout << "rbx : " << std::hex << regs->rbx << std::endl;
    std::cout << "rcx : " << std::hex << regs->rcx << std::endl;
    std::cout << "rdx : " << std::hex << regs->rdx << std::endl;
    std::cout << "rsi : " << std::hex << regs->rsi << std::endl;
    std::cout << "rdi : " << std::hex << regs->rdi << std::endl;
    std::cout << "rip : " << std::hex << regs->rip << std::endl;
    std::cout << "---------------------------------------" << std::endl;
}

bool ZkProcess::Snapshot::SaveSnapshot(u8_t flags)
{
    registers_t *regs = nullptr;
    void *stack = nullptr;
    void *instr = nullptr;

    // TODO
    //if (s_snapshots.size() + 1 > s_count) {
    //    s_snapshots.back().reset();
    //    s_snapshots.
    //}
    //
    if (ZK_CHECK_FLAGS(PROCESS_SNAP_ALL, flags)) {
        regs = (registers_t *)calloc(sizeof(registers_t), 1);
        if (regs ==  nullptr) {
            throw std::runtime_error("failed to allocate memory\n");
        }
        //std::__invoke(&ZkProcess::Ptrace::ReadRegisters, ptrace, regs);
        try {
            if (!s_ptrace.ReadRegisters(regs)) {
                return false;
            }
        }
        catch (ZkExcept::ptrace_error& e) {
            std::cerr << e.what() << std::endl;
        }
        print_registers(regs);

        stack = calloc(sizeof(u8_t), DEFAULT_SNAPSHOT_STACK_SZ);
        if (stack ==  nullptr) {
            throw std::runtime_error("failed to allocate memory\n");
        }
        try {
            s_ptrace.ReadProcess(stack, regs->rsp, DEFAULT_SNAPSHOT_STACK_SZ);
        }
        catch (ZkExcept::ptrace_error& e) {
            std::cerr << e.what();
            std::exit(1);
        }

        instr = calloc(sizeof(u8_t), DEFAULT_SNAPSHOT_INSTR);
        if (instr ==  nullptr) {
            throw std::runtime_error("failed to allocate memory\n");
        }
        try {
            s_ptrace.ReadProcess(instr, regs->rip, DEFAULT_SNAPSHOT_INSTR);
        }
        catch (ZkExcept::ptrace_error& e) {
            std::cerr << e.what();
            std::exit(1);
        }
    }

    if (ZK_CHECK_FLAGS(PROCESS_SNAP_FUNC, flags)) {
        regs = (registers_t *)calloc(sizeof(registers_t), 1);
        if (regs ==  nullptr) {
            throw std::runtime_error("failed to allocate memory\n");
        }
        s_ptrace.ReadRegisters(regs);

        int stack_frame_sz = regs->rbp - regs->rsp;
        stack = calloc(sizeof(u8_t), stack_frame_sz);
        if (stack ==  nullptr) {
            throw std::runtime_error("failed to allocate memory\n");
        }
        try { s_ptrace.ReadProcess(stack, regs->rsp, stack_frame_sz); }
        catch (ZkExcept::ptrace_error& e) {
            std::cerr << e.what();
            std::exit(1);
        }

        instr = calloc(sizeof(u8_t), DEFAULT_SNAPSHOT_INSTR);
        if (instr ==  nullptr) {
            throw std::runtime_error("failed to allocate memory\n");
        }
        try { s_ptrace.ReadProcess(instr, regs->rip,
                DEFAULT_SNAPSHOT_INSTR); }
        catch (ZkExcept::ptrace_error& e) {
            std::cerr << e.what();
            std::exit(1);
        }
    }

    std::shared_ptr<snapshot_t> snapshot = 
        std::make_shared<snapshot_t>(flags, regs, stack, instr); 
    s_snapshots.push(snapshot);

    return true;
}

bool ZkProcess::Snapshot::RestoreSnapshot(void)
{
    if (s_snapshots.empty()) {
        if (s_log != nullptr)
            s_log->PushLog("snapshot queue is empty",
                           ZkLog::LOG_LEVEL_ERROR);
        return false;
    }

    registers_t *regs = s_snapshots.front()->GetRegisters();
    print_registers(regs);
    s_ptrace.WriteRegisters(s_snapshots.front()->GetRegisters());
    if (ZK_CHECK_FLAGS(PROCESS_SNAP_ALL, s_snapshots.front()->GetFlags()))
    {
        s_ptrace.WriteProcess(s_snapshots.front()->GetStack(), regs->rsp,
                DEFAULT_SNAPSHOT_STACK_SZ);
    }
    else {
        int stack_frame_sz = regs->rbp - regs->rsp;
        s_ptrace.WriteProcess(s_snapshots.front()->GetStack(), regs->rsp,
                stack_frame_sz);
    }
    s_ptrace.WriteProcess(s_snapshots.front()->GetInstructions(), regs->rip,
            DEFAULT_SNAPSHOT_INSTR);

    s_snapshots.front().reset();
    s_snapshots.pop();

    return true;
}

void ZkProcess::Snapshot::ClearSnapshots(void)
{
    for (std::size_t i = 0; i < s_snapshots.size(); ++i) {
        s_snapshots.front().reset();
        s_snapshots.pop();
    }
}
