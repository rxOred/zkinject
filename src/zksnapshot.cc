#include "zksnapshot.hh"

#include <sys/ptrace.h>

#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>

#include "zkexcept.hh"
#include "zklog.hh"
#include "zkprocess.hh"
#include "zkptrace.hh"
#include "zktypes.hh"
#include "zkutils.hh"

// BUG - this may not work
zkprocess::snapshot_t::snapshot_t(zktypes::u8_t flags, registers_t *regs,
                                  void *stack, void *instr)
    : ps_flags(flags),
      ps_registers(regs),
      ps_instructions(instr),
      ps_stack(stack) {}

zkprocess::snapshot_t::~snapshot_t() {
    if (ps_registers) {
        free(ps_registers);
    }
    if (ps_instructions) {
        free(ps_instructions);
    }
    if (ps_stack) {
        free(ps_stack);
    }
}

// remove this
void print_registers(registers_t *regs) {
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

template <typename T>
zkprocess::Snapshot<T>::Snapshot(zkprocess::Ptrace<T> &ptrace,
                                 std::optional<zktypes::u8_t> count,
                                 std::optional<zklog::ZkLog *> log)
    : s_ptrace(ptrace), s_count(count), s_log(log) {
    if (count.has_value()) {
        if (count.value() > MAXIMUM_SNAPSHOT_COUNT) {
            if (log.has_value()) {
                log.value()->push_log(
                    "snapshot count cannot be larger than       \
						MAXIMUM_SNAPSHOT_COUNT",
                    zklog::log_level::LOG_LEVEL_ERROR);
            }
            s_count = DEFAULT_SNAPSHOT_COUNT;
        }
    }
}

template <typename T>
bool zkprocess::Snapshot<T>::save_snapshot(zktypes::u8_t flags) {
    registers_t *regs = nullptr;
    void *stack = nullptr;
    void *instr = nullptr;

    // TODO
    // if (s_snapshots.size() + 1 > s_count) {
    //    s_snapshots.back().reset();
    //    s_snapshots.
    //}
    //
    if (ZK_CHECK_FLAGS(
            static_cast<zktypes::u8_t>(snapshot_flags::PROCESS_SNAP_ALL),
            flags)) {
        regs = (registers_t *)calloc(sizeof(registers_t), 1);
        if (regs == nullptr) {
            throw std::runtime_error("failed to allocate memory\n");
        }
        // std::__invoke(&zkprocess::Ptrace::ReadRegisters, ptrace,
        // regs);
        try {
            if (!s_ptrace.read_process_registers(*regs)) {
                return false;
            }
        } catch (zkexcept::ptrace_error &e) {
            std::cerr << e.what() << std::endl;
        }
        print_registers(regs);

        stack = calloc(sizeof(zktypes::u8_t), DEFAULT_SNAPSHOT_STACK_SZ);
        if (stack == nullptr) {
            throw std::runtime_error("failed to allocate memory\n");
        }
        try {
            s_ptrace.read_process_memory(stack, regs->rsp,
                                 DEFAULT_SNAPSHOT_STACK_SZ);
        } catch (zkexcept::ptrace_error &e) {
            std::cerr << e.what();
            std::exit(1);
        }

        instr = calloc(sizeof(zktypes::u8_t), DEFAULT_SNAPSHOT_INSTR);
        if (instr == nullptr) {
            throw std::runtime_error("failed to allocate memory\n");
        }
        try {
            s_ptrace.read_process_memory(instr, regs->rip, DEFAULT_SNAPSHOT_INSTR);
        } catch (zkexcept::ptrace_error &e) {
            std::cerr << e.what();
            std::exit(1);
        }
    }

    if (ZK_CHECK_FLAGS(
            static_cast<zktypes::u8_t>(snapshot_flags::PROCESS_SNAP_FUNC),
            flags)) {
        regs = (registers_t *)calloc(sizeof(registers_t), 1);
        if (regs == nullptr) {
            throw std::runtime_error("failed to allocate memory\n");
        }
        s_ptrace.read_process_registers(*regs);

        int stack_frame_sz = regs->rbp - regs->rsp;
        stack = calloc(sizeof(zktypes::u8_t), stack_frame_sz);
        if (stack == nullptr) {
            throw std::runtime_error("failed to allocate memory\n");
        }
        try {
            s_ptrace.read_process_memory(stack, regs->rsp, stack_frame_sz);
        } catch (zkexcept::ptrace_error &e) {
            std::cerr << e.what();
            std::exit(1);
        }

        instr = calloc(sizeof(zktypes::u8_t), DEFAULT_SNAPSHOT_INSTR);
        if (instr == nullptr) {
            throw std::runtime_error("failed to allocate memory\n");
        }
        try {
            s_ptrace.read_process_memory(instr, regs->rip, DEFAULT_SNAPSHOT_INSTR);
        } catch (zkexcept::ptrace_error &e) {
            std::cerr << e.what();
            std::exit(1);
        }
    }
    s_snapshots.push(std::make_unique<snapshot_t>(flags, regs, stack, instr));

    return true;
}

template <typename T>
bool zkprocess::Snapshot<T>::restore_snapshot(void) {
    if (s_snapshots.empty()) {
        if (s_log.has_value())
            s_log.value()->push_log("snapshot stack is empty",
                                    zklog::log_level::LOG_LEVEL_ERROR);
        return false;
    }

    registers_t *regs = s_snapshots.top()->get_registers();
    print_registers(regs);
    s_ptrace.write_process_registers(*s_snapshots.top()->get_registers());
    if (ZK_CHECK_FLAGS(
            static_cast<zktypes::u8_t>(snapshot_flags::PROCESS_SNAP_ALL),
            s_snapshots.top()->get_flags())) {
        s_ptrace.write_process_memory(s_snapshots.top()->get_stack(), regs->rsp,
                              DEFAULT_SNAPSHOT_STACK_SZ);
    } else {
        int stack_frame_sz = regs->rbp - regs->rsp;
        s_ptrace.write_process_memory(s_snapshots.top()->get_stack(), regs->rsp,
                              stack_frame_sz);
    }
    s_ptrace.write_process_memory(s_snapshots.top()->get_instructions(), regs->rip,
                          DEFAULT_SNAPSHOT_INSTR);

    s_snapshots.top().reset();
    s_snapshots.pop();

    return true;
}

template <typename T>
void zkprocess::Snapshot<T>::clear_snapshots(void) {
    while (!s_snapshots.empty()) {
        s_snapshots.top().reset();
        s_snapshots.pop();
    }
}

template class zkprocess::Snapshot<x64>;
template class zkprocess::Snapshot<x86>;
