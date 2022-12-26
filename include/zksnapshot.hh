#ifndef ZKSNAPSHOT_HH
#define ZKSNAPSHOT_HH

#include <iostream>
#include <optional>
#include <stack>
#include <variant>

#include "zklog.hh"
#include "zkptrace.hh"
#include "zktypes.hh"
#include "zkutils.hh"

#define MAXIMUM_SNAPSHOT_COUNT 10
#define DEFAULT_SNAPSHOT_COUNT 5
#define DEFAULT_SNAPSHOT_STACK_SZ 1024
#define DEFAULT_SNAPSHOT_INSTR 64

namespace zkprocess {
enum class snapshot_flags : zktypes::u8_t {
    PROCESS_SNAP_ALL,
    PROCESS_SNAP_FUNC
};

struct snapshot_t {
public:
    snapshot_t(zktypes::u8_t flags, registers_t *regs, void *stack,
               void *instr);
    snapshot_t(const snapshot_t &) = default;
    snapshot_t(snapshot_t &&) = default;

    ~snapshot_t();

    inline zktypes::u8_t get_flags(void) const { return ps_flags; }
    inline registers_t *get_registers(void) const { return ps_registers; }
    inline void *get_stack(void) const { return ps_stack; }
    inline void *get_instructions(void) const { return ps_instructions; }

private:
    // generic information about amount of the captured data
    zktypes::u8_t ps_flags;
    registers_t *ps_registers;
    void *ps_stack;
    void *ps_instructions;
};

template <typename T>
class Snapshot {
public:
    Snapshot(Ptrace<T> &ptrace,
             std::optional<zktypes::u8_t> count = DEFAULT_SNAPSHOT_COUNT,
             std::optional<zklog::ZkLog *> log = std::nullopt);
    Snapshot(const Snapshot &) = default;
    Snapshot(Snapshot &&) = default;

    ~Snapshot() = default;
    bool save_snapshot(zktypes::u8_t flags);
    bool restore_snapshot(void);
    void clear_snapshots(void);

private:
    std::stack<std::unique_ptr<snapshot_t>> s_snapshots;
    Ptrace<T> &s_ptrace;
    std::optional<zktypes::u8_t> s_count;
    std::optional<zklog::ZkLog *> s_log;
};
};  // namespace zkprocess

#endif  // ZKSNAPSHOT_HH
