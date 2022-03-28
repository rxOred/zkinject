#ifndef ZKSNAPSHOT_HH
#define ZKSNAPSHOT_HH

#include "zktypes.hh"
#include "zklog.hh"
#include <stack>
#include <optional>

#define MAXIMUM_SNAPSHOT_COUNT      10
#define DEFAULT_SNAPSHOT_COUNT      5
#define DEFAULT_SNAPSHOT_STACK_SZ   1024
#define DEFAULT_SNAPSHOT_INSTR      64

namespace ZkProcess {

    enum PROCESS_SNAPSHOT : u8_t {
        PROCESS_SNAP_ALL     = 1,
        PROCESS_SNAP_FUNC
    };

    struct snapshot_t {
        public:
            snapshot_t(u8_t flags, registers_t *regs, void *stack,
                    void *instr);
    
            ~snapshot_t();

            inline u8_t GetFlags(void) const
            {
                return ps_flags;
            }
            inline registers_t *GetRegisters(void) const
            {
                return ps_registers;
            }
            inline void *GetStack(void) const
            {
                return ps_stack;
            }
            inline void *GetInstructions(void) const
            {
                return ps_instructions;
            }
        private:
            // generic information about amount of the captured data
            u8_t            ps_flags;
            registers_t     *ps_registers;
            void            *ps_stack;
            void            *ps_instructions;
    };

    class Ptrace;

    class Snapshot {
        public:
            Snapshot(ZkProcess::Ptrace& ptrace, 
                    std::optional<u8_t> count = DEFAULT_SNAPSHOT_COUNT,
                    std::optional<ZkLog::Log *> log = std::nullopt);

            ~Snapshot();
            bool SaveSnapshot(u8_t flags);
            bool RestoreSnapshot(void);
            void ClearSnapshots(void);
        private:
            std::stack<std::unique_ptr<snapshot_t>> s_snapshots;
            ZkProcess::Ptrace& s_ptrace;

            std::optional<u8_t> s_count;
            std::optional<ZkLog::Log *> s_log;
    };
};

#endif // ZKSNAPSHOT_HH
