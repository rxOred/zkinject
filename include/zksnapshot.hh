#ifndef ZKSNAPSHOT_HH
#define ZKSNAPSHOT_HH

#include "zktypes.hh"
#include "zklog.hh"
#include <queue>

#define DEFAULT_SNAPSHOT_COUNT      5
#define DEFAULT_SNAPSHOT_STACK_SZ   1024
#define DEFAULT_SNAPSHOT_INSTR      64

namespace ZkProcess {
    // queue to store process state
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
            Snapshot();
            Snapshot(int count);
            Snapshot(ZkLog::Log *log);
            Snapshot(int count, ZkLog::Log *log);
            ~Snapshot();

            bool SaveSnapshot(ZkProcess::Ptrace &ptrace, u8_t flags);
            bool RestoreSnapshot(ZkProcess::Ptrace &ptrace);
            void ClearSnapshots(void);
        private:
            int s_count = DEFAULT_SNAPSHOT_COUNT;
            std::queue<std::shared_ptr<snapshot_t>> s_snapshots;
            ZkLog::Log *s_log;
    };


};

#endif // ZKSNAPSHOT_HH
