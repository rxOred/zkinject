#ifndef ZKPROCESS_HH
#define ZKPROCESS_HH

#include "zkptrace.hh"
#include "zksnapshot.hh"
#include "zkmemorymap.hh"
#include "zksignal.hh"
#include "zklog.hh"
#include "zktypes.hh"

#include <memory>
#include <optional>
#include <variant>

namespace ZkProcess {
    class Process {
        public:
            Process(std::variant<const char **, pid_t> process_info, 
                    std::optional<ZkLog::Log *> log = std::nullopt);

        private:
            std::unique_ptr<ZkProcess::Ptrace> p_ptrace;
            std::unique_ptr<ZkProcess::Snapshot> p_snapshots;
            std::unique_ptr<ZkProcess::MemoryMap> p_memory_map;
            std::unique_ptr<ZkProcess::Signal> p_signal;
            // hooks
            // in memory parser

            std::optional<ZkLog::Log *> p_log;
    };
};

#endif // ZKPROCESS_HH
