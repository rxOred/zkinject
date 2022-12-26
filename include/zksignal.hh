#ifndef ZKSIG_HH
#define ZKSIG_HH

#include <signal.h>
#include <sys/types.h>

#include "zktypes.hh"

namespace ZkProcess {
class Signal {
public:
    Signal(pid_t pid);
    Signal(const Signal&) = default;
    Signal(Signal&&) = default;

    bool SignalProcess(int signal) const;
    inline bool SignalStopProcess(void) const {
        return SignalProcess(SIGSTOP);
    }
    inline bool SignalKillProcess(void) const {
        return SignalProcess(SIGKILL);
    }
    inline bool SignalContinueProcess(void) const {
        return SignalProcess(SIGCONT);
    }
    inline bool SignalTrapProcess(void) const {
        return SignalProcess(SIGTRAP);
    }

private:
    pid_t s_pid;
};
};  // namespace ZkProcess

#endif  // ZKSIG_HH
