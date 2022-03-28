#ifndef ZKSIG_HH
#define ZKSIG_HH

#include "zktypes.hh"
#include <signal.h>
#include <sys/types.h>

namespace ZkProcess {
    class Signal {
        public:
            Signal(pid_t pid);
            Signal(const Signal&) =default;
            Signal(Signal&&) =default;

            bool SignalProcess(int signal) const;
            inline bool SignalStopProcess(void) const
            {
                return SignalProcess(SIGSTOP);
            }
            inline bool SignalKillProcess(void) const
            {
                return SignalProcess(SIGKILL);
            }
            inline bool SignalContinueProcess(void) const
            {
                return SignalProcess(SIGCONT);
            }
            inline bool SignalTrapProcess(void) const
            {
                return SignalProcess(SIGTRAP);
            }
        private: 
            pid_t s_pid;
    };
};

#endif // ZKSIG_HH
