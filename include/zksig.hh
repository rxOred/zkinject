#ifndef ZKSIG_HH
#define ZKSIG_HH

#include "zktypes.hh"
#include <signal.h>
#include <sys/types.h>

namespace ZkProcess {
    class Signal {
        public:
            Signal(pid_t pid)
                :s_pid(pid)
            {// TODO initialize s_siginfo to 0x0
            }
            bool SignalProcess(int signal) const
            {
                if (kill(s_pid, signal) < 0) return false;
                else return true;
            }
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
            siginfo_t s_siginfo;
            pid_t s_pid;
    };
};

#endif // ZKSIG_HH
