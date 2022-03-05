#include "zkexcept.hh"
#include "zkproc.hh"
#include "zkproc.hh"
#include <signal.h>

ZkProcess::Signal::Signal(pid_t pid)
    :s_pid(pid)
{
    s_siginfo = {0};
}

bool ZkProcess::Signal::SignalProcess(int signal) const
{
    if (kill(s_pid, signal) < -1) 
        return false;
    else 
        return true;
}

bool ZkProcess::Signal::SignalStopProcess(void) const 
{
    return SignalProcess(SIGSTOP);
}

bool ZkProcess::Signal::SignalKillProcess(void) const 
{
    return SignalProcess(SIGKILL);
}

bool ZkProcess::Signal::SignalContinueProcess(void) const 
{
    return SignalProcess(SIGCONT);
}

bool ZkProcess::Signal::SignalTrapProcess(void) const 
{
    return SignalProcess(SIGTRAP);
}
