#include "zkexcept.hh"
#include "zkproc.hh"
#include "zkproc.hh"
#include <signal.h>

Process::Signal::Signal(pid_t pid)
    :s_pid(pid)
{
    s_siginfo = {0};
}

bool Process::Signal::SignalProcess(int signal) const
{
    if (kill(s_pid, signal) < -1) 
        return false;
    else 
        return true;
}

bool Process::Signal::SignalStopProcess(void) const 
{
    return SignalProcess(SIGSTOP);
}

bool Process::Signal::SignalKillProcess(void) const 
{
    return SignalProcess(SIGKILL);
}

bool Process::Signal::SignalContinueProcess(void) const 
{
    return SignalProcess(SIGCONT);
}

bool Process::Signal::SignalTrapProcess(void) const 
{
    return SignalProcess(SIGTRAP);
}
