#include "zksignal.hh"

ZkProcess::Signal::Signal(pid_t pid)
    :s_pid(pid)
{}

bool ZkProcess::Signal::SignalProcess(int signal) const
{
    if (kill(s_pid, signal) < 0) {
        return false;
    }
    else {
        return true;
    }
}
