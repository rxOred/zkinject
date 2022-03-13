#include "zksig.hh"

bool ZkProcess::Signal::SignalProcess(int signal) const
{
    if (kill(s_pid, signal) < 0) {
        return false;
    }
    else {
        return true;
    }
}
