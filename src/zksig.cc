#include "zkexcept.hh"
#include "zkproc.hh"
#include "zkproc.hh"
#include <signal.h>

Process::Signal::Signal(pid_t pid)
    :s_pid(pid)
{
    s_siginfo = {0};
}


