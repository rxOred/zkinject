#ifndef ZKPROC_HH
#define ZKPROC_HH

#include "zktypes.hh"
#include "zkexcept.hh"
#include <sys/types.h>
#include <assert.h>
#include <cstdio>
#include <fstream>
#include <new>
#include <sched.h>
#include <string>
#include <string.h>

#define PATH_LEN  64

#define MAPPATH     "/proc/%d/maps"
#define MEMPATH     "/proc/%d/mem"
#define CMDLINE     "/proc/%d/cmdline"

/* process information */
namespace Process {
    class Proc {
        protected:
            int     proc_id;
            Addr    proc_baseaddr;
            void    SetMapPath(void);
            void    SetMemPath(void);
            void    SetCmdline(void);
        public:
            char    *proc_mappath;
            char    *proc_mempath;
            char    *proc_cmdline;

            Proc(pid_t pid);
            ~Proc();
            void SetProcessId(pid_t pid);
            pid_t GetProcessId(void) const;
            Addr GetBaseAddress(void);
            Addr GetModuleBaseAddress(const char *module_name);
    };
};

#endif /* ZKPROC_HH */
