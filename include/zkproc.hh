#ifndef ZKPROC_HH
#define ZKPROC_HH

#include <zktypes.hh>
#include <zkexcept.hh>
#include <sys/types.h>
#include <stdlib.h>
#include <assert.h>

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
            void SetMapPath(pid_t pid);
            void SetMemPath(pid_t pid);
            void SetCmdline(pid_t pid);
        public:
            char    *proc_mappath;
            char    *proc_mempath;
            char    *proc_cmdline;

            Proc();
            Proc(pid_t pid);
            void SetProcessId(pid_t pid);
            pid_t GetProcessId(void) const;
            Addr GetLoadAddress(void);

            
    };
};

#endif /* ZKPROC_HH */
