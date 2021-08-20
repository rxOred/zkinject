#ifndef ZKPROC_HH
#define ZKPROC_HH

#include "zktypes.hh"
#include <sys/types.h>

#define PATHSZ  64
#define ADDRSZ  16

namespace Process {
    class Proc {
        protected:
            int proc_id;
        public:
            char *proc_pathname;

            Proc();
            Proc(pid_t pid);
            Addr GetLoadAddress(void) const;
            void SetPathname(pid_t pid);
    };
};

#endif /* ZKPROC_HH */
