#ifndef ZKHOOKS_HH
#define ZKHOOKS_HH

#include "zkelf.hh"
#include "zkproc.hh"
#include "zktypes.hh"
#include "zkexcept.hh"
#include <memory>
#include <sched.h>
#include <optional>
#include <sys/ptrace.h>

namespace Hooks {
    class Hook {
        private:
            addr_t h_addr;
        public:
            Hook(addr_t addr);
            ~Hook();
            virtual HookAddr() = 0;
    };

    class InlineHook: public Hook {
        private:
            uint8_t orig_data;
        public:
            InlineHook(addr_t addr, addr_t jmp_addr)
    };
}