#ifndef ZKTYPES_HH
#define ZKTYPES_HH

#include <cstdint>
#include <string>
//#include <elf.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>

/*
** TODO
** move all the template implementations to header files
** make all single lined functions non-inline
** make all functions less than 10 lines inline
*/

struct zktypes {
    using u8_t = std::uint8_t;
    using i8_t = std::int8_t;
    using u16_t = std::uint16_t;
    using u32_t = std::uint32_t;
    using i32_t = std::int32_t;
    using u64_t = std::uint64_t;
    using i64_t = std::int64_t;
};

struct x86 : public zktypes {
    using addr_t = std::uint32_t;
    using saddr_t = std::int64_t;
    using off_t = std::uint32_t;
};

struct x64 : public zktypes {
    using addr_t = std::uint64_t;
    using saddr_t = std::int64_t;
    using off_t = std::uint64_t;
};

using eventcodes_t      = __ptrace_eventcodes;
// TODO make this independant
using registers_t       = struct user_regs_struct;

#endif  // ZKTYPES_HH
