#include "zkhooks.hh"
#include "zktypes.hh"
#include <new>
#include <zkexcept.hh>

Hooks::Hook::Hook(addr_t addr)
    :h_addr(addr)
{}

