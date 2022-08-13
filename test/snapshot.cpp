#include <zkinject/zkprocess.hh>

void print_registers(registers_t& regs)
{
    std::cout << "rax : " << std::hex << regs.rax << std::endl;
    std::cout << "rbx : " << std::hex << regs.rbx << std::endl;
    std::cout << "rcx : " << std::hex << regs.rcx << std::endl;
    std::cout << "rdx : " << std::hex << regs.rdx << std::endl;
    std::cout << "rsi : " << std::hex << regs.rsi << std::endl;
    std::cout << "rdi : " << std::hex << regs.rdi << std::endl;
    std::cout << "rip : " << std::hex << regs.rip << std::endl;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        puts("expected an argument");
        exit(1);
    }

    char *s[2];
    s[0] = argv[1];
    s[1] = nullptr;
    ZkLog::Log log;
    ZkProcess::Ptrace ptrace((const char **)s, 0, ZkProcess::PTRACE_START_NOW,
        &log);
    ZkProcess::Snapshot snapshot;

    registers_t regs;

    std::cout << "[+] registers before snapshot" <<std::endl;
    ptrace.ReadRegisters(&regs);
    print_registers(regs);

    std::cout << "[+] saving snapshot " << std::endl;
    snapshot.SaveSnapshot(ptrace, ZkProcess::PROCESS_SNAP_ALL);

    std::cout << "[+] changing registers" << std::endl;
    regs.rax = 0x1234;
    regs.rbx = 0x1234;
    regs.rcx = 0x1234;
    regs.rdx = 0x1234;
    //regs.rip = 0x1234;
    ptrace.WriteRegisters(&regs);
    ptrace.ReadRegisters(&regs);
    print_registers(regs);

    // FIXME wont restore captured snapshot
    std::cout << "[+] restoring snapshot" << std::endl;
    snapshot.RestoreSnapshot(ptrace);
    ptrace.ReadRegisters(&regs);
    print_registers(regs);

    ptrace.ContinueProcess(false);
    ptrace.WaitForProcess(0);
}
