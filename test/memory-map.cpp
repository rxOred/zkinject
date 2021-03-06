#include <zkinject/zkprocess.hh>
#include <zkinject/zklog.hh>

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Expected a process\n");
        return -1;
    }
    char *s[2];
    s[0] = argv[1];
    s[1] = nullptr;

    using namespace zkprocess;
    auto& logger = zklog::ZkLog::get_logger();
    auto process = zkprocess::load_process_from_file(s, &logger);
    process->p_memory_map.

    ZkProcess::Ptrace ptrace((const char **)s, 0, ZkProcess::PTRACE_START_NOW, &log);
    auto memmap = ptrace.GetMemoryMap();
    for (auto it = memmap->GetIteratorBegin(); it != memmap->GetIteratorLast(); ++it) {
        std::cout << std::hex << it->get()->GetPageStartAddress() << "\t"
                  << std::hex << it->get()->GetPageEndAddress() << "\t"
                  << it->get()->GetPagePermissions() << "\t"
                  << it->get()->GetPageName() << std::endl;
    }
}
