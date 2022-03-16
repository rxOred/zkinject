#include "zklog.hh"

ZkLog::logmessage_t::logmessage_t(std::string string, ZK_LOG_LEVEL level)
    :log_string(string), log_level(level)
{}

ZkLog::Log ZkLog::Log::l_instance;

void ZkLog::Log::ClearLog(void) 
{
    std::stack<logmessage_t> empty;
    std::swap(l_log, empty);
}

void ZkLog::Log::PushLog(std::string log_string, ZK_LOG_LEVEL level)
{
    l_log.emplace(log_string, level);
}

std::pair<std::string, ZkLog::ZK_LOG_LEVEL> ZkLog::Log::PopLog(void)
{
    auto pair = std::make_pair(l_log.top().getLogMessage(),
                               l_log.top().getLoglevel());
    l_log.pop();
    return pair;
}

ZkLog::ZK_LOG_LEVEL ZkLog::Log::PeekLogLevel(void)
{
    return l_log.top().getLoglevel();
}
