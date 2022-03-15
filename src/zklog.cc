#include "zklog.hh"

ZkLog::Log ZkLog::Log::l_instance;

void ZkLog::Log::ClearLog(void) 
{
    std::queue<logmessage_t> empty;
    std::swap(l_log, empty);
}

void ZkLog::Log::PushLog(std::string log_string, ZkLog::ZK_LOG_LEVEL level)
{
    logmessage_t msg(log_string, level);
    l_log.push(msg);
}

std::pair<std::string, ZkLog::ZK_LOG_LEVEL> ZkLog::Log::PopLog(void)
{
    auto pair = std::make_pair(l_log.front().getLogMessage(),
                               l_log.front().getLoglevel());
    l_log.pop();
    return pair;
}

