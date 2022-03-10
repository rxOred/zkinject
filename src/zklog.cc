#include "zklog.hh"

ZkLog::Log::~Log()
{
    for (int i = 0; i < log.size(); i++) {
        log.front().reset();
        log.pop();
    }
}

void ZkLog::Log::PushLog(std::string *log_string, ZkLog::ZK_LOG_LEVEL level)
{
    auto msg = std::make_shared<logmessage_t>(log_string, level);
    log.push(msg);
}

std::pair<std::string, ZkLog::ZK_LOG_LEVEL> ZkLog::Log::PopLog(void)
{
    auto pair = std::make_pair(log.front()->getLogMessage(),
                               log.front()->getLoglevel());
    log.pop();
    return pair;
}
