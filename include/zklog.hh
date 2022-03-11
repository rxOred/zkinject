#ifndef ZKLOG_HH
#define ZKLOG_HH

#include <string>
#include <memory>
#include <queue>

#define DEFAULT_LOG_COUNT  50

namespace ZkLog {
    enum ZK_LOG_LEVEL {
        LOG_LEVEL_DEBUG,
        LOG_LEVEL_ERROR,
        LOG_LEVEL_CRITICAL
    };

    struct logmessage_t {
        public:
            logmessage_t(std::string string, ZK_LOG_LEVEL level)
                :log_string(string), log_level(level)
            {}
            inline std::string getLogMessage(void)
            {
                return log_string;
            }
            inline ZK_LOG_LEVEL getLoglevel(void)
            {
                return log_level;
            }
        private:
            std::string log_string;
            ZK_LOG_LEVEL log_level;
    };

    class Log {
        private:
            int log_count = DEFAULT_LOG_COUNT;
            std::queue<std::shared_ptr<logmessage_t>> log;
        public:
            ~Log();
            void PushLog(std::string log_string, ZK_LOG_LEVEL level);
            std::pair<std::string, ZK_LOG_LEVEL> PopLog(void);
            void ClearLog(void);
    };

    //void IniteZkLog(void);
};

#endif // !ZKLOG_HH
