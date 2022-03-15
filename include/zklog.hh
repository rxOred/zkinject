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
        public:
            Log(const Log&) =delete;
            static Log& Get(void) { return l_instance; }

            inline void SetLogCount(std::size_t count) 
            {
                l_count = count;
            }
            void ClearLog(void);
            void PushLog(std::string log_string, ZK_LOG_LEVEL level);
            std::pair<std::string, ZK_LOG_LEVEL> PopLog(void);
        private:
            Log() {}
            static Log l_instance; 
            std::size_t l_count = DEFAULT_LOG_COUNT;
            std::queue<logmessage_t> l_log;
    };
};

#endif // !ZKLOG_HH
