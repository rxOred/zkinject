#ifndef ZKLOG_HH
#define ZKLOG_HH

#include <memory>
#include <stack>
#include <string>

#define DEFAULT_LOG_COUNT 50

namespace zklog {
enum class log_level { LOG_LEVEL_DEBUG, LOG_LEVEL_ERROR, LOG_LEVEL_CRITICAL };

struct logmessage_t {
public:
    logmessage_t(std::string string, log_level level);
    logmessage_t(const logmessage_t& msg) = delete;
    logmessage_t(logmessage_t&& msg) = default;

    inline std::string get_log_message(void) { return log_string; }
    inline log_level get_log_level(void) { return log_level; }

private:
    std::string log_string;
    log_level log_level;
};

class Log {
public:
    Log(const Log&) = delete;

    static Log& get_logger(void) { return l_instance; }
    inline void set_log_buffer_count(std::size_t count) { l_count = count; }
    void clear_log(void);
    void push_log(std::string log_string, log_level level);
    std::pair<std::string, log_level> pop_log(void);
    log_level peek_log_level(void);

private:
    Log() {}

    static Log l_instance;
    std::size_t l_count = DEFAULT_LOG_COUNT;
    std::stack<logmessage_t> l_log;
};
};  // namespace zklog

#endif  // !ZKLOG_HH
