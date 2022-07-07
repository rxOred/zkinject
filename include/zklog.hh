#ifndef ZKLOG_HH
#define ZKLOG_HH

#include <memory>
#include <optional>
#include <stack>
#include <string>

#define DEFAULT_LOG_COUNT 50

namespace zklog {
enum class log_level {
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_CRITICAL
};

enum class log_error_code {
    LOG_ERROR_NONE,
    LOG_ERROR_INVALID_FILE_TYPE,
    LOG_ERROR_INVALID_SECTION,
    LOG_ERROR_INVALID_SEGMENT,
    LOG_ERROR_INALID_SYMBOL,
    LOG_ERROR_INDEX_OUT_OF_RANGE
};

// logs are stored in a stack as instances of this struct.
struct logmessage_t {
public:
    logmessage_t(std::string string, log_level level,
                 log_error_code error_code);
    logmessage_t(const logmessage_t& msg) = delete;
    logmessage_t(logmessage_t&& msg) = default;

    inline std::string get_log_message(void) { return l_string; }
    inline log_level get_log_level(void) { return l_level; }
    inline log_error_code get_log_error_code(void) {
        return l_error_code;
    }

private:
    std::string l_string;
    log_level l_level;
    log_error_code l_error_code = log_error_code::LOG_ERROR_NONE;
};

class ZkLog {
public:
    ZkLog(const ZkLog&) = delete;

    static ZkLog& get_logger(void) { return l_instance; }
    inline void set_log_buffer_count(std::size_t count) {
        l_count = count;
    }
    void clear_log(void);
    void push_log(std::string log_string, log_level level,
                  std::optional<log_error_code> error_code =
                      log_error_code::LOG_ERROR_NONE);
	std::tuple<std::string, log_level, log_error_code> pop_log(void);
    log_level peek_log_level(void);

private:
    ZkLog() {}

    static ZkLog l_instance;
    std::size_t l_count = DEFAULT_LOG_COUNT;
    std::stack<logmessage_t> l_log;
};

};  // namespace zklog

#endif  // !ZKLOG_HH
