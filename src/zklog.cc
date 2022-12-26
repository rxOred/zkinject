#include "zklog.hh"

zklog::logmessage_t::logmessage_t(std::string string,
                                  zklog::log_level level,
                                  zklog::log_error_code error_code)
    : l_string(string), l_level(level), l_error_code(error_code) {}

zklog::ZkLog zklog::ZkLog::l_instance;

void zklog::ZkLog::clear_log(void) {
    std::stack<logmessage_t> empty;
    std::swap(l_log, empty);
}

void zklog::ZkLog::push_log(std::string log_string, log_level level,
                            std::optional<log_error_code> error_code) {
    l_log.emplace(log_string, level,
                  error_code.value_or(log_error_code::LOG_ERROR_NONE));
}

std::tuple<std::string, zklog::log_level, zklog::log_error_code>
zklog::ZkLog::pop_log(void) {
    auto t = std::make_tuple(l_log.top().get_log_message(),
                             l_log.top().get_log_level(),
                             l_log.top().get_log_error_code());
    l_log.pop();
    return t;
}

zklog::log_level zklog::ZkLog::peek_log_level() {
    return l_log.top().get_log_level();
}
