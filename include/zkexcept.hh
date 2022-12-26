#ifndef ZKEXCEPT_HH
#define ZKEXCEPT_HH

#include <stdexcept>

namespace zkexcept {
struct not_exec_error : public std::runtime_error {
    not_exec_error() : runtime_error("not an executable file") {}
};

struct not_dyn_error : public std::runtime_error {
    not_dyn_error() : runtime_error("not a shared object") {}
};

struct segment_not_found_error : public std::runtime_error {
    segment_not_found_error(const char *what) : runtime_error(what) {}
    segment_not_found_error() : runtime_error("segment not found") {}
};

struct section_not_found_error : public std::runtime_error {
    section_not_found_error(const char *what) : runtime_error(what) {}
    section_not_found_error() : runtime_error("section not found") {}
};

struct file_not_found_error : public std::runtime_error {
    file_not_found_error(const char *what) : runtime_error(what) {}
    file_not_found_error() : runtime_error("file not found") {}
};

struct invalid_file_format_error : public std::runtime_error {
    invalid_file_format_error(const char *what) : runtime_error(what) {}
    invalid_file_format_error() : runtime_error("invalid file type") {}
};

struct invalid_file_type_error : public std::runtime_error {
    invalid_file_type_error(const char *what) : runtime_error(what) {}
    invalid_file_type_error() : runtime_error("invalid file type") {}
};

struct symbol_not_found_error : public std::runtime_error {
    symbol_not_found_error(const char *what) : runtime_error(what) {}
    symbol_not_found_error() : runtime_error("symbol not found") {}
};

struct page_not_found_error : public std::runtime_error {
    page_not_found_error(const char *what) : runtime_error(what) {}
    page_not_found_error() : runtime_error("page not found") {}
};

struct ptrace_error : public std::runtime_error {
    ptrace_error(const char *what) : runtime_error(what) {}
    ptrace_error() : runtime_error("ptrace error") {}
};

struct process_error : public std::runtime_error {
    process_error(const char *what) : runtime_error(what) {}
    process_error() : runtime_error("process error") {}
};
};  // namespace zkexcept

#endif  // ZKEXCEPT_HH
