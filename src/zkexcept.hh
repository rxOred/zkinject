#ifndef ZKEXCEPT_HH
#define ZKEXCEPT_HH

#include <stdexcept>

namespace zkexcept {

    struct some_weird_error : public std::runtime_error{
        some_weird_error(const char *what) : runtime_error(what) {}
        some_weird_error() : runtime_error("some weird error occured\n")
        {}
    };

    struct opration_failed_error : public std::runtime_error {
        opration_failed_error(const char *what) : runtime_error(what){}
        opration_failed_error() : runtime_error("operation failed"){}
    };

    /* type stuff */
    struct not_exec_error : public std::runtime_error{
        not_exec_error() : runtime_error("not an executable file") {}
    };

    struct not_dyn_error : public std::runtime_error{
        not_dyn_error() : runtime_error("not a shared object") {}
    };

    /* not found stuff */
    struct segment_not_found_error : public std::runtime_error{
        segment_not_found_error(const char *what) : runtime_error(what)
        {}
        segment_not_found_error() : runtime_error("segment not found\n")
        {}
    };

    struct section_not_found_error : public std::runtime_error{
        section_not_found_error(const char *what) : runtime_error(what)
        {}
        section_not_found_error() : runtime_error("section not found\n")
        {}
    };

    struct file_not_found_error : public std::runtime_error{
        file_not_found_error(const char *what) : runtime_error(what) {}
        file_not_found_error() : runtime_error("file not found\n") {}
    };

    struct magic_not_found_error : public std::runtime_error{
        magic_not_found_error(const char *what) : runtime_error(what) {}
        magic_not_found_error() : runtime_error("magic number not found\n")
        {}
    };

    struct stripped_binary_error : public std::runtime_error{
        stripped_binary_error(const char *what) : runtime_error(what) {}
        stripped_binary_error() : runtime_error("stripped binary error\n")
        {}
    };

    struct symbol_not_found_error : public std::runtime_error{
        symbol_not_found_error(const char *what) : runtime_error(what){}
        symbol_not_found_error() : runtime_error("symbol not found\n")
        {}
    };

    struct permission_denied : public std::runtime_error{
        permission_denied(const char *what) : runtime_error(what) {}
        permission_denied() : runtime_error("permission denied\n") {}
    };

    struct proc_file_error : public std::runtime_error{
        proc_file_error(const char *what) : runtime_error(what) {}
        proc_file_error() : runtime_error("proc file error\n") {}
    };
}

#endif /* ZKEXCEPT_HH */
