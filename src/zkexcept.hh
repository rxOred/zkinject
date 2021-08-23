#ifndef ZKEXCEPT_HH
#define ZKINJECT_HH

#include <stdexcept>

namespace zkexcept {

    struct file_not_found_error : public std::runtime_error{
        file_not_found_error(const char *what) : runtime_error(what)
        {}
    }

    struct magic_not_found_error : public std::runtime_error{
        magic_not_found_error(const char *what) : runtime_error(what)
        {}
    }

#define 
    struct not

    struct segment_not_found_error : public std::runtime_error{
        segment_not_found_error(const char *what) : runtime_error(what)
         {}
    }

    struct section_not_found_error : public std::runtime_error{
        section_not_found_error(const char *what) : runtime_error(what){}
    } 
}

#endif /* ZKEXCEPT_HH */