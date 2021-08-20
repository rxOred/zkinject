#ifndef ERR_HH
#define ERR_HH

#include <assert.h>
#include <stdexcept>

#define NDEBUG
#undef NDEBUG

#ifdef EXEPTIONS
    #define ERROR(ex) throw ex
#else 
    #define ERROR(ex) (ex), std::abort()
#endif

struct fetal_error {
    using handler = void(*)( ... );
    handler set_handler(handler h);
    handler get_handler();
};

#endif /* ERR_HH */
