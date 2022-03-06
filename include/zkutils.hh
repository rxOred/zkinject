#ifndef ZKUTIL_HH
#define ZKUTIL_HH

#include "zktypes.hh"
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>

#define ZK_PATH_LEN 64

#define ZK_CHECK_FLAGS(x, y)   ((x) & (y))

#define ZK_PAGE_ALIGN_UP(x)    ((x) & ~(4095))

#define ZK_PAGE_SIZE           sysconf(_SC_PAGESIZE)

namespace ZkUtils {
    
    void SaveMemoryMap(const char *pathname, void *memmap, int map_size);
    
    void SaveBufferToFile(const char *pathname, off_t offset, 
            void *buffer, int buffer_size);

    void PatchAddress(u8 *buffer, size_t len, u64 addr, u8 *magic);

};

#endif /* ZKUTIL_HH */
