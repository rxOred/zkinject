#ifndef ZKUTILS_HH
#define ZKUTILS_HH

#include "zktypes.hh"
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>

#define MAGIC_LEN   3

#define ZK_PATH_LEN            64
#define ZK_CHECK_FLAGS(x, y)   ((x) & (y))
#define ZK_PAGE_ALIGN_UP(x)    ((x) & ~(4095))
#define ZK_PAGE_SIZE           sysconf(_SC_PAGESIZE)

namespace ZkUtils {
    
    void SaveMemoryMap(const char *pathname, void *memmap, int map_size);
    
    void SaveBufferToFile(const char *pathname, off_t offset, 
            void *buffer, int buffer_size);

    void PatchAddress(u8_t *buffer, size_t len, u64_t addr, u8_t *magic);
};

#endif // ZKUTILS_HH
