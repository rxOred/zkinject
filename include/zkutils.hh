#ifndef ZKUTIL_HH
#define ZKUTIL_HH

#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>

#define PATH_LEN 64

#define CHECK_FLAGS(x, y)   ((x) & (y))

#define PAGE_ALIGN_UP(x)    ((x) & ~(4095))

#define PAGE_SIZE           sysconf(_SC_PAGESIZE)

namespace ZkUtils {
    
    void SaveMemoryMap(const char *pathname, void *memmap, int map_size);
    
    void SaveBufferToFile(const char *pathname, off_t offset, 
            void *buffer, int buffer_size);

}

#endif /* ZKUTIL_HH */
