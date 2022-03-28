#ifndef ZKUTILS_HH
#define ZKUTILS_HH

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "zkexcept.hh"
#include "zktypes.hh"

#define MAGIC_LEN 3

#define ZK_PATH_LEN 64
#define ZK_CHECK_FLAGS(x, y) ((x) & (y))
#define ZK_CLEAR_FLAGS(x) ((x) ^ (x))
#define ZK_SET_FLAGS(x, y) (((x) ^ (x)) | (y))
#define ZK_PAGE_ALIGN_UP(x) ((x) & ~(4095))
#define ZK_PAGE_SIZE sysconf(_SC_PAGESIZE)

namespace zkutils {

std::pair<void *, std::size_t> open_file(const char *path);

template <typename T, int size>
bool validate_magic_number(T a[size], T b[size])
{
	for (int i = 0; i < size; ++i) {
		if (a[i] != b[i]) {
			return false;
		}
	}
	return true;
}

void save_memory_map(const char *path, void *memory_map, int map_size);

void save_buffer_to_file(const char *pathname, off_t offset, void *buffer,
                         int buffer_size);

template <typename T = x64>
int patch_address(typename T::u8_t *buffer, size_t len, typename T::addr_t addr,
                  typename T::u8_t *magic) {
    int count = 0;
    for (int i = 0; i < len; i++) {
        printf("%x\n", buffer[i]);
        if (buffer[i] == magic[0]) {
            for (int j = 0; j < MAGIC_LEN; j++) {
                if (buffer[i + j] == magic[j]) count++;
            }
            if (count == MAGIC_LEN) {
                *(typename T::addr_t *)((void *)(buffer + i)) = addr;
            } else {
                continue;
            }
        }
    }
}

};  // namespace zkutils

#endif  // ZKUTILS_HH
