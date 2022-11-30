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

std::pair<void *, std::size_t> open_file(const char *path, bool should_writable = false);

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

inline void save_memory_map(const char *path, void *memory_map,
                            int map_size) noexcept {
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0666);
    if (fd < 0) {
        throw std::runtime_error("open failed");
    }
    if (write(fd, memory_map, map_size) < map_size) {
        throw std::runtime_error("write failed");
    }
    if (close(fd) < 0) {
        throw std::runtime_error("close failed");
    }
}

inline void save_buffer_to_file(const char *path, off_t offset, void *buffer,
                               int buffer_size) noexcept {
    int fd = open(path, O_CREAT | O_WRONLY, 0666);
    if (fd < 0) {
        throw zkexcept::file_not_found_error();
    }
    if (pwrite(fd, buffer, buffer_size, offset) < buffer_size) {
        throw std::runtime_error("write failed\n");
    }
    if (close(fd) < 0) {
        throw std::runtime_error("close failed\n");
    }
}

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
