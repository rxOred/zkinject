#include "zkutils.hh"

#include <cstring>
#include <errno.h>
#include <iostream>

#include "zkexcept.hh"

std::pair<void *, std::size_t> zkutils::open_file(const char *path,
                                                  bool should_writable) {
    int fd = -1;
    if (should_writable) {
        fd = open(path, O_RDWR);
    } else {
        fd = open(path, O_RDONLY);
    }
    if (fd < 0) {
        throw zkexcept::file_not_found_error();
    }
    struct stat st;
    if (fstat(fd, &st) < 0) {
        throw std::runtime_error("fstat failed");
    }
	if (st.st_size == 0) {
		throw std::runtime_error("file is empty");
	}
    void *map = MAP_FAILED;
    if (should_writable) {
        map = mmap(nullptr, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                   fd, 0);
    } else {
        map = mmap(nullptr, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    }
    if (map == MAP_FAILED) {
		auto errstr = std::strerror(errno);
		std::cerr << errstr << std::endl;
        throw std::runtime_error("mmap failed");
    }
    if (close(fd) == -1) {
        throw std::runtime_error("close failed");
    }

    return std::make_pair(map, st.st_size);
}
