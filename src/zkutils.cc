#include "zkutils.hh"

#include "zkexcept.hh"

std::pair<void *, std::size_t> zkutils::open_file(const char *path) {
    int fd = open(path, O_RDWR);
    if (fd < 0) {
        throw zkexcept::file_not_found_error();
    }
    struct stat st;
    if (fstat(fd, &st) < 0) {
        throw std::runtime_error("fstat failed");
    }
    void *map =
        mmap(nullptr, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        throw std::runtime_error("mmap failed");
    }
	if (close(fd)) {
		throw std::runtime_error("close failed");
	}
    return std::make_pair(map, st.st_size);
}

