#include "zkexcept.hh"
#include "zkutils.hh"

void ZkUtils::SaveMemoryMap(const char *pathname, void *memmap, 
        int map_size) 
{
    int fd = open(pathname, O_CREAT | O_TRUNC | O_WRONLY, 0666);
    if (fd < 0) {
        throw zkexcept::file_not_found_error();
    }

    if (write(fd, memmap, map_size) < map_size) {
        throw zkexcept::file_not_found_error();
    }
}

void ZkUtils::SaveBufferToFile(const char *pathname, off_t offset, 
        void *buffer, int buffer_size)  
{
    int fd = open(pathname, O_CREAT | O_WRONLY, 0666);
    if (fd < 0)
        throw zkexcept::file_not_found_error();

    if (pwrite(fd, buffer, buffer_size, offset) < buffer_size) {
        throw zkexcept::file_not_found_error();
    }
}

void ZkUtils::PatchAddress(u8 *buffer, size_t len, u64 addr, u8 *magic)
{
    int count = 0;
    for (int i = 0; i < len; i++){
        printf("%x\n", buffer[i]);
        if(buffer[i] == magic[0]){
            for (int j = 0; j < MAGIC_LEN; j++){
                if(buffer[i + j] == magic[j])
                    count++;
            }
            if(count == MAGIC_LEN)
                *(u64 *)((void *)(buffer + i)) = addr;
            else
                continue;
        }
    }
error:
    throw zkexcept::magic_not_found_error();
}
