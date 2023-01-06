cmake_minimum_required(VERSION 3.20)
enable_language(CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

project(test)

#include_directories(../include/)
include_directories(/usr/include)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/../bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/../bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/../bin)

find_library(ZKINJECT_LIB libzkinject HINTS /usr/lib)

add_executable(elf-get ../src/elf_get.cpp)
add_executable(elf-set ../src/elf_set.cpp)
add_executable(memory-map ../src/memory-map.cpp)

target_link_libraries(elf-get PUBLIC ${ZKINJECT_LIB})
target_link_libraries(elf-set PUBLIC ${ZKINJECT_LIB})
target_link_libraries(memory-map PUBLIC ${ZKINJECT_LIB})
