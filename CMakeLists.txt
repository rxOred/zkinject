cmake_minimun_required(VERSION 3.20)
enable_language(CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)

project(zkinject 0.1)
find_package(Threads REQUIRED)
file(GLOB_RECURSE SRC_FILES ./src/*.cc)