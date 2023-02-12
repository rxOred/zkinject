cmake_minimum_required(VERSION 3.20)
enable_language(CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(zkinject VERSION 0.1 DESCRIPTION "some ugly library")
include(GNUInstallDirs)

set(LIBZKINJECT_PUBLIC_INCLUDE_DIRECTORIES include/)
set(LIBZKINJECT_PRIVATE_INCLUDE_DIRECTORIES src/)

file(GLOB_RECURSE LIBZKINJECT_SOURCE_FILES "src/*.cc" "src/*.hh")
file(GLOB_RECURSE LIBZKINJECT_INCLUDE_FILES "include/*.hh")

add_library(zkinject SHARED ${LIBZKINJECT_PUBLIC_INCLUDE_DIRECTORIES} ${LIBZKINJECT_SOURCE_FILES})

target_include_directories(zkinject PUBLIC ${LIBZKINJECT_PUBLIC_INCLUDE_DIRECTORIES})
target_include_directories(zkinject PRIVATE ${LIBZKINJECT_PRIVATE_INCLUDE_DIRECTORIES})

set_target_properties(zkinject PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(zkinject PROPERTIES SOVERSION 1)
set_target_properties(zkinject PROPERTIES PUBLIC_HEADER "${LIBZKINJECT_INCLUDE_FILES}")

configure_file(libzkinject.pc.in libzkinject.pc @ONLY)

add_compile_definitions(ZKINJECT_DEBUG)

install (TARGETS zkinject
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION /usr/lib/
    ARCHIVE DESTINATION /usr/lib/
    PUBLIC_HEADER DESTINATION /usr/include/zkinject/
)

#install(FILES $CMAKE_BINARY_DIR/zkinject.pc
#    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig)
