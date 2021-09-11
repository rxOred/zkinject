cmake_minimum_required(VERSION 3.20)
enable_language(CXX)

set(CMAKE_CXX_STANDARD 17)

project(zkinject VERSION 0.1 DESCRIPTION "Elf malware development library")
include(GNUInstallDirs)

set(LIBZKINJECT_PUBLIC_INCLUDE_DIRECTORIES include/)
set(LIBZKINJECT_PRIVATE_INCLUDE_DIRECTORIES src/)

file(GLOB_RECURSE LIBZKINJECT_SOURCE_FILES "src/*.cc" "src/*.hh")
file(GLOB_RECURSE LIBZKINJECT_INCLUDE_FILES "include/*.hh")

add_library(zkinject STATIC ${LIBZKINJECT_PUBLIC_INCLUDE_DIRECTORIES} ${LIBZKINJECT_SOURCE_FILES})

target_include_directories(zkinject PUBLIC ${LIBZKINJECT_PUBLIC_INCLUDE_DIRECTORIES})
target_include_directories(zkinject PRIVATE ${LIBZKINJECT_PRIVATE_INCLUDE_DIRECTORIES})

set_target_properties(zkinject PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(zkinject PROPERTIES SOVERSION 1)
set_target_properties(zkinject PROPERTIES PUBLIC_HEADER "${LIBZKINJECT_INCLUDE_FILES}")

configure_file(libzkinject.pc.in libzkinject.pc @ONLY)

install (TARGETS zkinject
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(FILES $CMAKE_BINARY_DIR/zkinject.pc
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig)
