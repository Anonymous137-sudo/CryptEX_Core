# Minimal cross setup from macOS to Linux using clang + target triple.
# Requires a Linux sysroot and libs (OpenSSL) available under ${LINUX_SYSROOT}.
#
# Example:
#   export LINUX_SYSROOT=/path/to/sysroot
#   cmake -S . -B build-linux -DCMAKE_TOOLCHAIN_FILE=toolchains/linux-clang.cmake -DCMAKE_BUILD_TYPE=Release

if(NOT DEFINED ENV{LINUX_SYSROOT})
    message(FATAL_ERROR "Set LINUX_SYSROOT to a Linux sysroot containing /usr/include and libs")
endif()

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_SYSROOT $ENV{LINUX_SYSROOT})
set(CMAKE_C_COMPILER_TARGET x86_64-unknown-linux-gnu)
set(CMAKE_CXX_COMPILER_TARGET x86_64-unknown-linux-gnu)

set(CMAKE_FIND_ROOT_PATH $ENV{LINUX_SYSROOT})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
