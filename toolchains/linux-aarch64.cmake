# Cross-compilation from macOS to Linux ARM64 using a sysroot/toolchain.
#
# Required:
#   - LINUX_AARCH64_SYSROOT pointing at a Linux ARM64 sysroot
#   - aarch64-linux-gnu-gcc/g++ (or aarch64-unknown-linux-gnu-gcc/g++)

if(NOT DEFINED ENV{LINUX_AARCH64_SYSROOT})
    message(FATAL_ERROR "Set LINUX_AARCH64_SYSROOT to a Linux ARM64 sysroot containing headers and libs")
endif()

find_program(AARCH64_GCC NAMES aarch64-linux-gnu-gcc aarch64-unknown-linux-gnu-gcc REQUIRED)
find_program(AARCH64_GXX NAMES aarch64-linux-gnu-g++ aarch64-unknown-linux-gnu-g++ REQUIRED)

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)
set(CMAKE_C_COMPILER ${AARCH64_GCC})
set(CMAKE_CXX_COMPILER ${AARCH64_GXX})
set(CMAKE_SYSROOT $ENV{LINUX_AARCH64_SYSROOT})

set(CMAKE_FIND_ROOT_PATH $ENV{LINUX_AARCH64_SYSROOT})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
