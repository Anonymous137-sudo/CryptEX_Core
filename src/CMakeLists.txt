cmake_minimum_required(VERSION 3.15)
project(CryptEX LANGUAGES CXX ASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(WIN32 AND CMAKE_CROSSCOMPILING)
    if(NOT DEFINED OPENSSL_ROOT_DIR)
        message(FATAL_ERROR "Set OPENSSL_ROOT_DIR to the Windows OpenSSL prefix")
    endif()
    set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include")
    # Prefer lib64 for mingw-w64 static build
    if(EXISTS "${OPENSSL_ROOT_DIR}/lib64/libcrypto.a")
        set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_ROOT_DIR}/lib64/libcrypto.a")
        set(OPENSSL_SSL_LIBRARY "${OPENSSL_ROOT_DIR}/lib64/libssl.a")
    else()
        set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_ROOT_DIR}/lib/libcrypto.a")
        set(OPENSSL_SSL_LIBRARY "${OPENSSL_ROOT_DIR}/lib/libssl.a")
    endif()
    set(OPENSSL_LIBRARIES ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY} ws2_32 gdi32 crypt32 mswsock)
else()
    find_package(OpenSSL REQUIRED)
endif()
if(WIN32 AND CMAKE_CROSSCOMPILING)
    # Header-only Boost.Asio usage; use host-installed headers
    set(Boost_INCLUDE_DIRS "/opt/homebrew/include")
else()
    find_package(Boost REQUIRED)
endif()
set(CRYPTEX_OPUS_LINK_TARGET "")
if(WIN32 AND CMAKE_CROSSCOMPILING AND DEFINED OPUS_ROOT_DIR)
    set(OPUS_INCLUDE_DIRS "${OPUS_ROOT_DIR}/include/opus")
    if(EXISTS "${OPUS_ROOT_DIR}/lib/libopus.a")
        set(OPUS_LIBRARIES "${OPUS_ROOT_DIR}/lib/libopus.a")
    elseif(EXISTS "${OPUS_ROOT_DIR}/lib64/libopus.a")
        set(OPUS_LIBRARIES "${OPUS_ROOT_DIR}/lib64/libopus.a")
    else()
        message(FATAL_ERROR "Set OPUS_ROOT_DIR to a Windows Opus prefix containing libopus.a")
    endif()
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(OPUS REQUIRED IMPORTED_TARGET opus)
    set(CRYPTEX_OPUS_LINK_TARGET "PkgConfig::OPUS")
endif()

set(CRYPTEX_CORE_SOURCES
    chainparams.cpp
    chat_content.cpp
    chat_state.cpp
    chat_history.cpp
    chat_secure.cpp
    config.cpp
    debug.cpp
    duckdns.cpp
    block.cpp
    transaction.cpp
    types.cpp
    voice_call.cpp
    base64.cpp
    bip39.cpp
    utxo.cpp
    mempool.cpp
    script.cpp
    network.cpp
    rpc.cpp
    wallet.cpp
    blockchain.cpp
    block_store.cpp
)

add_executable(cryptexd
    main.cpp
    ${CRYPTEX_CORE_SOURCES}
)

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set_target_properties(cryptexd PROPERTIES OUTPUT_NAME "cryptexd_osx")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set_target_properties(cryptexd PROPERTIES OUTPUT_NAME "cryptexd_win32")
else()
    set_target_properties(cryptexd PROPERTIES OUTPUT_NAME "cryptexd_linux")
endif()

target_include_directories(cryptexd PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${OPENSSL_INCLUDE_DIR} ${OPUS_INCLUDE_DIRS} ${Boost_INCLUDE_DIRS})
target_compile_definitions(cryptexd PRIVATE BOOST_ERROR_CODE_HEADER_ONLY BOOST_SYSTEM_NO_LIB)
if(WIN32 AND CMAKE_CROSSCOMPILING)
    target_link_libraries(cryptexd PRIVATE ${OPENSSL_LIBRARIES} ${OPUS_LIBRARIES})
else()
    target_link_libraries(cryptexd PRIVATE OpenSSL::SSL OpenSSL::Crypto pthread z ${CRYPTEX_OPUS_LINK_TARGET})
endif()

add_executable(cryptex_tests
    tests.cpp
    ${CRYPTEX_CORE_SOURCES}
)
target_include_directories(cryptex_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${OPENSSL_INCLUDE_DIR} ${OPUS_INCLUDE_DIRS} ${Boost_INCLUDE_DIRS})
target_compile_definitions(cryptex_tests PRIVATE BOOST_ERROR_CODE_HEADER_ONLY BOOST_SYSTEM_NO_LIB)
if(WIN32 AND CMAKE_CROSSCOMPILING)
    target_link_libraries(cryptex_tests PRIVATE ${OPENSSL_LIBRARIES} ${OPUS_LIBRARIES})
else()
    target_link_libraries(cryptex_tests PRIVATE OpenSSL::SSL OpenSSL::Crypto pthread z ${CRYPTEX_OPUS_LINK_TARGET})
endif()

set(CRYPTEX_ASM_POWMINER FALSE)
set(CRYPTEX_POWMINER_NEEDS_CORE TRUE)
if(CMAKE_SYSTEM_NAME STREQUAL "Darwin" AND
   ((DEFINED CMAKE_OSX_ARCHITECTURES AND CMAKE_OSX_ARCHITECTURES MATCHES "arm64") OR
    CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm64|aarch64)$"))
    set(CRYPTEX_ASM_POWMINER TRUE)
    set(CRYPTEX_POWMINER_NEEDS_CORE FALSE)
    add_executable(cryptex_powminer
        asm/powminer_darwin_arm64.S
    )
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND
       CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm64|aarch64)$")
    set(CRYPTEX_ASM_POWMINER TRUE)
    set(CRYPTEX_POWMINER_NEEDS_CORE FALSE)
    add_executable(cryptex_powminer
        asm/powminer_linux_arm64.S
    )
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND
       CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
    set(CRYPTEX_ASM_POWMINER TRUE)
    set(CRYPTEX_POWMINER_NEEDS_CORE FALSE)
    add_executable(cryptex_powminer
        asm/powminer_linux_x86_64.S
    )
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows" AND
       CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
    set(CRYPTEX_ASM_POWMINER TRUE)
    set(CRYPTEX_POWMINER_NEEDS_CORE FALSE)
    add_executable(cryptex_powminer
        asm/powminer_windows_x86_64.S
    )
else()
    add_executable(cryptex_powminer
        powminer_main.cpp
        ${CRYPTEX_CORE_SOURCES}
    )
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set_target_properties(cryptex_powminer PROPERTIES OUTPUT_NAME "cryptex_powminer_osx")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set_target_properties(cryptex_powminer PROPERTIES OUTPUT_NAME "cryptex_powminer_win32")
else()
    set_target_properties(cryptex_powminer PROPERTIES OUTPUT_NAME "cryptex_powminer_linux")
endif()

if(CRYPTEX_POWMINER_NEEDS_CORE)
    target_include_directories(cryptex_powminer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${OPENSSL_INCLUDE_DIR} ${OPUS_INCLUDE_DIRS} ${Boost_INCLUDE_DIRS})
    target_compile_definitions(cryptex_powminer PRIVATE BOOST_ERROR_CODE_HEADER_ONLY BOOST_SYSTEM_NO_LIB)
    if(CRYPTEX_ASM_POWMINER)
        target_compile_definitions(cryptex_powminer PRIVATE CRYPTEX_ASM_ENTRY_STUB=1)
    endif()
    if(WIN32 AND CMAKE_CROSSCOMPILING)
        target_link_libraries(cryptex_powminer PRIVATE ${OPENSSL_LIBRARIES} ${OPUS_LIBRARIES})
    else()
        target_link_libraries(cryptex_powminer PRIVATE OpenSSL::SSL OpenSSL::Crypto pthread z ${CRYPTEX_OPUS_LINK_TARGET})
    endif()
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    install(TARGETS cryptexd cryptex_tests cryptex_powminer RUNTIME DESTINATION ".")
elseif(WIN32)
    install(TARGETS cryptexd cryptex_tests cryptex_powminer RUNTIME DESTINATION ".")
else()
    install(TARGETS cryptexd cryptex_tests cryptex_powminer RUNTIME DESTINATION "bin")
endif()
