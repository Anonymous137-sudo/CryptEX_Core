cmake_minimum_required(VERSION 3.15)
project(CryptEX LANGUAGES CXX)

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

add_executable(cryptexd
    main.cpp
    chainparams.cpp
    chat_history.cpp
    chat_secure.cpp
    config.cpp
    debug.cpp
    duckdns.cpp
    block.cpp
    transaction.cpp
    types.cpp
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

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set_target_properties(cryptexd PROPERTIES OUTPUT_NAME "cryptexd_osx")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set_target_properties(cryptexd PROPERTIES OUTPUT_NAME "cryptexd_win32")
else()
    set_target_properties(cryptexd PROPERTIES OUTPUT_NAME "cryptexd_linux")
endif()

target_include_directories(cryptexd PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})
target_compile_definitions(cryptexd PRIVATE BOOST_ERROR_CODE_HEADER_ONLY BOOST_SYSTEM_NO_LIB)
if(WIN32 AND CMAKE_CROSSCOMPILING)
    target_link_libraries(cryptexd PRIVATE ${OPENSSL_LIBRARIES})
else()
    target_link_libraries(cryptexd PRIVATE OpenSSL::SSL OpenSSL::Crypto pthread z)
endif()

add_executable(cryptex_tests
    tests.cpp
    chainparams.cpp
    chat_history.cpp
    chat_secure.cpp
    config.cpp
    debug.cpp
    duckdns.cpp
    block.cpp
    transaction.cpp
    types.cpp
    base64.cpp
    bip39.cpp
    utxo.cpp
    mempool.cpp
    script.cpp
    network.cpp
    rpc.cpp
    block_store.cpp
    blockchain.cpp
    wallet.cpp
)
target_include_directories(cryptex_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})
target_compile_definitions(cryptex_tests PRIVATE BOOST_ERROR_CODE_HEADER_ONLY BOOST_SYSTEM_NO_LIB)
if(WIN32 AND CMAKE_CROSSCOMPILING)
    target_link_libraries(cryptex_tests PRIVATE ${OPENSSL_LIBRARIES})
else()
    target_link_libraries(cryptex_tests PRIVATE OpenSSL::SSL OpenSSL::Crypto pthread z)
endif()
