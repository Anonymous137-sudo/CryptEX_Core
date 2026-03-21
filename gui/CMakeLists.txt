cmake_minimum_required(VERSION 3.21)

find_package(Qt6 COMPONENTS Widgets Network QUIET)
if(NOT Qt6_FOUND)
    message(STATUS "Qt6 not found; skipping cryptexqt build")
    return()
endif()

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

qt_standard_project_setup()

set(CRYPTEXQT_SOURCES
    app/main.cpp
    app/MainWindow.cpp
    app/DaemonController.cpp
    app/MinerController.cpp
    resources/CryptEX.icns
    rpc/RpcClient.cpp
    views/DashboardPage.cpp
    views/NetworkGraphPage.cpp
    views/WalletPage.cpp
    views/ChatPage.cpp
    views/MiningPage.cpp
    views/RpcConsolePage.cpp
    views/TerminalPage.cpp
)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    list(APPEND CRYPTEXQT_SOURCES resources/CryptEX.rc)
endif()

qt_add_executable(cryptexqt
    ${CRYPTEXQT_SOURCES}
    resources/branding.qrc
)

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set_source_files_properties(resources/CryptEX.icns PROPERTIES MACOSX_PACKAGE_LOCATION "Resources")
    set_target_properties(cryptexqt PROPERTIES
        OUTPUT_NAME "cryptexqt_osx"
        MACOSX_BUNDLE TRUE
        MACOSX_BUNDLE_BUNDLE_NAME "CryptEX Qt"
        MACOSX_BUNDLE_GUI_IDENTIFIER "org.cryptex.qt"
        MACOSX_BUNDLE_ICON_FILE "CryptEX.icns")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set_target_properties(cryptexqt PROPERTIES OUTPUT_NAME "cryptexqt_win32")
else()
    set_target_properties(cryptexqt PROPERTIES OUTPUT_NAME "cryptexqt_linux")
endif()

target_include_directories(cryptexqt PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/app
    ${CMAKE_CURRENT_SOURCE_DIR}/rpc
    ${CMAKE_CURRENT_SOURCE_DIR}/views
)

target_link_libraries(cryptexqt PRIVATE Qt6::Widgets Qt6::Network)

if(TARGET cryptexd)
    add_dependencies(cryptexqt cryptexd)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin" AND TARGET cryptexd)
    add_custom_command(TARGET cryptexqt POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:cryptexd>
            $<TARGET_BUNDLE_CONTENT_DIR:cryptexqt>/MacOS/$<TARGET_FILE_NAME:cryptexd>
        VERBATIM)
endif()
