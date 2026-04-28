cmake_minimum_required(VERSION 3.21)

find_package(Qt6 COMPONENTS Widgets Network QUIET)
if(NOT Qt6_FOUND)
    message(STATUS "Qt6 not found; skipping cryptexqt build")
    return()
endif()
find_package(Qt6 COMPONENTS Multimedia MultimediaWidgets QUIET)
if(NOT Qt6Multimedia_FOUND OR NOT Qt6MultimediaWidgets_FOUND)
    message(STATUS "Qt6 Multimedia or MultimediaWidgets not found; skipping cryptexqt build")
    return()
endif()

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

qt_standard_project_setup()

set(CRYPTEXQT_SOURCES
    app/main.cpp
    app/MainWindow.cpp
    app/NodeWindow.cpp
    app/ChatWindow.cpp
    app/MailWindow.cpp
    app/WalletManagerWindow.cpp
    app/DaemonController.cpp
    app/MinerController.cpp
    resources/CryptEX.icns
    rpc/RpcClient.cpp
    views/DashboardPage.cpp
    views/AddressFormatDialog.cpp
    views/SendPage.cpp
    views/ReceivePage.cpp
    views/TransactionsPage.cpp
    views/NetworkGraphPage.cpp
    views/WalletPage.cpp
    views/AudioPreviewWidget.cpp
    views/ChatPage.cpp
    views/ChatEntryDialog.cpp
    views/MediaComposerDialog.cpp
    views/MailAccountCreatePage.cpp
    views/MailComposePage.cpp
    views/MailAccountsPage.cpp
    views/MailEntryDialog.cpp
    views/MailListPage.cpp
    views/MailSecurityPage.cpp
    views/VoiceCallPage.cpp
    views/ForumPage.cpp
    views/PrivateContactsPage.cpp
    views/PrivateHistoryPage.cpp
    views/PublicDirectoryPage.cpp
    views/ChatProxyPage.cpp
    views/IrcPage.cpp
    views/MiningPage.cpp
    views/RpcConsolePage.cpp
    views/TerminalPage.cpp
)

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    list(APPEND CRYPTEXQT_SOURCES
        platform/SpeechTranscriber_mac.mm
        platform/VideoThumbnailer_mac.mm)
else()
    list(APPEND CRYPTEXQT_SOURCES
        platform/SpeechTranscriber.cpp
        platform/VideoThumbnailer.cpp)
endif()

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

target_link_libraries(cryptexqt PRIVATE Qt6::Widgets Qt6::Network Qt6::Multimedia Qt6::MultimediaWidgets)

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    find_library(SPEECH_FRAMEWORK Speech)
    find_library(FOUNDATION_FRAMEWORK Foundation)
    find_library(AVFOUNDATION_FRAMEWORK AVFoundation)
    find_library(COREMEDIA_FRAMEWORK CoreMedia)
    find_library(COREGRAPHICS_FRAMEWORK CoreGraphics)
    if(SPEECH_FRAMEWORK)
        target_link_libraries(cryptexqt PRIVATE ${SPEECH_FRAMEWORK})
    endif()
    if(FOUNDATION_FRAMEWORK)
        target_link_libraries(cryptexqt PRIVATE ${FOUNDATION_FRAMEWORK})
    endif()
    if(AVFOUNDATION_FRAMEWORK)
        target_link_libraries(cryptexqt PRIVATE ${AVFOUNDATION_FRAMEWORK})
    endif()
    if(COREMEDIA_FRAMEWORK)
        target_link_libraries(cryptexqt PRIVATE ${COREMEDIA_FRAMEWORK})
    endif()
    if(COREGRAPHICS_FRAMEWORK)
        target_link_libraries(cryptexqt PRIVATE ${COREGRAPHICS_FRAMEWORK})
    endif()
endif()

if(TARGET cryptexd)
    add_dependencies(cryptexqt cryptexd)
endif()
if(TARGET cryptex_powminer)
    add_dependencies(cryptexqt cryptex_powminer)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin" AND TARGET cryptexd AND TARGET cryptex_powminer)
    set_property(TARGET cryptexqt APPEND PROPERTY LINK_DEPENDS
        $<TARGET_FILE:cryptexd>
        $<TARGET_FILE:cryptex_powminer>)
    add_custom_command(
        TARGET cryptexqt POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory
            $<TARGET_BUNDLE_CONTENT_DIR:cryptexqt>/MacOS
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:cryptexd>
            $<TARGET_BUNDLE_CONTENT_DIR:cryptexqt>/MacOS/$<TARGET_FILE_NAME:cryptexd>
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:cryptex_powminer>
            $<TARGET_BUNDLE_CONTENT_DIR:cryptexqt>/MacOS/$<TARGET_FILE_NAME:cryptex_powminer>
        VERBATIM)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    install(TARGETS cryptexqt BUNDLE DESTINATION ".")
elseif(WIN32)
    install(TARGETS cryptexqt RUNTIME DESTINATION ".")
else()
    install(TARGETS cryptexqt RUNTIME DESTINATION "bin")
endif()
