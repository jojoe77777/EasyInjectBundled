cmake_minimum_required(VERSION 3.20)
project(ToolscreenDownloaderExe LANGUAGES CXX RC)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

set(BRANDING_FILE "${CMAKE_CURRENT_SOURCE_DIR}/../branding.properties")
set(APP_ICON_FILE "${CMAKE_CURRENT_SOURCE_DIR}/../exe/ts_full.ico")

if(NOT EXISTS "${BRANDING_FILE}")
    message(FATAL_ERROR "branding.properties not found: ${BRANDING_FILE}")
endif()

macro(read_branding_property property_name out_var default_value)
    file(STRINGS "${BRANDING_FILE}" _prop_line REGEX "^[ \t]*${property_name}[ \t]*=" LIMIT_COUNT 1)
    if(_prop_line STREQUAL "")
        set(${out_var} "${default_value}")
    else()
        string(REGEX REPLACE "^[ \t]*${property_name}[ \t]*=[ \t]*" "" _prop_value "${_prop_line}")
        string(STRIP "${_prop_value}" _prop_value)
        if(_prop_value STREQUAL "")
            set(${out_var} "${default_value}")
        else()
            set(${out_var} "${_prop_value}")
        endif()
    endif()
endmacro()

read_branding_property("update.latestReleaseApiUrl" INSTALLER_API_URL "https://api.github.com/repos/jojoe77777/Toolscreen/releases/latest")
read_branding_property("update.releasesUrl" INSTALLER_RELEASES_URL "https://github.com/jojoe77777/Toolscreen/releases")

file(TO_CMAKE_PATH "${APP_ICON_FILE}" APP_ICON_FILE_RC)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/src/config.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/generated_config.h"
    @ONLY
)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/src/app.rc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/app.rc"
    @ONLY
)

add_executable(ToolscreenDownloaderExe WIN32
    src/main.cpp
    "${CMAKE_CURRENT_BINARY_DIR}/app.rc"
)

target_include_directories(ToolscreenDownloaderExe PRIVATE
    "${CMAKE_CURRENT_BINARY_DIR}"
)

set_target_properties(ToolscreenDownloaderExe PROPERTIES
    OUTPUT_NAME "toolscreen-downloader"
)

target_compile_definitions(ToolscreenDownloaderExe PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

target_link_libraries(ToolscreenDownloaderExe PRIVATE
    Comctl32
    Kernel32
    User32
    Winhttp
)