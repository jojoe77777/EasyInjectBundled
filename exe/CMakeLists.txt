cmake_minimum_required(VERSION 3.20)
project(EasyInjectExe LANGUAGES CXX RC)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Statically link the MSVC runtime so the exe has no CRT DLL dependencies
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

set(BRANDING_FILE "${CMAKE_CURRENT_SOURCE_DIR}/../branding.properties")
set(LOGGER_DLL_FILE "${CMAKE_CURRENT_SOURCE_DIR}/../src/main/resources/dlls/liblogger_x64.dll")
set(BRANDING_RESOURCE_ID 101)
set(DLL_INDEX_RESOURCE_ID 102)
set(CUSTOM_DLL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../custom-dlls")
file(GLOB CUSTOM_DLL_FILES CONFIGURE_DEPENDS
    "${CUSTOM_DLL_DIR}/*.dll"
    "${CUSTOM_DLL_DIR}/*.DLL"
)

if(NOT EXISTS "${BRANDING_FILE}")
    message(FATAL_ERROR "branding.properties not found: ${BRANDING_FILE}")
endif()

if(NOT EXISTS "${LOGGER_DLL_FILE}")
    message(FATAL_ERROR "liblogger_x64.dll not found: ${LOGGER_DLL_FILE}")
endif()

set(EMBED_DLL_FILES)
set(_seen_dll_names)

macro(append_embed_dll file_path)
    if(EXISTS "${file_path}")
        get_filename_component(_dll_name "${file_path}" NAME)
        string(TOLOWER "${_dll_name}" _dll_name_lc)
        list(FIND _seen_dll_names "${_dll_name_lc}" _seen_idx)
        if(_seen_idx EQUAL -1)
            list(APPEND EMBED_DLL_FILES "${file_path}")
            list(APPEND _seen_dll_names "${_dll_name_lc}")
        endif()
    endif()
endmacro()

append_embed_dll("${LOGGER_DLL_FILE}")
foreach(_dll IN LISTS CUSTOM_DLL_FILES)
    append_embed_dll("${_dll}")
endforeach()

set(EMBED_DLL_INDEX_FILE "${CMAKE_CURRENT_BINARY_DIR}/embedded_dll_index.txt")
set(EMBED_DLL_RESOURCE_LINES "")
set(_embed_dll_index_content "")
set(_embed_dll_counter 0)

foreach(_dll IN LISTS EMBED_DLL_FILES)
    math(EXPR _embed_dll_counter "${_embed_dll_counter} + 1")
    math(EXPR _res_id "1000 + ${_embed_dll_counter}")
    get_filename_component(_dll_name "${_dll}" NAME)
    file(TO_CMAKE_PATH "${_dll}" _dll_rc_path)

    string(APPEND _embed_dll_index_content "${_res_id}|${_dll_name}\n")
    string(APPEND EMBED_DLL_RESOURCE_LINES "${_res_id} RCDATA \"${_dll_rc_path}\"\n")
endforeach()

file(WRITE "${EMBED_DLL_INDEX_FILE}" "${_embed_dll_index_content}")

file(TO_CMAKE_PATH "${BRANDING_FILE}" BRANDING_FILE_RC)
file(TO_CMAKE_PATH "${EMBED_DLL_INDEX_FILE}" EMBED_DLL_INDEX_FILE_RC)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/src/embedded_resources.rc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/embedded_resources.rc"
    @ONLY
)

add_executable(EasyInjectExe
    src/main.cpp
    "${CMAKE_CURRENT_BINARY_DIR}/embedded_resources.rc"
)

target_compile_definitions(EasyInjectExe PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

target_link_libraries(EasyInjectExe PRIVATE
    Advapi32
    Bcrypt
    Kernel32
    Ntdll
    Psapi
    Shell32
    Shlwapi
    User32
    Winhttp
    Comctl32
)
