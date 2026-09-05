cmake_minimum_required(VERSION 3.20)
project(EasyInjectExe LANGUAGES CXX RC)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    set(EASYINJECT_STANDALONE_DEFAULT ON)
else()
    set(EASYINJECT_STANDALONE_DEFAULT OFF)
endif()
option(EASYINJECT_BUILD_REDUCED_AV_HEURISTICS
    "Build the reduced-antivirus-heuristics native installer"
    ${EASYINJECT_STANDALONE_DEFAULT})
option(EASYINJECT_ENABLE_PACKAGING_TESTS
    "Register EasyInject packaging inspection tests"
    ${EASYINJECT_STANDALONE_DEFAULT})

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Statically link the MSVC runtime so the exe has no CRT DLL dependencies
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

set(BRANDING_FILE "${CMAKE_CURRENT_SOURCE_DIR}/../branding.properties")
set(LOGGER_DLL_FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/main/resources/dlls/liblogger_x64.dll"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/main/resources/dlls/liblogger_arm64.dll"
)
set(APP_ICON_FILE "${CMAKE_CURRENT_SOURCE_DIR}/ts_full.ico")
set(BRANDING_RESOURCE_ID 101)
set(DLL_INDEX_RESOURCE_ID 102)
set(CUSTOM_DLL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../custom-dlls")
file(GLOB CUSTOM_DLL_FILES CONFIGURE_DEPENDS
    "${CUSTOM_DLL_DIR}/*.dll"
    "${CUSTOM_DLL_DIR}/*.DLL"
)
file(GLOB CUSTOM_SUPPORT_RESOURCE_FILES CONFIGURE_DEPENDS
    "${CUSTOM_DLL_DIR}/*.json"
    "${CUSTOM_DLL_DIR}/*.JSON"
)
set(ARCHITECTURE_PAYLOAD_FILES
    "${CUSTOM_DLL_DIR}/Toolscreen_x64.dll"
    "${CUSTOM_DLL_DIR}/Toolscreen_arm64.dll"
)
# A stale unsuffixed payload would overwrite the selected architecture at
# extraction time, so universal packages never embed it.
list(FILTER CUSTOM_DLL_FILES EXCLUDE REGEX "[/\\\\]Toolscreen[.]dll$")

if(NOT EXISTS "${BRANDING_FILE}")
    message(FATAL_ERROR "branding.properties not found: ${BRANDING_FILE}")
endif()

if(NOT EXISTS "${APP_ICON_FILE}")
    message(FATAL_ERROR "Application icon not found: ${APP_ICON_FILE}")
endif()

file(STRINGS "${BRANDING_FILE}" BRAND_VERSION_LINE REGEX "^[ \t]*brand\\.version[ \t]*=" LIMIT_COUNT 1)
file(STRINGS "${BRANDING_FILE}" BRAND_NAME_LINE REGEX "^[ \t]*brand\\.name[ \t]*=" LIMIT_COUNT 1)
if(BRAND_NAME_LINE STREQUAL "")
    message(FATAL_ERROR "brand.name not found in ${BRANDING_FILE}")
endif()
string(REGEX REPLACE "^[ \t]*brand\\.name[ \t]*=[ \t]*" "" BRAND_NAME "${BRAND_NAME_LINE}")
string(STRIP "${BRAND_NAME}" BRAND_NAME)
if(BRAND_NAME STREQUAL "")
    message(FATAL_ERROR "brand.name is empty in ${BRANDING_FILE}")
endif()

if(BRAND_VERSION_LINE STREQUAL "")
    message(FATAL_ERROR "brand.version not found in ${BRANDING_FILE}")
endif()

string(REGEX REPLACE "^[ \t]*brand\\.version[ \t]*=[ \t]*" "" BRAND_VERSION "${BRAND_VERSION_LINE}")
string(STRIP "${BRAND_VERSION}" BRAND_VERSION)
if(BRAND_VERSION STREQUAL "")
    message(FATAL_ERROR "brand.version is empty in ${BRANDING_FILE}")
endif()

set(EMBED_DLL_FILES)
set(_seen_dll_names)

macro(append_embed_dll file_path)
    get_filename_component(_dll_name "${file_path}" NAME)
    string(TOLOWER "${_dll_name}" _dll_name_lc)
    list(FIND _seen_dll_names "${_dll_name_lc}" _seen_idx)
    if(_seen_idx EQUAL -1)
        list(APPEND EMBED_DLL_FILES "${file_path}")
        list(APPEND _seen_dll_names "${_dll_name_lc}")
    endif()
endmacro()

foreach(_logger IN LISTS LOGGER_DLL_FILES)
    append_embed_dll("${_logger}")
endforeach()
foreach(_payload IN LISTS ARCHITECTURE_PAYLOAD_FILES)
    append_embed_dll("${_payload}")
endforeach()
foreach(_dll IN LISTS CUSTOM_DLL_FILES)
    append_embed_dll("${_dll}")
endforeach()
foreach(_resource IN LISTS CUSTOM_SUPPORT_RESOURCE_FILES)
    append_embed_dll("${_resource}")
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
file(TO_CMAKE_PATH "${APP_ICON_FILE}" APP_ICON_FILE_RC)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/src/embedded_resources.rc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/embedded_resources.rc"
    @ONLY
)

function(configure_installer_target target output_name)
    add_executable(${target} WIN32
        src/main.cpp
        "${CMAKE_CURRENT_BINARY_DIR}/embedded_resources.rc"
    )
    set_target_properties(${target} PROPERTIES OUTPUT_NAME "${output_name}")
    target_compile_definitions(${target} PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX ${ARGN})
    if(MSVC)
        target_link_options(${target} PRIVATE /Brepro)
    endif()
    target_link_libraries(${target} PRIVATE
        Advapi32 Bcrypt Kernel32 Ntdll Psapi Shell32 Shlwapi User32 Winhttp Comctl32
    )
endfunction()

# Existing compatibility target and filename remain unchanged.
configure_installer_target(EasyInjectExe "${BRAND_NAME}-${BRAND_VERSION}-double-click-me")

# Compile-time policy target: compatibility-only code and strings are not linked.
if(EASYINJECT_BUILD_REDUCED_AV_HEURISTICS)
    configure_installer_target(installer_exe_reduced_av_heuristics
        "${BRAND_NAME}-${BRAND_VERSION}-double-click-me-reduced-av-heuristics"
        EASYINJECT_REDUCED_AV_HEURISTICS=1)
endif()

include(CTest)
if(BUILD_TESTING)
    add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../tests" "instance-cfg-tests")
endif()
if(BUILD_TESTING AND EASYINJECT_ENABLE_PACKAGING_TESTS AND TARGET installer_exe_reduced_av_heuristics)
    add_test(NAME reduced_av_heuristics_artifact_inspection
        COMMAND powershell -NoProfile -ExecutionPolicy RemoteSigned -File
            "${CMAKE_CURRENT_SOURCE_DIR}/../tests/verify-packaging.ps1"
            -RepositoryRoot "${CMAKE_CURRENT_SOURCE_DIR}/.."
            -ReducedExe "$<TARGET_FILE:installer_exe_reduced_av_heuristics>"
            -CompatibilityExe "$<TARGET_FILE:EasyInjectExe>")
endif()
