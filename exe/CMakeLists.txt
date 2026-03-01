cmake_minimum_required(VERSION 3.20)
project(EasyInjectExe LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Statically link the MSVC runtime so the exe has no CRT DLL dependencies
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_executable(EasyInjectExe
    src/main.cpp
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

# Copy branding.properties from project root and DLLs from custom-dlls/
add_custom_command(TARGET EasyInjectExe POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory $<TARGET_FILE_DIR:EasyInjectExe>/dlls
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_SOURCE_DIR}/../branding.properties $<TARGET_FILE_DIR:EasyInjectExe>/branding.properties
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_SOURCE_DIR}/../custom-dlls $<TARGET_FILE_DIR:EasyInjectExe>/dlls
)
