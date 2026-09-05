#pragma once
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace ConfigFile {
inline void write(const std::filesystem::path& path, const std::string& text) {
    wchar_t temporary[MAX_PATH];
    if (!GetTempFileNameW(path.parent_path().wstring().c_str(), L"eic", 0, temporary))
        throw std::runtime_error("Cannot create temporary config file");
    try {
        std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
        output.exceptions(std::ios::badbit | std::ios::failbit);
        output.write(text.data(), static_cast<std::streamsize>(text.size()));
        output.close();
        if (!MoveFileExW(temporary, path.wstring().c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
            throw std::runtime_error("Cannot replace config file (Windows error " + std::to_string(GetLastError()) + ")");
    } catch (...) {
        DeleteFileW(temporary);
        throw;
    }
}
inline void writeLines(const std::filesystem::path& path, const std::vector<std::string>& lines) {
    std::string text;
    for (const auto& line : lines) text += line + "\r\n";
    write(path, text);
}
}
