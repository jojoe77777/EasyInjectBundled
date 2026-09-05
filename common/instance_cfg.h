#pragma once

#include <string>
#include <vector>

namespace InstanceCfg {

inline std::string normalized(const std::string& line) {
    const auto first = line.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    auto text = line.substr(first, line.find_last_not_of(" \t\r\n") - first + 1);
    if (text.compare(0, 3, "\xEF\xBB\xBF") == 0) return normalized(text.substr(3));
    return text;
}

inline std::string key(const std::string& line) {
    const auto text = normalized(line);
    const auto equals = text.find('=');
    return equals == std::string::npos ? "" : normalized(text.substr(0, equals));
}

// Repair legacy entries in other sections as well as installing into General.
inline std::vector<std::string> update(const std::vector<std::string>& lines, const std::string& command) {
    std::vector<std::string> updated;
    size_t insertion = std::string::npos;
    bool hadPreLaunch = false;
    bool hadOverride = false;
    for (const auto& line : lines) {
        const auto name = key(line);
        if (name == "PreLaunchCommand") {
            hadPreLaunch = true;
        } else if (name == "OverrideCommands") {
            hadOverride = true;
        } else {
            updated.push_back(line);
            if (insertion == std::string::npos && normalized(line) == "[General]") {
                insertion = updated.size();
            }
        }
    }

    const bool installing = !normalized(command).empty();
    if (!installing && !hadPreLaunch && !hadOverride) return updated;
    if (insertion == std::string::npos) {
        std::string header = "[General]";
        if (!updated.empty() && updated.front().compare(0, 3, "\xEF\xBB\xBF") == 0) {
            updated.front().erase(0, 3);
            header.insert(0, "\xEF\xBB\xBF");
        }
        updated.insert(updated.begin(), header);
        insertion = 1;
    }
    if (installing || hadPreLaunch) {
        updated.insert(updated.begin() + insertion++, "PreLaunchCommand=" + command);
    }
    if (installing || hadOverride) {
        updated.insert(updated.begin() + insertion, "OverrideCommands=true");
    }
    return updated;
}

} // namespace InstanceCfg
