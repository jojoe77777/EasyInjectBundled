#pragma once
#include "../third_party/nlohmann/json.hpp"

namespace InstanceJson {
using Json = nlohmann::ordered_json;

inline Json parse(const std::string& text) {
    auto root = Json::parse(text);
    if (!root.is_object()) throw std::runtime_error("Instance JSON must be an object");
    if (root.contains("launcher") && !root["launcher"].is_object())
        throw std::runtime_error("Instance JSON launcher must be an object");
    return root;
}

inline std::string preLaunchCommand(const Json& root) {
    if (!root.contains("launcher")) return {};
    const auto& launcher = root["launcher"];
    if (!launcher.contains("preLaunchCommand") || launcher["preLaunchCommand"].is_null()) return {};
    return launcher["preLaunchCommand"].get<std::string>();
}

inline std::string update(Json root, const std::string& command) {
    const bool installing = !command.empty();
    if (installing && !root.contains("launcher")) root["launcher"] = Json::object();
    if (root.contains("launcher")) {
        auto& launcher = root["launcher"];
        if (installing || launcher.contains("preLaunchCommand")) launcher["preLaunchCommand"] = command;
        if (installing) launcher["enableCommands"] = true;
    }
    return root.dump(4) + "\n";
}
}
