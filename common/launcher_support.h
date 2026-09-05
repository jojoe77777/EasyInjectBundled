#pragma once
#include "instance_json.h"
#include "prelaunch.h"
#include <filesystem>
#include <fstream>

namespace LauncherSupport {
inline bool isMcsr(const std::filesystem::path &instance) {
    std::ifstream file(instance / L"instance.json", std::ios::binary);
    if (!file)
        return false;
    try {
        auto root = InstanceJson::Json::parse(file);
        return root.is_object() && root.contains("lwjglVersion") && root["lwjglVersion"].is_object() &&
               root.contains("minecraftVersion") && root.contains("displayName");
    } catch (...) {
        return false;
    }
}
inline bool isAtLauncher(const std::string &command) {
    auto args = Prelaunch::arguments(Prelaunch::lower(command));
    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "com.atlauncher.app")
            return true;
        if (args[i] == "-jar" && i + 1 < args.size()) {
            auto path = args[i + 1];
            auto slash = path.find_last_of("/\\");
            if (path.substr(slash == path.npos ? 0 : slash + 1) == "atlauncher.jar")
                return true;
        }
    }
    return false;
}
inline bool isMinecraft(const std::string &command) {
    auto args = Prelaunch::arguments(Prelaunch::lower(command));
    for (const auto *entry :
         {"org.prismlauncher.entrypoint", "org.multimc.entrypoint", "mojangtricksinteldriversforperformance",
          "net.minecraft.client.main.main", "net.fabricmc.loader.impl.launch.knot.knotclient",
          "net.fabricmc.loader.launch.knot.knotclient", "org.quiltmc.loader.impl.launch.knot.knotclient",
          "net.minecraft.launchwrapper.launch", "cpw.mods.modlauncher.launcher",
          "cpw.mods.bootstraplauncher.bootstraplauncher"}) {
        if (std::find(args.begin(), args.end(), entry) != args.end())
            return true;
    }
    return false;
}
} // namespace LauncherSupport
