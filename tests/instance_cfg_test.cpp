#include "../common/instance_cfg.h"

#include <iostream>
#include <stdexcept>

using Lines = std::vector<std::string>;

static void check(const char* name, const Lines& actual, const Lines& expected) {
    if (actual != expected) throw std::runtime_error(name);
}

int main() {
    try {
        const std::string command = "\\\"$INST_DIR/Toolscreen.exe\\\" --prelaunch";
        const std::string pre = "PreLaunchCommand=" + command;
        const std::string enable = "OverrideCommands=true";
        const Lines fresh = {"[General]", "name=1.16.1", "JavaRealArchitecture=aarch64", "", "[UI]", "layout=saved"};
        check("fresh install with trailing UI", InstanceCfg::update(fresh, command),
            {"[General]", pre, enable, "name=1.16.1", "JavaRealArchitecture=aarch64", "", "[UI]", "layout=saved"});
        const Lines broken = {"[General]", "name=1.16.1", "[UI]", "PreLaunchCommand=old",
            "OverrideCommands=false", "layout=saved", "PreLaunchCommand=duplicate", enable};
        const Lines repaired = {"[General]", pre, enable, "name=1.16.1", "[UI]", "layout=saved"};
        check("repair misplaced duplicates", InstanceCfg::update(broken, command), repaired);
        check("reinstall is idempotent", InstanceCfg::update(repaired, command), repaired);
        check("General after UI", InstanceCfg::update({"[UI]", "PreLaunchCommand=old", "[General]", "name=instance"}, command),
            {"[UI]", "[General]", pre, enable, "name=instance"});
        check("sectionless config", InstanceCfg::update({"name=legacy"}, command),
            {"[General]", pre, enable, "name=legacy"});
        check("missing General", InstanceCfg::update({"[UI]", "layout=saved"}, command),
            {"[General]", pre, enable, "[UI]", "layout=saved"});
        check("empty config", InstanceCfg::update({}, command), {"[General]", pre, enable});
        check("BOM and whitespace", InstanceCfg::update({"\xEF\xBB\xBF[General]", "; comment", " PreLaunchCommand =old",
            " OverrideCommands =false", "[UI]"}, command), {"\xEF\xBB\xBF[General]", pre, enable, "; comment", "[UI]"});
        check("sectionless BOM", InstanceCfg::update({"\xEF\xBB\xBFname=legacy"}, command),
            {"\xEF\xBB\xBF[General]", pre, enable, "name=legacy"});
        check("uninstall repairs misplaced keys", InstanceCfg::update(broken, ""),
            {"[General]", "PreLaunchCommand=", enable, "name=1.16.1", "[UI]", "layout=saved"});
        check("uninstall untouched config", InstanceCfg::update(fresh, ""), fresh);
        std::cout << "11 instance.cfg regression cases passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Failed: " << error.what() << '\n';
        return 1;
    }
}
