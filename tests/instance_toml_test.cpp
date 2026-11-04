#include <windows.h>
#include "../common/instance_toml.h"

#include <fstream>
#include <iostream>
#include <stdexcept>

using Lines = std::vector<std::string>;

static void check(const char *name, bool ok) {
    if (!ok)
        throw std::runtime_error(name);
}
static void same(const char *name, const Lines &actual, const Lines &expected) { check(name, actual == expected); }
template <class F> static void rejects(const char *name, F f) {
    bool threw = false;
    try {
        f();
    } catch (const std::exception &) {
        threw = true;
    }
    check(name, threw);
}

int main() {
    namespace fs = std::filesystem;
    try {
        const std::string exe = "\"$INST_MC_DIR/Toolscreen.exe\" --prelaunch";
        const std::string entry = "preLaunch = \"\\\"$INST_MC_DIR/Toolscreen.exe\\\" --prelaunch\"";
        // As Waymark writes it: plain keys, an array over several lines, a blank line, then tables.
        const Lines waymark = {"id = \"speedrun\"", "name = \"1.16.1 RSG\"", "env = [[", "    \"A\",",
                               "    \"b\",", "]]", "", "[loader]", "kind = \"fabric\""};
        const Lines installed = {"id = \"speedrun\"", "name = \"1.16.1 RSG\"", "env = [[", "    \"A\",",
                                 "    \"b\",", "]]", entry, "", "[loader]", "kind = \"fabric\""};
        same("fresh install goes above the first table", InstanceToml::update(waymark, exe), installed);
        same("reinstall is idempotent", InstanceToml::update(installed, exe), installed);
        check("reads back what it wrote", InstanceToml::preLaunchCommand(installed) == exe);
        same("uninstall restores the file", InstanceToml::update(installed, ""), waymark);
        same("uninstall leaves an untouched file alone", InstanceToml::update(waymark, ""), waymark);

        // A line inside a multi-line array can start with "[" without being a table.
        const Lines nested = {"env = [", "    [", "    \"A\",", "    \"b\",", "],", "]", "", "[loader]"};
        same("nested arrays are not tables", InstanceToml::update(nested, exe),
             {"env = [", "    [", "    \"A\",", "    \"b\",", "],", "]", entry, "", "[loader]"});
        check("finds the first real table", InstanceToml::layout(nested).firstTable == 7);

        // Waymark itself may have saved the command as a literal string.
        const Lines literal = {"preLaunch = '\"C:\\Tools\\obs.exe\" --minimize' # mine", "", "[loader]"};
        check("reads literal strings", InstanceToml::preLaunchCommand(literal) == "\"C:\\Tools\\obs.exe\" --minimize");
        same("replaces in place", InstanceToml::update(literal, exe), {entry, "", "[loader]"});
        check("reads escapes", InstanceToml::preLaunchCommand({"preLaunch = \"a\\\\b \\\"c\\\" \\u00e9\""}) ==
                                   "a\\b \"c\" \xC3\xA9");
        check("round-trips control characters",
              InstanceToml::preLaunchCommand(InstanceToml::update({}, "x\ty")) == "x\ty");

        // A key with the same name inside a table belongs to that table.
        const Lines tabled = {"name = \"x\"", "", "[other]", "preLaunch = \"not ours\""};
        check("ignores keys in tables", InstanceToml::preLaunchCommand(tabled).empty());
        same("adds a top-level key even then", InstanceToml::update(tabled, exe),
             {"name = \"x\"", entry, "", "[other]", "preLaunch = \"not ours\""});

        // Strings that look like the end of an array or a table.
        const Lines tricky = {"name = \"[a] ]] # not a comment\"", "jvmArgs = ['[', \"]\"]", "[loader]"};
        same("brackets in strings are text", InstanceToml::update(tricky, exe),
             {"name = \"[a] ]] # not a comment\"", "jvmArgs = ['[', \"]\"]", entry, "[loader]"});
        same("file without tables", InstanceToml::update({"name = \"x\"", ""}, exe), {"name = \"x\"", entry, ""});
        same("empty file", InstanceToml::update({}, exe), {entry});
        same("byte order mark stays first", InstanceToml::update({"\xEF\xBB\xBF[loader]"}, exe),
             {"\xEF\xBB\xBF" + entry, "[loader]"});
        rejects("multi-line commands are left to Waymark",
                [] { InstanceToml::preLaunchCommand({"preLaunch = \"\"\"", "a", "\"\"\""}); });
        rejects("non-strings are refused", [] { InstanceToml::preLaunchCommand({"preLaunch = 3"}); });

        // Only a game folder inside a Waymark instance counts.
        auto root = fs::temp_directory_path() / (L"EasyInject waymark " + std::to_wstring(GetCurrentProcessId()));
        fs::create_directories(root / L"game");
        check("needs the instance files", InstanceToml::waymarkFile(root / L"game").empty());
        std::ofstream(root / L"instance.toml") << "id = \"x\"\n";
        check("needs the lockfile too", InstanceToml::waymarkFile(root / L"game").empty());
        std::ofstream(root / L"waymark.lock") << "";
        check("finds the instance", InstanceToml::waymarkFile(root / L"game") == root / L"instance.toml");
        check("only from the game folder", InstanceToml::waymarkFile(root).empty());
        fs::remove_all(root);

        std::cout << "22 instance.toml regression cases passed\n";
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "instance.toml test failed: " << e.what() << "\n";
        return 1;
    }
}
