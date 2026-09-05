#define NOMINMAX
#include "../common/instance_json.h"
#include "../common/config_file.h"
#include "../common/process_capture.h"
#include <iostream>
#include <chrono>

static void require(bool pass, const char* message) { if (!pass) throw std::runtime_error(message); }
int main(int argc, char**) {
    if (argc > 1) { Sleep(30000); return 0; }
    try {
        const std::string command = "\"$INST_DIR/a b.exe\" --prelaunch\\path\nnext";
        auto root = InstanceJson::parse(R"({"preLaunchCommand":"outside","other":{"enableCommands":false},"launcher":{"memory":4096,"preLaunchCommand":"old"}})");
        auto updated = InstanceJson::parse(InstanceJson::update(root, command));
        require(InstanceJson::preLaunchCommand(updated) == command, "JSON command round trip");
        require(updated["other"] == root["other"] && updated["preLaunchCommand"] == "outside", "JSON scope");
        require(updated["launcher"]["memory"] == 4096 && updated["launcher"]["enableCommands"] == true, "JSON preserve settings");
        require(InstanceJson::parse(InstanceJson::update(updated, command)) == updated, "reinstall idempotence");
        for (const auto* text : {"{}", "{\"launcher\":{}}"})
            require(InstanceJson::preLaunchCommand(InstanceJson::parse(InstanceJson::update(InstanceJson::parse(text), command))) == command, "missing launcher");
        auto removed = InstanceJson::parse(InstanceJson::update(updated, ""));
        require(InstanceJson::preLaunchCommand(removed).empty() && removed["other"] == root["other"], "uninstall preservation");
        for (const auto* text : {"[]", "null", "{", "{\"launcher\":null}", "{\"launcher\":[]}", "{\"launcher\":{},}", "{} junk"}) {
            bool rejected = false;
            try { InstanceJson::parse(text); } catch (const std::exception&) { rejected = true; }
            require(rejected, "invalid JSON accepted");
        }
        namespace fs = std::filesystem;
        const auto dir = fs::temp_directory_path() / (L"EasyInject tests " + std::to_wstring(GetCurrentProcessId()));
        fs::create_directories(dir);
        const auto path = dir / L"\u914d\u7f6e.cfg";
        ConfigFile::write(path, "original");
        SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_READONLY);
        bool rejected = false;
        try { ConfigFile::write(path, "replacement"); } catch (const std::exception&) { rejected = true; }
        require(rejected, "read-only write reported success");
        std::ifstream original(path); std::string content; original >> content; original.close();
        require(content == "original", "failed write damaged original");
        SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_NORMAL);
        ConfigFile::write(path, "replacement");
        require(std::distance(fs::directory_iterator(dir), fs::directory_iterator{}) == 1, "temporary file leaked");
        fs::remove(path); fs::remove(dir);
        auto captured = ProcessCapture::run(L"cmd.exe /d /c \"for /L %i in (1,1,5000) do @echo capture-output\"", 30000);
        require(captured.exitCode == 0 && captured.output.size() > 60000, "pipe drain");
        require(ProcessCapture::run(L"cmd.exe /d /c exit /b 7").exitCode == 7, "exit code");
        wchar_t self[32768]; GetModuleFileNameW(nullptr, self, 32768);
        auto start = GetTickCount64();
        require(ProcessCapture::run(L"\"" + std::wstring(self) + L"\" --sleep", 250).exitCode == 124, "timeout exit code");
        require(GetTickCount64() - start < 8000, "timeout blocked on read");
        std::cout << "PASS: JSON scope/roundtrip/reinstall/uninstall/invalid input, Unicode atomic writes, read-only failure, pipe draining, exit codes, timeout\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n'; return 1;
    }
}
