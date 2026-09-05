// Exercise the real native frontends and Windows process argument transport.
#define wmain installerEntryForTest
#define wWinMain installerWindowsEntryForTest
#if defined(TEST_LITE_INSTALLER)
#include "../exe-lite/src/main.cpp"
#else
#include "../exe/src/main.cpp"
#endif
#undef wmain
#undef wWinMain

static void require(bool value, const char *message) {
    if (!value)
        throw std::runtime_error(message);
}
static std::string contents(const fs::path &file) {
    std::ifstream in(file, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in), {});
}

template <class F> static void withClicks(HDESK desktop, const std::vector<std::wstring> &buttons, F operation) {
    bool clicked = true;
    std::thread automation([&] {
        if (!SetThreadDesktop(desktop)) {
            clicked = false;
            return;
        }
        for (const auto &label : buttons) {
            HWND button = nullptr;
            for (int i = 0; i < 200 && !button; ++i) {
                HWND dialog = FindWindowW(L"EasyInject.DarkDialog", nullptr);
                if (dialog && (GetWindowLongPtrW(dialog, GWL_STYLE) & WS_VISIBLE))
                    button = FindWindowExW(dialog, nullptr, L"Button", label.c_str());
                if (!button)
                    Sleep(25);
            }
            if (!button) {
                clicked = false;
                return;
            }
            DWORD_PTR result = 0;
            if (!SendMessageTimeoutW(button, BM_CLICK, 0, 0, SMTO_ABORTIFHUNG, 5000, &result)) {
                clicked = false;
                return;
            }
            Sleep(50);
        }
    });
    try {
        operation();
    } catch (...) {
        automation.join();
        throw;
    }
    automation.join();
    require(clicked, "UI automation failed");
}

int main() {
    int argc = 0;
    auto argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (hasArg(argc, argv, L"--chain-test")) {
        bool result = runForwardedPreLaunchChain(argc, argv);
        LocalFree(argv);
        return result ? 0 : 1;
    }
    LocalFree(argv);
    auto root = fs::temp_directory_path() /
                (L"EasyInject native frontend \u914d\u7f6e " + std::to_wstring(GetCurrentProcessId()));
    HDESK original = GetThreadDesktop(GetCurrentThreadId());
    HDESK desktop = CreateDesktopW((L"EasyInject-frontend-" + std::to_wstring(GetCurrentProcessId())).c_str(), nullptr,
                                   nullptr, 0, GENERIC_ALL, nullptr);
    HANDLE finished = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    std::thread watchdog([&] {
        if (WaitForSingleObject(finished, 60000) == WAIT_TIMEOUT)
            TerminateProcess(GetCurrentProcess(), 2);
    });
    int exitCode = 0;
    try {
        require(desktop && SetThreadDesktop(desktop), "private desktop");
        g_projectName = "Toolscreen";
        g_version = "test";
        fs::create_directories(root);
        auto child = root / L"chain runner.exe";
        fs::copy_file(getExePath(), child);
        auto run = [&](const std::string &chain) {
            auto result = ProcessCapture::run(L"\"" + child.wstring() + L"\" --chain-test --run-prelaunch-chain-hex " +
                                                  toWide(Prelaunch::hex(chain)),
                                              10000);
            if (result.exitCode)
                std::cerr << result.output;
            return result.exitCode;
        };
        // A quoted script path plus arguments, real shell redirection and instance cwd.
        ConfigFile::write(root / L"helper script.cmd", "@echo off\r\necho %1>\"first marker.txt\"\r\n");
        ConfigFile::write(root / L"prelaunch.txt", "# comment\r\n; comment\r\n// comment\r\nif not exist \"first "
                                                   "marker.txt\" exit /b 7\r\necho second>\"second marker.txt\"\r\n");
        require(run("\"" + (root / L"helper script.cmd").u8string() + "\" \"a & b\"") == 0,
                "quoted script through native forwarding");
        require(contents(root / L"first marker.txt").find("a & b") != std::string::npos &&
                    fs::exists(root / L"second marker.txt"),
                "forwarded chain runs before prelaunch.txt");
        auto variableChain =
            Prelaunch::merge("\"$INST_DIR/helper script.cmd\" \"from variable\"", "test --prelaunch", "Toolscreen")
                .keep;
        auto flag = variableChain.find(" --run-prelaunch-chain-hex");
        auto transported = variableChain.substr(flag);
        auto placeholder = transported.find("$INST_DIR");
        transported.replace(placeholder, 9, root.u8string());
        require(
            ProcessCapture::run(L"\"" + child.wstring() + L"\" --chain-test" + toWide(transported), 10000).exitCode ==
                0,
            "launcher-expanded path reaches encoded chain");
        require(contents(root / L"first marker.txt").find("from variable") != std::string::npos,
                "expanded path executed");
        fs::remove(root / L"second marker.txt");
        require(run("exit /b 7") == 1 && !fs::exists(root / L"second marker.txt"),
                "failed forwarded command aborts text chain");
        require(
            ProcessCapture::run(L"\"" + child.wstring() + L"\" --chain-test --run-prelaunch-chain-hex invalid", 10000)
                    .exitCode == 1,
            "invalid transport fails");
        ConfigFile::write(root / L"prelaunch.txt", "exit /b 9\r\necho unwanted>never.txt\r\n");
        require(run("echo harmless>\"first marker.txt\"") == 1 && !fs::exists(root / L"never.txt"),
                "text-chain failure stops later commands");
        auto cfg = root / L"instance.cfg";
        const std::string originalConfig = "[General]\r\nPreLaunchCommand=echo existing\r\n[UI]\r\nsentinel=yes\r\n";
        auto command = InstanceConfig::buildPreLaunchCommand("Toolscreen.exe");
        ConfigFile::write(cfg, originalConfig);
        withClicks(desktop, {L"Cancel"}, [&] {
            require(!InstanceConfig::installPreLaunchCommandCfg(cfg, command).success, "cancel status");
        });
        require(contents(cfg) == originalConfig, "cancel leaves original bytes");
        withClicks(desktop, {L"Keep Existing"}, [&] {
            require(InstanceConfig::installPreLaunchCommandCfg(cfg, command).success, "keep installation");
        });
        auto installed = contents(cfg);
        require(installed.find("--run-prelaunch-chain-hex") != installed.npos &&
                    installed.find("sentinel=yes") != installed.npos,
                "installed forwarder and UI settings");
        require(InstanceConfig::installPreLaunchCommandCfg(cfg, command).success && contents(cfg) == installed,
                "actual reinstall idempotence");
        ConfigFile::write(cfg, originalConfig);
        withClicks(desktop, {L"Replace Command"}, [&] {
            require(InstanceConfig::installPreLaunchCommandCfg(cfg, command).success, "replace installation");
        });
        require(contents(cfg).find("--run-prelaunch-chain") == std::string::npos, "replace removes old command");
        // Actual Modrinth install and uninstall flow, including success/confirmation dialogs.
        auto instance = root / "profiles" / "game";
        fs::create_directories(instance);
        sqlite3 *db = nullptr;
        require(sqlite3_open((root / "app.db").u8string().c_str(), &db) == SQLITE_OK, "fixture database");
        require(sqlite3_exec(db,
                             "CREATE TABLE profiles(path TEXT PRIMARY KEY,override_hook_pre_launch TEXT); INSERT INTO "
                             "profiles VALUES('game',NULL);",
                             nullptr, nullptr, nullptr) == SQLITE_OK,
                "fixture schema");
        sqlite3_close(db);
        withClicks(desktop, {L"Done"}, [&] {
            require(installModrinth(instance, instance / L"Toolscreen.exe") == 0, "Modrinth install frontend");
        });
        {
            Modrinth::Database verify(root / "app.db");
            Modrinth::Statement q(verify, "SELECT override_hook_pre_launch FROM profiles");
            require(q.row() && q.text(0) == "\"" + (instance / L"Toolscreen.exe").u8string() + "\" --prelaunch",
                    "absolute native Modrinth hook");
        }
        withClicks(desktop, {L"Uninstall", L"Uninstall", L"Done"}, [&] {
            require(installModrinth(instance, instance / L"Toolscreen.exe") == 0, "Modrinth uninstall frontend");
        });
        {
            Modrinth::Database verify(root / "app.db");
            Modrinth::Statement q(verify, "SELECT override_hook_pre_launch IS NULL FROM profiles");
            require(q.row() && q.text(0) == "1", "uninstall clears hook");
        }
        fs::remove_all(root);
        std::cout << "PASS: native forwarding processes, failure ordering, keep/replace/cancel/reinstall UI, Modrinth "
                     "install/uninstall UI\n";
    } catch (const std::exception &e) {
        std::cerr << "FAIL: " << e.what() << "; fixtures at " << root.u8string() << '\n';
        exitCode = 1;
    }
    SetEvent(finished);
    watchdog.join();
    CloseHandle(finished);
    SetThreadDesktop(original);
    if (desktop)
        CloseDesktop(desktop);
    return exitCode;
}
