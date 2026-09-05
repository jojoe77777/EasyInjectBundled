#pragma once
// Included after the frontend's InstanceConfig and shared success dialog.
static std::vector<fs::path> modrinthDatabases() {
    std::vector<fs::path> paths;
    for (const auto *name : {L"THESEUS_CONFIG_DIR", L"APPDATA", L"LOCALAPPDATA"}) {
        DWORD length = GetEnvironmentVariableW(name, nullptr, 0);
        if (!length)
            continue;
        std::wstring value(length, L'\0');
        DWORD read = GetEnvironmentVariableW(name, value.data(), length);
        if (!read || read >= length)
            continue;
        value.resize(read);
        if (std::wstring(name) == L"THESEUS_CONFIG_DIR")
            paths.push_back(fs::path(value) / L"app.db");
        else
            for (const auto *folder : {L"com.modrinth.theseus", L"ModrinthApp"})
                paths.push_back(fs::path(value) / folder / L"app.db");
    }
    return paths;
}
static void showMcsrManagedWarning() {
    for (;;) {
        int choice =
            Ui::showDialog(L"MCSR Launcher Detected",
                           L"This instance is managed by MCSR Launcher.\n\nEnable Toolscreen in Edit instance > Tools "
                           L"instead of installing it manually.",
                           Ui::DialogTone::Warning,
                           {{IDYES, L"Toolscreen"}, {IDNO, L"MCSR Ranked"}, {IDCANCEL, L"Close", true}}, IDCANCEL);
        if (choice != IDYES && choice != IDNO)
            return;
        ShellExecuteW(nullptr, L"open",
                      choice == IDYES ? L"https://discord.gg/A2v6bCJg6K" : L"https://discord.mcsrranked.com/", nullptr,
                      nullptr, SW_SHOWNORMAL);
    }
}
static std::optional<int> installModrinth(const fs::path &instanceDir, const fs::path &stableExe) {
    try {
        auto profile = Modrinth::detect(instanceDir, modrinthDatabases());
        if (!profile)
            return {};
        auto isOurs = [](const std::string &value) { return Prelaunch::isOurs(value, g_projectName); };
        Modrinth::update(*profile, "\"" + stableExe.u8string() + "\" --prelaunch", isOurs);
        InstanceConfig::ensurePrelaunchTxtExists(instanceDir);
        showInstallSuccessDialogWithUninstall({}, instanceDir, [profile, isOurs] {
            try {
                Modrinth::update(*profile, std::nullopt, isOurs);
                return InstanceConfig::InstallResult{true, ""};
            } catch (const std::exception &e) {
                return InstanceConfig::InstallResult{false, e.what()};
            }
        });
        return 0;
    } catch (const std::exception &e) {
        Ui::showDialog(toWide(g_projectName + " — Installation Failed"),
                       toWide("Modrinth integration failed:\n" + std::string(e.what())), Ui::DialogTone::Error,
                       {{IDOK, L"Exit", true}}, IDOK);
        return 1;
    }
}
