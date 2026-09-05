#pragma once
// Included after InstanceConfig; shared by compatibility, reduced and lite frontends.
static void showInstallSuccessDialogWithUninstall(const fs::path &instanceCfg, const fs::path &instanceDir,
                                                  std::function<InstanceConfig::InstallResult()> uninstall = {}) {
    while (true) {
        int action = Ui::showDialog(toWide(g_projectName + " v" + g_version + " — Installed"),
                                    toWide(g_projectName +
                                           " has been configured for this instance.\n\n"
                                           "Instance: " +
                                           instanceDir.filename().u8string() +
                                           "\n"
                                           "Path: " +
                                           instanceDir.u8string() +
                                           "\n\n"
                                           "You can now launch Minecraft from your launcher."),
                                    Ui::DialogTone::Success, {{IDOK, L"Done", true}, {IDNO, L"Uninstall"}}, IDOK, true,
                                    L"Installation Complete", 760);

        if (action != IDNO) {
            return;
        }

        int confirm = Ui::showDialog(toWide(g_projectName + " — Confirm Uninstall"),
                                     L"Are you sure you want to undo the installation?\n"
                                     L"This will remove the launcher integration.",
                                     Ui::DialogTone::Warning, {{IDYES, L"Uninstall", true}, {IDNO, L"Cancel"}}, IDNO,
                                     true, L"Confirm Uninstall", 700);

        if (confirm != IDYES) {
            continue;
        }

        InstanceConfig::InstallResult uninstallResult;
        if (uninstall) {
            uninstallResult = uninstall();
        } else if (iequals(toLower(instanceCfg.extension().string()), ".json")) {
            uninstallResult = InstanceConfig::installPreLaunchCommandJson(instanceCfg, "");
        } else {
            uninstallResult = InstanceConfig::installPreLaunchCommandCfg(instanceCfg, "");
        }

        if (uninstallResult.success) {
            Ui::showDialog(toWide(g_projectName + " v" + g_version + " — Uninstalled"),
                           toWide("Launcher integration was removed for this instance.\n\n"
                                  "Instance: " +
                                  instanceDir.filename().u8string() +
                                  "\n"
                                  "Path: " +
                                  instanceDir.u8string()),
                           Ui::DialogTone::Info, {{IDOK, L"Done", true}}, IDOK, true, L"Uninstalled", 760);
            return;
        }

        Ui::showDialog(toWide(g_projectName + " — Error"), toWide("Failed to uninstall:\n" + uninstallResult.error),
                       Ui::DialogTone::Error, {{IDOK, L"OK", true}}, IDOK, true, L"Uninstall Failed", 760);
    }
}
