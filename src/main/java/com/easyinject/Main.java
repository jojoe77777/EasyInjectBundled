package com.easyinject;

import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.Shell32;
import com.sun.jna.platform.win32.ShellAPI;
import com.sun.jna.platform.win32.WinBase;
import com.sun.jna.platform.win32.WinDef;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.ptr.IntByReference;

import java.io.ByteArrayOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URISyntaxException;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.nio.charset.Charset;
import java.nio.file.Path;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;

/**
 * EasyInjectBundled - Java DLL Injector with Embedded DLLs
 * 
 * This version embeds all DLLs inside the JAR at build time.
 * At runtime, it extracts them to %USERPROFILE%/.config/<brand>/dlls and injects them.
 * The <brand> folder name is derived from branding.properties (brand.name).
 * 
 * Two-phase execution model:
 * - Launcher Mode (default): Spawns watcher process and exits immediately with code 0
 * - Watcher Mode (--watcher): Polls for Java process, waits for window, injects DLLs
 * - Info Mode (--info): Prints information about embedded DLLs
 */
public class Main {

    // Branding - loaded from branding.properties
    private static String PROJECT_NAME = "EasyInjectBundled";
    private static String VERSION = "1.0";
    
    private static final String WATCHER_ARG = "--watcher";
    private static final String INFO_ARG = "--info";
    private static final String PRELAUNCH_ARG = "--prelaunch";
    private static final String FORWARDED_PRELAUNCH_CHAIN_ARG = "--run-prelaunch-chain";
    private static final String DEFENDER_ELEVATED_ENSURE_ARG = "--defender-elevated-ensure";
    private static final String DEFENDER_ELEVATED_SELFJAR_ARG = "--defender-elevated-selfjar";
    private static final String DEFENDER_ELEVATED_OUT_ARG = "--defender-elevated-out";
    private static final String DLL_RESOURCE_PATH = "dlls/";
    private static final String LOGGER_DLL_NAME = "liblogger_x64.dll";
    private static final String LOG_FILE = "injector.log";
    private static final int POLL_INTERVAL_MS = 500;
    private static final int TARGET_LEAF_RECHECK_INTERVAL_MS = 2000;
    private static final int TIMEOUT_SECONDS = 60;
    
    private static PrintWriter logWriter = null;
    private static SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
    private static final List<String> savedLauncherPathsForRestart = new ArrayList<String>();

    static {
        // Load branding from embedded properties file
        loadBranding();
    }

    private static void loadBranding() {
        try {
            InputStream is = Main.class.getResourceAsStream("/branding.properties");
            if (is != null) {
                Properties props = new Properties();
                props.load(is);
                is.close();
                
                String name = props.getProperty("brand.name");
                if (name != null && !name.isEmpty()) {
                    PROJECT_NAME = name;
                }
                
                String ver = props.getProperty("brand.version");
                if (ver != null && !ver.isEmpty()) {
                    VERSION = ver;
                }
            }
        } catch (Exception e) {
            // Use defaults if loading fails
        }
    }

    /**
     * Apply a dark theme to Swing UIManager defaults.
     */
    static void applyDarkTheme() {
        java.awt.Color bg = new java.awt.Color(43, 43, 43);
        java.awt.Color fg = new java.awt.Color(224, 224, 224);
        java.awt.Color fieldBg = new java.awt.Color(30, 30, 30);
        java.awt.Color btnBg = new java.awt.Color(60, 60, 60);
        java.awt.Font baseFont = new java.awt.Font("Segoe UI", java.awt.Font.PLAIN, 13);
        java.awt.Font btnFont = new java.awt.Font("Segoe UI", java.awt.Font.PLAIN, 12);

        javax.swing.UIManager.put("OptionPane.background", bg);
        javax.swing.UIManager.put("OptionPane.messageForeground", fg);
        javax.swing.UIManager.put("OptionPane.messageFont", baseFont);
        javax.swing.UIManager.put("Panel.background", bg);
        javax.swing.UIManager.put("Panel.foreground", fg);
        javax.swing.UIManager.put("Label.background", bg);
        javax.swing.UIManager.put("Label.foreground", fg);
        javax.swing.UIManager.put("Label.font", baseFont);
        javax.swing.UIManager.put("Button.background", btnBg);
        javax.swing.UIManager.put("Button.foreground", fg);
        javax.swing.UIManager.put("Button.font", btnFont);
        javax.swing.UIManager.put("Button.border", javax.swing.BorderFactory.createCompoundBorder(
            javax.swing.BorderFactory.createLineBorder(new java.awt.Color(80, 80, 80)),
            javax.swing.BorderFactory.createEmptyBorder(4, 12, 4, 12)
        ));
        javax.swing.UIManager.put("TextField.background", fieldBg);
        javax.swing.UIManager.put("TextField.foreground", fg);
        javax.swing.UIManager.put("TextField.caretForeground", fg);
        javax.swing.UIManager.put("TextField.font", new java.awt.Font("Consolas", java.awt.Font.PLAIN, 12));
    }

    public static void main(String[] args) {
        // Internal elevated helper mode (used to ensure Defender exclusions with a single UAC prompt).
        if (hasArgument(args, DEFENDER_ELEVATED_ENSURE_ARG)) {
            System.exit(runDefenderElevatedEnsureMode(args));
            return;
        }

        if (hasArgument(args, INFO_ARG)) {
            System.exit(runInfoMode());
        } else if (hasArgument(args, WATCHER_ARG)) {
            System.exit(runWatcherMode());
        } else {
            // Check if running from pre-launch (has --prelaunch flag or INST_ID env var) or double-clicked
            String instId = System.getenv("INST_ID");
            if (hasArgument(args, PRELAUNCH_ARG) || (instId != null && !instId.isEmpty())) {
                System.exit(runLauncherMode(args));
            } else {
                showDoubleClickWarning();
                System.exit(0);
            }
        }
    }

    /**
     * Handle double-click: look for instance.cfg (MultiMC/Prism) or instance.json (ATLauncher)
     * and install PreLaunchCommand.
     */
    private static void showDoubleClickWarning() {
        // If the user double-clicks the JAR, start with a clean log for easier troubleshooting.
        resetLogFilesForStartup();

        // Get the actual JAR file and its directory. We must be able to create a stable jar copy.
        String jarFilename = getStableSelfJarFileName();
        File jarDir = null;
        File stableJarForLauncher = null;
        try {
            String jarPath = getJarPath();
            File jarFile = new File(jarPath);
            if (jarFile.isFile()) {
                jarDir = jarFile.getParentFile();

                // For launcher integration, always install/run via a stable filename:
                // <brand>.jar in the same folder as the current jar.
                // This keeps the MultiMC/Prism PreLaunchCommand stable across updates.
                File stableJar = new File(jarDir, getStableSelfJarFileName());
                if (!stableJar.getAbsolutePath().equalsIgnoreCase(jarFile.getAbsolutePath())) {
                    try {
                        Files.copy(jarFile.toPath(), stableJar.toPath(), StandardCopyOption.REPLACE_EXISTING);
                        jarFilename = stableJar.getName();
                        stableJarForLauncher = stableJar;
                    } catch (Throwable copyErr) {
                        // If we can't create the stable jar, don't install a broken prelaunch command.
                        showErrorDialog(
                            "Failed to create/replace " + stableJar.getName() + " next to the current JAR.\n\n" +
                            "This usually means the file is currently in use (busy/locked) or blocked by antivirus.\n\n" +
                            "Close MultiMC/Prism/any process using it and try again.\n\n" +
                            "Reason: " + (copyErr.getMessage() != null ? copyErr.getMessage() : copyErr.toString())
                        );
                        return;
                    }
                } else {
                    jarFilename = jarFile.getName();
                    stableJarForLauncher = jarFile;
                }
            }
        } catch (Exception e) {
            // Use default name if we can't get the path
        }

        if (jarDir == null || stableJarForLauncher == null) {
            showErrorDialog("Could not resolve the current JAR path to create " + getStableSelfJarFileName() + ".\n\n" +
                "Please run this from a JAR file (not from an IDE/classpath) and try again.");
            return;
        }

        // Check for Smart App Control FIRST - it blocks unsigned DLLs and cannot be bypassed with exclusions.
        // This must be checked before Defender exclusions since SAC takes precedence over Defender.
        checkAndWarnAboutSmartAppControl();

        // Prepare persistent DLL directory + Defender exclusion (may trigger UAC)
        // This must be based on the stable launcher jar (e.g. Toolscreen.jar).
        prepareDllFolderAndDefenderExclusionForInstall(stableJarForLauncher);
        
        // Determine if JAR is in a minecraft/.minecraft subfolder
        String subfolderPrefix = "";
        File instanceDir = jarDir;
        
        if (jarDir != null) {
            String dirName = jarDir.getName().toLowerCase();
            if (dirName.equals("minecraft") || dirName.equals(".minecraft")) {
                // JAR is in minecraft subfolder, look one level up for instance config
                instanceDir = jarDir.getParentFile();
                // Include the subfolder in the command path
                subfolderPrefix = jarDir.getName() + "/";
            }
        }
        
        // Build the prelaunch command with appropriate path
        String jarRelativePath = subfolderPrefix + jarFilename;
        String prelaunchCommand = "\\\"$INST_JAVA\\\" -jar \\\"$INST_DIR/" + jarRelativePath + "\\\"";
        
        // Look for instance.cfg (MultiMC/Prism) or instance.json (ATLauncher)
        File instanceCfg = (instanceDir != null) ? new File(instanceDir, "instance.cfg") : null;
        File instanceJson = (instanceDir != null) ? new File(instanceDir, "instance.json") : null;
        
        if (instanceCfg != null && instanceCfg.exists() && instanceCfg.isFile()) {
            // MultiMC / Prism Launcher - install via instance.cfg
            InstallResult result = installPreLaunchCommand(instanceCfg, prelaunchCommand);
            if (result.success) {
                ensurePrelaunchTxtExists(instanceDir);
                showSuccessDialog(jarRelativePath, instanceCfg, instanceDir);
            } else {
                showErrorDialog(result.error);
            }
        } else if (instanceJson != null && instanceJson.exists() && instanceJson.isFile()) {
            // ATLauncher - install via instance.json
            InstallResult result = installPreLaunchCommandJson(instanceJson, prelaunchCommand + " " + PRELAUNCH_ARG);
            if (result.success) {
                ensurePrelaunchTxtExists(instanceDir);
                showSuccessDialog(jarRelativePath, instanceJson, instanceDir);
            } else {
                showErrorDialog(result.error);
            }
        } else {
            // No instance config found - show the setup warning
            showNoInstanceCfgWarning(prelaunchCommand);
        }
    }

    /**
     * Create an empty prelaunch.txt file in the instance root folder (best-effort).
     *
     * This is used as a user-editable prelaunch chain file. If the file already exists,
     * it is left untouched.
     */
    private static void ensurePrelaunchTxtExists(File instanceDir) {
        if (instanceDir == null || !instanceDir.isDirectory()) {
            return;
        }

        try {
            File f = new File(instanceDir, "prelaunch.txt");
            if (f.exists()) {
                return;
            }

            // Ensure parent exists and create empty file.
            File parent = f.getParentFile();
            if (parent != null && !parent.exists()) {
                //noinspection ResultOfMethodCallIgnored
                parent.mkdirs();
            }

            //noinspection ResultOfMethodCallIgnored
            f.createNewFile();
        } catch (Throwable ignored) {
            // Best-effort; do not block installation.
        }
    }

    /**
     * Stable JAR filename used for launcher integration and self-updates.
     * Example: Toolscreen.jar
     */
    private static String getStableSelfJarFileName() {
        String base = PROJECT_NAME;
        if (base == null) {
            base = "Toolscreen";
        }
        base = base.trim();
        if (base.isEmpty()) {
            base = "Toolscreen";
        }

        // Sanitize for Windows filenames.
        base = base.replaceAll("[\\\\/:*\\\"<>|]", "_");
        return base + ".jar";
    }

    private static class PrepareDllFolderResult {
        final boolean folderReady;
        final boolean defenderExcluded;
        final boolean defenderExclusionSkipped;
        final String message;

        PrepareDllFolderResult(boolean folderReady, boolean defenderExcluded, boolean defenderExclusionSkipped, String message) {
            this.folderReady = folderReady;
            this.defenderExcluded = defenderExcluded;
            this.defenderExclusionSkipped = defenderExclusionSkipped;
            this.message = message;
        }
    }

    /**
     * On double-click install: ensure the persistent DLL folder exists and is excluded from Windows Defender.
     *
     * This is best-effort and non-fatal: the launcher integration can still be installed even if Defender
     * exclusion fails (e.g. user cancels UAC, Defender cmdlets unavailable, etc).
     */
    private static void prepareDllFolderAndDefenderExclusionForInstall(File jarToExclude) {
        try {
            PrepareDllFolderResult r = prepareDllFolderAndDefenderExclusion(jarToExclude);
            if (r == null) {
                return;
            }

            if (!r.folderReady || (!r.defenderExcluded && !r.defenderExclusionSkipped)) {
                // Folder creation failure is unrecoverable for our use-case.
                if (!r.folderReady) {
                    showFatalWarningDialogAndExit(r.message != null ? r.message : "Could not create DLL folder");
                    return;
                }

                // Defender exclusion failure may be fixable by user action; guide and keep retrying.
                // If the user explicitly chose to continue without exclusions, do not block here.
                if (!r.defenderExclusionSkipped) {
                    File preferredDllDir = getPreferredPersistentDllDir();
                    guideUserThroughManualDefenderExclusionUntilDone(preferredDllDir, jarToExclude, r.message);
                }
            }
        } catch (Throwable ignored) {
            // Non-fatal.
        }
    }

    /**
     * If automatic Defender exclusion fails, guide the user through manually adding the exclusion.
     * This method does not return until the exclusion is detected (or the process is killed).
     */
    private static void guideUserThroughManualDefenderExclusionUntilDone(File dllDir, File jarToExclude, String initialDetails) {
        if (dllDir == null || !isWindows()) {
            return;
        }

        final String exclusionsKey = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths";
        final String path = normalizePathForDefenderExclusionCheck(dllDir.getAbsolutePath());

        final String jarCheckPath = (jarToExclude != null)
            ? normalizePathForDefenderExclusionCheck(jarToExclude.getAbsolutePath())
            : null;

        // If already excluded, nothing to do.
        boolean folderOk = isDefenderExclusionPresent(exclusionsKey, path);
        boolean jarOk = (jarCheckPath == null || jarCheckPath.isEmpty()) || isDefenderExclusionPresent(exclusionsKey, jarCheckPath);
        if (folderOk && jarOk) {
            return;
        }

        // Single-UAC policy: we do not run any further automatic attempts here, because
        // this method can be entered after an automatic attempt already happened.
        // Manual UI guidance only from here.
        DefenderExclusionResult lastAttempt = new DefenderExclusionResult(false, initialDetails);

            // Keep prompting until we can detect the exclusions present.
        while (true) {
            folderOk = isDefenderExclusionPresent(exclusionsKey, path);
            jarOk = (jarCheckPath == null || jarCheckPath.isEmpty()) || isDefenderExclusionPresent(exclusionsKey, jarCheckPath);
            if (folderOk && jarOk) {
                return;
            }

            String details = null;
            if (lastAttempt != null && lastAttempt.details != null && !lastAttempt.details.trim().isEmpty()) {
                details = lastAttempt.details.trim();
            } else if (initialDetails != null && !initialDetails.trim().isEmpty()) {
                details = initialDetails.trim();
            }

            Integer tpNow = getWindowsDefenderTamperProtectionValue();
            if (tpNow != null && tpNow.intValue() != 0) {
                String tpNote = "Defender Tamper Protection appears enabled (value=" + tpNow + ").";
                if (details == null || details.isEmpty()) {
                    details = tpNote;
                } else if (details.toLowerCase().indexOf("tamper protection") < 0) {
                    details = details + "\n\n" + tpNote;
                }
            }

            int action = showManualDefenderExclusionDialogBlocking(path, jarCheckPath, details);

            // -1 = window closed (X) => exit installer
            // 0 = "I've added it" => proceed (best-effort verify)
            // 1 = "Open Windows Security" => open and re-check
            // 2 = "Retry automatic" => intentionally disabled (to avoid additional UAC prompts)
            // 3 = "Skip (not recommended)" => continue without exclusion (after warning)
            // 4 = "Exit" => exit installer
            if (action == -1 || action == 4) {
                System.exit(1);
                return;
            }

            if (action == 1) {
                openWindowsSecurityExclusionsUi();
            } else if (action == 2) {
                // Do not trigger another UAC prompt. Provide a hint instead.
                lastAttempt = new DefenderExclusionResult(false, "Automatic retry is disabled to avoid multiple UAC prompts. Please add the exclusion manually in Windows Security.");
            } else if (action == 3) {
                // User wants to proceed without exclusions.
                if (confirmSkipDefenderExclusionDialogBlocking()) {
                    return;
                }
            } else if (action == 0) {
                // Best-effort: try to verify once, but do not block forever if verification isn't possible.
                folderOk = isDefenderExclusionPresent(exclusionsKey, path);
                jarOk = (jarCheckPath == null || jarCheckPath.isEmpty()) || isDefenderExclusionPresent(exclusionsKey, jarCheckPath);
                if (folderOk && jarOk) {
                    return;
                }
                showNonFatalWarningDialog(
                    "Could not verify the Defender exclusion was added (this can happen on some systems due to permission/policy restrictions).\n\n" +
                    "If you added the exclusion in Windows Security, you can continue.\n\n" +
                    "Folder:\n" + dllDir.getAbsolutePath() +
                    ((jarCheckPath != null && !jarCheckPath.isEmpty()) ? ("\n\nJAR:\n" + jarCheckPath) : "")
                );
                return;
            }

            sleep(600);
        }
    }

    /**
     * First-time prompt shown before triggering an elevation/UAC request.
     *
     * Return values:
     * 0 = Continue (attempt to add exclusions)
     * 1 = Exit
     * 2 = Skip exclusions (not recommended)
     * -1 = Window closed
     */
    private static int showExclusionWillBeAddedDialogBlocking(String folderPath) {
        return showExclusionWillBeAddedDialogBlocking(folderPath, null);
    }

    private static int showExclusionWillBeAddedDialogBlocking(String folderPath, String jarPath) {
        try {
            applyDarkTheme();

            StringBuilder body = new StringBuilder();
            body.append("<html><body style='width: 420px; font-family: Segoe UI, sans-serif; color: #e0e0e0;'>");
            body.append("<p style='margin:0 0 10px 0; color: #FFB300; font-size: 15px;'><b>Windows Defender Exclusion Needed</b></p>");
            body.append("<p style='margin:0 0 10px 0;'>");
            body.append("This installer needs to add exclusions so Windows Defender does not quarantine the injected DLLs or the installer itself.");
            body.append("</p>");
            body.append("<p style='margin:0 0 10px 0; color:#c7ced6; font-size: 12px;'>");
            body.append("<b>Why?</b> This tool loads a DLL into another process (DLL injection). That behavior is commonly used by malware, so antivirus tools often flag or block it, especially when the DLL is <b>unsigned</b>. ");
            body.append("The ").append(escapeHtml(PROJECT_NAME)).append(" DLL is not signed as that requires paying Microsoft a yearly subscription for a digital certificate.");
            body.append("</p>");
            body.append("<p style='margin:0 0 10px 0; color:#c7ced6;'><b>Folder</b></p>");
            body.append("<pre style='white-space: pre-wrap; font-family: Consolas, monospace; color: #81D4FA; margin:0 0 10px 0;'>");
            body.append(escapeHtml(folderPath));
            body.append("</pre>");

            if (jarPath != null && !jarPath.trim().isEmpty()) {
                body.append("<p style='margin:0 0 10px 0; color:#c7ced6;'><b>JAR</b></p>");
                body.append("<pre style='white-space: pre-wrap; font-family: Consolas, monospace; color: #81D4FA; margin:0 0 10px 0;'>");
                body.append(escapeHtml(jarPath));
                body.append("</pre>");
            }
            body.append("<p style='margin:0 0 10px 0; color:#c7ced6; font-size: 12px;'>");
            body.append("The installer will also add an exclusion for this JAR file (best-effort). If your system blocks file exclusions, excluding the folder is usually sufficient.");
            body.append("</p>");
            body.append("<p style='margin:0; color:#9e9e9e; font-size: 11px;'>");
            body.append("A User Account Control (UAC) prompt may appear to verify and add the exclusion. You must click <b>Yes</b> for the exclusion to be added.");
            body.append("</p>");
            body.append("<p style='margin:10px 0 0 0; color:#9e9e9e; font-size: 11px;'>");
            body.append("If you don't want to create an antivirus exclusion, click <b>Exit</b>. ").append(escapeHtml(PROJECT_NAME)).append(" will not be installed.");
            body.append("</p>");
            body.append("</body></html>");

            javax.swing.JLabel msgLabel = new javax.swing.JLabel(body.toString());

            javax.swing.JButton continueBtn = createStyledButton("Continue");
            javax.swing.JButton skipBtn = createStyledButton("Skip (not recommended)");
            javax.swing.JButton exitBtn = createStyledButton("Exit");

            Object[] options = new Object[] { continueBtn, skipBtn, exitBtn };

            while (true) {
                int res = showBlockingOptionDialog(
                    PROJECT_NAME + " v" + VERSION + " — Defender Exclusion",
                    msgLabel,
                    options,
                    0
                );

                // closed or Exit
                if (res == -1 || res == 2) {
                    return 1;
                }
                // Continue
                if (res == 0) {
                    return 0;
                }
                // Skip (after warning)
                if (res == 1) {
                    if (confirmSkipDefenderExclusionDialogBlocking()) {
                        return 2;
                    }
                    // user chose to go back; show the first prompt again
                    continue;
                }
                return 1;
            }
        } catch (Throwable ignored) {
            // If GUI fails, default to continue.
            return 0;
        }
    }

    private static int showManualDefenderExclusionDialogBlocking(String folderPath, String jarPath, String details) {
        try {
            applyDarkTheme();

            StringBuilder body = new StringBuilder();
            body.append("<html><body style='width: 420px; font-family: Segoe UI, sans-serif; color: #e0e0e0;'>");
            body.append("<p style='margin:0 0 10px 0; color: #FFB300; font-size: 15px;'><b>⚠ Action Required</b></p>");
            body.append("<p style='margin:0 0 10px 0;'>");
            body.append("Please add this folder (and the installer JAR, if shown) to Windows Defender exclusions, then click <b>I've added it</b>.");
            body.append("</p>");
            body.append("<p style='margin:0 0 10px 0; color:#c7ced6; font-size: 12px;'>");
            body.append("This is required because DLL injection is commonly flagged by antivirus software and the DLLs are unsigned.");
            body.append("</p>");
            body.append("<p style='margin:0 0 6px 0; color:#c7ced6;'><b>Folder</b></p>");
            body.append("<pre style='white-space: pre-wrap; font-family: Consolas, monospace; color: #81D4FA; margin:0 0 10px 0;'>");
            body.append(escapeHtml(folderPath));
            body.append("</pre>");

            if (jarPath != null && !jarPath.trim().isEmpty()) {
                body.append("<p style='margin:0 0 6px 0; color:#c7ced6;'><b>JAR</b></p>");
                body.append("<pre style='white-space: pre-wrap; font-family: Consolas, monospace; color: #81D4FA; margin:0 0 10px 0;'>");
                body.append(escapeHtml(jarPath));
                body.append("</pre>");
            }

            body.append("<p style='margin:0 0 6px 0; color:#c7ced6;'><b>Steps</b></p>");
            body.append("<ol style='margin:0 0 10px 18px; padding:0; color:#c7ced6; font-size: 12px;'>");
            body.append("<li>Open <b>Windows Security</b></li>");
            body.append("<li>Go to <b>Virus &amp; threat protection</b> → <b>Manage settings</b></li>");
            body.append("<li>Scroll to <b>Exclusions</b> → <b>Add or remove exclusions</b></li>");
            body.append("<li>Click <b>Add an exclusion</b> → <b>Folder</b></li>");
            body.append("<li>Select the folder above</li>");
            if (jarPath != null && !jarPath.trim().isEmpty()) {
                body.append("<li>Click <b>Add an exclusion</b> → <b>File</b></li>");
                body.append("<li>Select the JAR file above</li>");
            }
            body.append("</ol>");

            body.append("<p style='margin:0 0 10px 0; color:#9e9e9e; font-size: 11px;'>");
            body.append("If your PC is managed by an organization, Defender policies may prevent exclusions. In that case, contact your administrator.");
            body.append("</p>");

            if (details != null && !details.trim().isEmpty()) {
                body.append("<p style='margin:0 0 6px 0; color:#c7ced6;'><b>Details</b></p>");
                body.append("<pre style='white-space: pre-wrap; font-family: Segoe UI, sans-serif; color: #9e9e9e; margin:0;'>");
                body.append(escapeHtml(details));
                body.append("</pre>");
            }

            body.append("</body></html>");

            javax.swing.JLabel msgLabel = new javax.swing.JLabel(body.toString());

            javax.swing.JButton doneBtn = createStyledButton("I've added it");
            javax.swing.JButton openBtn = createStyledButton("Open Windows Security");
            javax.swing.JButton retryBtn = createStyledButton("Retry automatic");
            javax.swing.JButton skipBtn = createStyledButton("Skip (not recommended)");
            javax.swing.JButton exitBtn = createStyledButton("Exit");

            Object[] options = new Object[] { doneBtn, openBtn, retryBtn, skipBtn, exitBtn };
            // Map: done=0, open=1, retry=2, skip=3, exit=4, closed=-1
            return showBlockingOptionDialog(
                PROJECT_NAME + " v" + VERSION + " — Defender Exclusion Required",
                msgLabel,
                options,
                0
            );
        } catch (Throwable ignored) {
            // If GUI fails, fall back to console prompt (blocking).
            System.out.println("=======================================================");
            System.out.println("  " + PROJECT_NAME + " - Action Required");
            System.out.println("=======================================================");
            System.out.println();
            System.out.println("Add this folder to Windows Defender exclusions:");
            System.out.println(folderPath);
            System.out.println();
            if (jarPath != null && !jarPath.trim().isEmpty()) {
                System.out.println("Add this JAR file to Windows Defender exclusions:");
                System.out.println(jarPath);
                System.out.println();
            }
            if (details != null && !details.trim().isEmpty()) {
                System.out.println("Details: " + details);
                System.out.println();
            }
            System.out.println("After you've added it, press Enter to continue...");
            try { System.in.read(); } catch (Exception ignored2) {}
            return 0;
        }
    }

    /**
     * Second-step warning shown when the user chooses to skip Defender exclusions.
     *
     * @return true if the user confirms they want to continue without exclusions.
     */
    private static boolean confirmSkipDefenderExclusionDialogBlocking() {
        try {
            applyDarkTheme();

            StringBuilder body = new StringBuilder();
            body.append("<html><body style='width: 420px; font-family: Segoe UI, sans-serif; color: #e0e0e0;'>");
            body.append("<p style='margin:0 0 10px 0; color: #FFB300; font-size: 15px;'><b>Continue without exclusions?</b></p>");
            body.append("<p style='margin:0 0 10px 0;'>");
            body.append("If you skip Windows Defender exclusions, Windows may quarantine or block the DLLs or this installer.");
            body.append("</p>");
            body.append("<ul style='margin:0 0 10px 18px; padding:0; color:#c7ced6; font-size: 12px;'>");
            body.append("<li>The injection may fail or stop working later after an update/scan.</li>");
            body.append("<li>You may need to re-run this installer and add the exclusions to make it work.</li>");
            body.append("</ul>");
            body.append("<p style='margin:0; color:#9e9e9e; font-size: 11px;'>");
            body.append("This is not recommended, but you can continue at your own risk.");
            body.append("</p>");
            body.append("</body></html>");

            javax.swing.JLabel msgLabel = new javax.swing.JLabel(body.toString());
            javax.swing.JButton contBtn = createStyledButton("Continue anyway");
            javax.swing.JButton backBtn = createStyledButton("Go back");

            int choice = showBlockingOptionDialog(
                PROJECT_NAME + " v" + VERSION + " — Warning",
                msgLabel,
                new Object[] { contBtn, backBtn },
                1
            );
            return choice == 0;
        } catch (Throwable ignored) {
            return false;
        }
    }

    /**
     * Show a blocking option dialog that:
     * - returns the selected option index
     * - returns -1 when the dialog is closed via the window X
     */
    private static int showBlockingOptionDialog(String title, java.awt.Component message, Object[] options, int defaultIndex) {
        try {
            javax.swing.JOptionPane pane = new javax.swing.JOptionPane(
                message,
                javax.swing.JOptionPane.PLAIN_MESSAGE,
                javax.swing.JOptionPane.DEFAULT_OPTION,
                null,
                options,
                (options != null && options.length > 0 && defaultIndex >= 0 && defaultIndex < options.length) ? options[defaultIndex] : null
            );

            final javax.swing.JDialog dialog = pane.createDialog(null, title);
            dialog.setDefaultCloseOperation(javax.swing.JDialog.DISPOSE_ON_CLOSE);

            // If the user clicks X, pane.getValue() will remain unset/null; we treat that as -1.
            // Hook buttons to set a concrete value.
            if (options != null) {
                for (Object opt : options) {
                    if (opt instanceof javax.swing.JButton) {
                        final javax.swing.JButton b = (javax.swing.JButton) opt;
                        b.addActionListener(new java.awt.event.ActionListener() {
                            public void actionPerformed(java.awt.event.ActionEvent e) {
                                pane.setValue(b);
                                dialog.dispose();
                            }
                        });
                    }
                }
            }

            dialog.setVisible(true);

            Object val = pane.getValue();
            if (val == null || options == null) {
                return -1;
            }
            for (int i = 0; i < options.length; i++) {
                if (options[i] == val) {
                    return i;
                }
            }
            return -1;
        } catch (Throwable ignored) {
            return -1;
        }
    }

    private static void openWindowsSecurityExclusionsUi() {
        // Best effort. Some Windows builds support windowsdefender: URI, others prefer ms-settings.
        try {
            new ProcessBuilder("cmd", "/C", "start", "", "windowsdefender:").start();
            return;
        } catch (Throwable ignored) {
            // ignore
        }
        try {
            new ProcessBuilder("cmd", "/C", "start", "", "ms-settings:windowsdefender").start();
        } catch (Throwable ignored) {
            // ignore
        }
    }

    /**
     * Best-effort: read Defender Tamper Protection value from registry.
     * Common values observed: 0 (off) and 5 (on). This is not guaranteed across Windows versions.
     */
    private static Integer getWindowsDefenderTamperProtectionValue() {
        if (!isWindows()) {
            return null;
        }
        try {
            ExecResult q = execCommandCapture(new String[] {
                getRegExePath(), "query",
                "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features",
                "/v", "TamperProtection"
            });
            if (q.exitCode != 0 || q.output == null) {
                return null;
            }

            // Output typically contains: TamperProtection    REG_DWORD    0x5
            String out = q.output;
            String lower = out.toLowerCase();
            int idx = lower.indexOf("0x");
            if (idx >= 0) {
                int end = idx + 2;
                while (end < out.length()) {
                    char c = out.charAt(end);
                    boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
                    if (!hex) {
                        break;
                    }
                    end++;
                }
                String hex = out.substring(idx + 2, end);
                if (!hex.isEmpty()) {
                    return Integer.parseInt(hex, 16);
                }
            }

            // Fallback: try to parse the last integer-ish token.
            String[] tokens = out.trim().split("\\s+");
            for (int i = tokens.length - 1; i >= 0; i--) {
                try {
                    if (tokens[i].startsWith("0x") || tokens[i].startsWith("0X")) {
                        return Integer.parseInt(tokens[i].substring(2), 16);
                    }
                    return Integer.parseInt(tokens[i]);
                } catch (Exception ignored) {
                    // keep scanning
                }
            }
            return null;
        } catch (Throwable ignored) {
            return null;
        }
    }

    /**
     * Smart App Control state enumeration.
     * SAC is a Windows 11 feature that blocks unsigned/unsigned apps and DLLs.
     * Unlike Windows Defender, SAC does NOT support exclusions - it must be disabled entirely.
     */
    private enum SmartAppControlState {
        /** SAC is enabled and actively blocking unsigned apps */
        ENABLED,
        /** SAC is in evaluation mode (still learning, may or may not block) */
        EVALUATION,
        /** SAC is disabled */
        DISABLED,
        /** Unable to determine SAC state (older Windows, registry inaccessible, etc.) */
        UNKNOWN
    }

    /**
     * Detect Smart App Control state via registry.
     * Registry path: HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy
     * Value: VerifiedAndReputablePolicyState
     *   0 = Disabled
     *   1 = Enabled (Enforcement mode - blocks unsigned apps)
     *   2 = Evaluation mode (learning phase, may still block)
     * 
     * SAC is only available on Windows 11 22H2+. On older Windows, this returns UNKNOWN.
     */
    private static SmartAppControlState getSmartAppControlState() {
        if (!isWindows()) {
            return SmartAppControlState.UNKNOWN;
        }
        try {
            // Check the CI (Code Integrity) policy registry key
            ExecResult q = execCommandCapture(new String[] {
                getRegExePath(), "query",
                "HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Policy",
                "/v", "VerifiedAndReputablePolicyState"
            });
            if (q.exitCode != 0 || q.output == null) {
                // Key doesn't exist - likely older Windows without SAC
                return SmartAppControlState.UNKNOWN;
            }

            // Output typically contains: VerifiedAndReputablePolicyState    REG_DWORD    0x1
            String out = q.output;
            String lower = out.toLowerCase();
            int idx = lower.indexOf("0x");
            if (idx >= 0) {
                int end = idx + 2;
                while (end < out.length()) {
                    char c = out.charAt(end);
                    boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
                    if (!hex) {
                        break;
                    }
                    end++;
                }
                String hex = out.substring(idx + 2, end);
                if (!hex.isEmpty()) {
                    int value = Integer.parseInt(hex, 16);
                    if (value == 0) {
                        return SmartAppControlState.DISABLED;
                    } else if (value == 1) {
                        return SmartAppControlState.ENABLED;
                    } else if (value == 2) {
                        return SmartAppControlState.EVALUATION;
                    }
                }
            }

            // Fallback: try to parse the last integer-ish token
            String[] tokens = out.trim().split("\\s+");
            for (int i = tokens.length - 1; i >= 0; i--) {
                try {
                    int value;
                    if (tokens[i].startsWith("0x") || tokens[i].startsWith("0X")) {
                        value = Integer.parseInt(tokens[i].substring(2), 16);
                    } else {
                        value = Integer.parseInt(tokens[i]);
                    }
                    if (value == 0) {
                        return SmartAppControlState.DISABLED;
                    } else if (value == 1) {
                        return SmartAppControlState.ENABLED;
                    } else if (value == 2) {
                        return SmartAppControlState.EVALUATION;
                    }
                } catch (Exception ignored) {
                    // keep scanning
                }
            }
            return SmartAppControlState.UNKNOWN;
        } catch (Throwable ignored) {
            return SmartAppControlState.UNKNOWN;
        }
    }

    /**
     * Check if Smart App Control is enabled or in evaluation mode.
     * Returns true if SAC might block unsigned DLLs.
     */
    private static boolean isSmartAppControlBlocking() {
        SmartAppControlState state = getSmartAppControlState();
        return state == SmartAppControlState.ENABLED || state == SmartAppControlState.EVALUATION;
    }

    /**
     * Check for Smart App Control and guide user through disabling it if enabled.
     * This is called during installation before Defender exclusion setup.
     * SAC blocks unsigned DLLs and cannot be bypassed with exclusions like Defender.
     */
    private static void checkAndWarnAboutSmartAppControl() {
        if (!isWindows()) {
            return;
        }

        SmartAppControlState state = getSmartAppControlState();
        log("Smart App Control state: " + state);

        // Only block if SAC is actively enabled (not evaluation or unknown)
        // Evaluation mode is less strict and may allow the DLLs
        if (state != SmartAppControlState.ENABLED) {
            return;
        }

        // SAC is enabled - show warning and guide user to disable it
        guideUserThroughDisablingSmartAppControl();
    }

    /**
     * Show a dialog guiding the user through disabling Smart App Control.
     * This method loops until SAC is disabled or the user exits.
     */
    private static void guideUserThroughDisablingSmartAppControl() {
        while (true) {
            SmartAppControlState state = getSmartAppControlState();
            if (state != SmartAppControlState.ENABLED && state != SmartAppControlState.EVALUATION) {
                // SAC is now disabled or unknown (user may have disabled it)
                return;
            }

            int action = showSmartAppControlWarningDialog(state);
            // -1 = window closed (X) => exit installer
            // 0 = "I've disabled it" => re-check
            // 1 = "Open Windows Security" => open settings and re-check
            // 2 = "Exit" => exit installer
            if (action == -1 || action == 2) {
                System.exit(1);
                return;
            }

            if (action == 1) {
                openWindowsSecuritySmartAppControlUi();
            } else if (action == 0) {
                // User claims to have disabled it - verify
                state = getSmartAppControlState();
                if (state != SmartAppControlState.ENABLED && state != SmartAppControlState.EVALUATION) {
                    return;
                }
                // Still enabled - show warning that we couldn't verify
                showNonFatalWarningDialog(
                    "Smart App Control still appears to be enabled.\n\n" +
                    "Please make sure to:\n" +
                    "1. Go to Windows Security > App & browser control\n" +
                    "2. Under 'Smart App Control', click 'Settings'\n" +
                    "3. Select 'Off'\n\n" +
                    "If you've already turned it off, click 'I've disabled it' again."
                );
            }

            sleep(500);
        }
    }

    /**
     * Show the Smart App Control warning dialog.
     * @return -1 (closed), 0 (I've disabled it), 1 (Open Windows Security), 2 (Exit)
     */
    private static int showSmartAppControlWarningDialog(SmartAppControlState state) {
        try {
            applyDarkTheme();

            StringBuilder body = new StringBuilder();
            body.append("<html><body style='width: 450px; font-family: Segoe UI, sans-serif; color: #e0e0e0;'>");
            body.append("<p style='margin:0 0 10px 0; color: #FF5252; font-size: 15px;'><b>⚠ Smart App Control is Enabled</b></p>");
            body.append("<p style='margin:0 0 10px 0;'>");
            body.append("Windows Smart App Control is currently <b>enabled</b> and will block the injected DLLs used by ");
            body.append(escapeHtml(PROJECT_NAME));
            body.append(".");
            body.append("</p>");
            body.append("<p style='margin:0 0 10px 0;'>");
            body.append("<b>Smart App Control does not support exclusions</b> — it must be disabled entirely for this program to work.");
            body.append("</p>");
            body.append("<p style='margin:0 0 10px 0; color:#c7ced6;'>");
            body.append("Current state: <b>");
            if (state == SmartAppControlState.ENABLED) {
                body.append("<span style='color:#FF5252;'>Enabled (Blocking)</span>");
            } else if (state == SmartAppControlState.EVALUATION) {
                body.append("<span style='color:#FFB300;'>Evaluation Mode</span>");
            } else {
                body.append(state);
            }
            body.append("</b></p>");
            body.append("<p style='margin:0 0 10px 0; color:#9e9e9e; font-size: 12px;'>");
            body.append("<b>How to disable Smart App Control:</b>");
            body.append("</p>");
            body.append("<ol style='margin:0 0 10px 0; padding-left:20px; color:#c7ced6; font-size: 12px;'>");
            body.append("<li>Open <b>Windows Security</b> (click below or search in Start)</li>");
            body.append("<li>Go to <b>App &amp; browser control</b></li>");
            body.append("<li>Under <b>Smart App Control</b>, click <b>Settings</b></li>");
            body.append("<li>Select <b>Off</b></li>");
            body.append("</ol>");
            body.append("<p style='margin:0 0 10px 0; color:#9e9e9e; font-size: 11px;'>");
            body.append("Note: Smart App Control is a Windows 11 feature. If you don't see it, you may be on an older version.");
            body.append("</p>");
            body.append("</body></html>");

            javax.swing.JLabel msgLabel = new javax.swing.JLabel(body.toString());
            javax.swing.JButton btnDisabled = createStyledButton("I've disabled it");
            javax.swing.JButton btnOpen = createStyledButton("Open Windows Security");
            javax.swing.JButton btnExit = createStyledButton("Exit");

            Object[] options = new Object[] { btnDisabled, btnOpen, btnExit };

            return showBlockingOptionDialog(
                PROJECT_NAME + " v" + VERSION + " — Smart App Control",
                msgLabel,
                options,
                0
            );
        } catch (Throwable t) {
            // Fallback to console
            System.out.println("=======================================================");
            System.out.println("  Smart App Control is Enabled");
            System.out.println("=======================================================");
            System.out.println();
            System.out.println("Smart App Control is blocking unsigned DLLs.");
            System.out.println("Please disable it in Windows Security:");
            System.out.println("  1. Open Windows Security");
            System.out.println("  2. Go to App & browser control");
            System.out.println("  3. Under Smart App Control, click Settings");
            System.out.println("  4. Select Off");
            System.out.println();
            System.out.println("Then run this installer again.");
            return 2; // Exit
        }
    }

    /**
     * Open Windows Security to the App & browser control page where Smart App Control settings are located.
     */
    private static void openWindowsSecuritySmartAppControlUi() {
        // Best effort - try multiple approaches
        try {
            // Try the windowsdefender URI scheme
            new ProcessBuilder("cmd", "/C", "start", "", "windowsdefender:").start();
            return;
        } catch (Throwable ignored) {}

        try {
            // Try ms-settings for App & browser control
            new ProcessBuilder("cmd", "/C", "start", "", "ms-settings:windowsdefender-appbrowser").start();
            return;
        } catch (Throwable ignored) {}

        try {
            // Fallback to generic Windows Security
            new ProcessBuilder("cmd", "/C", "start", "", "ms-settings:windowsdefender").start();
        } catch (Throwable ignored) {}
    }

    private static void showFatalWarningDialogAndExit(String warning) {
        try {
            applyDarkTheme();

            String message =
                "<html><body style='width: 380px; font-family: Segoe UI, sans-serif; color: #e0e0e0;'>" +
                "<p style='margin:0 0 10px 0; color: #EF5350; font-size: 15px;'><b>✗ Setup Failed</b></p>" +
                "<p style='margin:0 0 10px 0;'>" +
                "This installer must create and whitelist the DLL folder before continuing." +
                "</p>" +
                "<pre style='white-space: pre-wrap; font-family: Segoe UI, sans-serif; color: #c7ced6; margin:0;'>" +
                escapeHtml(warning) +
                "</pre>" +
                "<p style='margin:10px 0 0 0; color:#9e9e9e; font-size: 11px;'>" +
                "If you cancelled the UAC prompt, run this JAR again and click Yes." +
                "</p>" +
                "</body></html>";

            javax.swing.JLabel msgLabel = new javax.swing.JLabel(message);
            javax.swing.JButton okButton = createStyledButton("Exit");
            okButton.addActionListener(new java.awt.event.ActionListener() {
                public void actionPerformed(java.awt.event.ActionEvent e) {
                    java.awt.Window w = javax.swing.SwingUtilities.getWindowAncestor(okButton);
                    if (w != null) w.dispose();
                }
            });

            javax.swing.JOptionPane.showOptionDialog(
                null,
                msgLabel,
                PROJECT_NAME + " v" + VERSION + " — Setup Failed",
                javax.swing.JOptionPane.DEFAULT_OPTION,
                javax.swing.JOptionPane.PLAIN_MESSAGE,
                null,
                new Object[]{ okButton },
                okButton
            );
        } catch (Throwable ignored) {
            // If GUI fails, print to console
            System.out.println("=======================================================");
            System.out.println("  " + PROJECT_NAME + " - Setup Failed");
            System.out.println("=======================================================");
            System.out.println();
            if (warning != null && !warning.trim().isEmpty()) {
                System.out.println(warning);
                System.out.println();
            }
        }

        // Prevent installing launcher integration when setup prerequisites are missing.
        try {
            System.exit(1);
        } catch (Throwable ignored) {
            // ignore
        }
    }

    private static PrepareDllFolderResult prepareDllFolderAndDefenderExclusion(File jarToExclude) {
        File preferredDllDir = getPreferredPersistentDllDir();
        boolean folderReady = false;
        try {
            folderReady = (preferredDllDir.exists() && preferredDllDir.isDirectory()) || preferredDllDir.mkdirs();
        } catch (Throwable ignored) {
            folderReady = false;
        }

        boolean defenderExcluded = false;
        StringBuilder msg = new StringBuilder();

        if (!folderReady) {
            msg.append("Could not create DLL folder:\n\n");
            msg.append(preferredDllDir.getAbsolutePath());
            msg.append("\n\nThe install will continue, but DLL extraction/injection may fail.");
            return new PrepareDllFolderResult(false, false, false, msg.toString());
        }

        if (!isWindows()) {
            return new PrepareDllFolderResult(true, true, false, null);
        }

        // Single-UAC policy:
        // 1) First try non-elevated detection (fast). This avoids prompting when we can already tell.
        // 2) If not detected, ask user consent and then run ONE elevated helper (UAC once) that both
        //    checks via Get-MpPreference and adds the exclusion if needed.
        final String exclusionsKey = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths";
        final String jarCheckPath = (jarToExclude != null)
            ? normalizePathForDefenderExclusionCheck(jarToExclude.getAbsolutePath())
            : null;

        defenderExcluded = isDefenderExclusionPresent(exclusionsKey, preferredDllDir.getAbsolutePath());
        boolean folderExcluded = defenderExcluded;
        boolean jarExcluded = (jarCheckPath == null || jarCheckPath.isEmpty()) || isDefenderExclusionPresent(exclusionsKey, jarCheckPath);
        defenderExcluded = folderExcluded && jarExcluded;
        String ensureDetails = null;

        if (!defenderExcluded) {
            int consent = showExclusionWillBeAddedDialogBlocking(
                normalizePathForDefenderExclusionCheck(preferredDllDir.getAbsolutePath()),
                jarCheckPath
            );
            if (consent == 2) {
                // User explicitly chose to continue without exclusions.
                return new PrepareDllFolderResult(true, false, true, "User chose to continue without Defender exclusions");
            }
            if (consent != 0) {
                System.exit(1);
                return new PrepareDllFolderResult(true, false, false, "User declined Defender exclusion");
            }

            DefenderExclusionResult ensured = ensureDefenderExclusionWithSingleUac(preferredDllDir, jarToExclude);
            if (ensured != null && ensured.success) {
                defenderExcluded = true;
            } else {
                ensureDetails = ensured != null ? ensured.details : "Failed to ensure Defender exclusion";
            }
        }
        if (!defenderExcluded) {
            msg.append("DLL folder created, but Windows Defender exclusion is not set yet.\n\n");
            msg.append("Folder:\n");
            msg.append(preferredDllDir.getAbsolutePath());

            if (jarCheckPath != null && !jarCheckPath.isEmpty()) {
                msg.append("\n\nJAR:\n");
                msg.append(jarCheckPath);
            }

            if (ensureDetails != null && !ensureDetails.trim().isEmpty()) {
                msg.append("\n\nDetails:\n");
                msg.append(ensureDetails.trim());
            }

            Integer tp = getWindowsDefenderTamperProtectionValue();
            if (tp != null && tp.intValue() != 0) {
                msg.append("\n\nNote: Defender Tamper Protection appears to be enabled (value=");
                msg.append(tp);
                msg.append("). Programmatic exclusion changes may be blocked; manual UI may be required.");
            }

            return new PrepareDllFolderResult(true, false, false, msg.toString());
        }

        return new PrepareDllFolderResult(true, true, false, null);
    }

    /**
     * Ensure the Defender exclusion using exactly one UAC prompt by spawning an elevated helper
     * instance of this JAR. The helper runs Get-MpPreference (admin) and adds the exclusion if needed.
     */
    private static DefenderExclusionResult ensureDefenderExclusionWithSingleUac(File dir, File jarToExclude) {
        if (dir == null) {
            return new DefenderExclusionResult(false, "No directory provided");
        }
        if (!isWindows()) {
            return new DefenderExclusionResult(true, null);
        }

        try {
            String jarPath = getJarPath();
            String target = dir.getAbsolutePath();
            String selfJar = (jarToExclude != null) ? jarToExclude.getAbsolutePath() : "";

            File outFile = File.createTempFile("easyinject-defender-ensure-", ".txt");
            outFile.deleteOnExit();

            String javaw = getJavawExePath();
            if (javaw == null || javaw.trim().isEmpty()) {
                return new DefenderExclusionResult(false, "javaw.exe not found");
            }

            String params =
                "-jar \"" + jarPath + "\" " +
                DEFENDER_ELEVATED_ENSURE_ARG + " \"" + target + "\" ";

            if (selfJar != null && !selfJar.trim().isEmpty()) {
                params += DEFENDER_ELEVATED_SELFJAR_ARG + " \"" + selfJar + "\" ";
            }

            params += DEFENDER_ELEVATED_OUT_ARG + " \"" + outFile.getAbsolutePath() + "\"";

            ExecResult elevated = execElevatedAndWait(javaw, params, 120_000);
            String out = safeReadSmallTextFile(outFile);

            if (elevated.exitCode == 0) {
                return new DefenderExclusionResult(true, null);
            }

            String details = "Elevated ensure failed";
            if (elevated.output != null && !elevated.output.trim().isEmpty()) {
                details = elevated.output.trim();
            }
            if (out != null && !out.trim().isEmpty()) {
                details = details + ": " + out.trim();
            }
            return new DefenderExclusionResult(false, details);
        } catch (Throwable t) {
            return new DefenderExclusionResult(false, t.getClass().getName() + ": " + t.getMessage());
        }
    }

    private static String getJavawExePath() {
        try {
            String javaHome = System.getProperty("java.home");
            if (javaHome != null) {
                javaHome = javaHome.trim();
                if (!javaHome.isEmpty()) {
                    File f = new File(new File(javaHome, "bin"), "javaw.exe");
                    if (f.isFile()) {
                        return f.getAbsolutePath();
                    }
                    // Some JRE layouts require going up one level.
                    File parent = new File(javaHome).getParentFile();
                    if (parent != null) {
                        File f2 = new File(new File(parent, "bin"), "javaw.exe");
                        if (f2.isFile()) {
                            return f2.getAbsolutePath();
                        }
                    }
                }
            }
        } catch (Throwable ignored) {
            // ignore
        }
        return "javaw.exe";
    }

    private static String getJavaExePath() {
        try {
            String javaHome = System.getProperty("java.home");
            if (javaHome != null) {
                javaHome = javaHome.trim();
                if (!javaHome.isEmpty()) {
                    File f = new File(new File(javaHome, "bin"), "java.exe");
                    if (f.isFile()) {
                        return f.getAbsolutePath();
                    }
                    // Some JRE layouts require going up one level.
                    File parent = new File(javaHome).getParentFile();
                    if (parent != null) {
                        File f2 = new File(new File(parent, "bin"), "java.exe");
                        if (f2.isFile()) {
                            return f2.getAbsolutePath();
                        }
                    }
                }
            }
        } catch (Throwable ignored) {
            // ignore
        }
        return "java.exe";
    }

    /**
     * Resolve the Java executable to use when spawning child processes.
     *
     * Goal: use the same Java installation (and likely the same java/javaw flavor) as the current process.
     *
     * On Windows:
     * - If this process has a console, prefer java.exe.
     * - Otherwise prefer javaw.exe (common when double-clicking a JAR).
     */
    private static String getCurrentJavaExecutablePath() {
        try {
            if (isWindows()) {
                boolean hasConsole;
                try {
                    hasConsole = (System.console() != null);
                } catch (Throwable ignored) {
                    hasConsole = false;
                }
                return hasConsole ? getJavaExePath() : getJavawExePath();
            }

            // Non-Windows: use java from the current java.home when possible.
            String javaHome = System.getProperty("java.home");
            if (javaHome != null) {
                javaHome = javaHome.trim();
                if (!javaHome.isEmpty()) {
                    File f = new File(new File(javaHome, "bin"), "java");
                    if (f.isFile()) {
                        return f.getAbsolutePath();
                    }
                    File parent = new File(javaHome).getParentFile();
                    if (parent != null) {
                        File f2 = new File(new File(parent, "bin"), "java");
                        if (f2.isFile()) {
                            return f2.getAbsolutePath();
                        }
                    }
                }
            }
        } catch (Throwable ignored) {
            // ignore
        }

        return isWindows() ? "javaw.exe" : "java";
    }

    /**
     * Elevated helper entry point. Must be executed with admin privileges.
     */
    private static int runDefenderElevatedEnsureMode(String[] args) {
        String target = getArgumentValue(args, DEFENDER_ELEVATED_ENSURE_ARG);
        String selfJarOverride = getArgumentValue(args, DEFENDER_ELEVATED_SELFJAR_ARG);
        String outPath = getArgumentValue(args, DEFENDER_ELEVATED_OUT_ARG);
        if (target == null || target.trim().isEmpty() || outPath == null || outPath.trim().isEmpty()) {
            return 2;
        }

        File outFile = new File(outPath);
        String psExe = getPowerShellExePath();
        if (psExe == null || psExe.trim().isEmpty()) {
            safeWriteTextFile(outFile, "PowerShell not available");
            return 3;
        }

        File script = null;
        try {
            script = File.createTempFile("easyinject-defender-ensure-", ".ps1");
            script.deleteOnExit();

            String selfJarPath = null;
            if (selfJarOverride != null && !selfJarOverride.trim().isEmpty()) {
                selfJarPath = selfJarOverride.trim();
            } else {
                selfJarPath = safeGetJarPathOrNull();
            }
            if (selfJarPath == null) {
                selfJarPath = "";
            }

            String scriptText =
                "param([string]$TargetPath, [string]$SelfJarPath, [string]$OutFile)\n" +
                "$ErrorActionPreference='Stop'\n" +
                "function Normalize([string]$p) {\n" +
                "  if ($p -eq $null) { return '' }\n" +
                "  $s = ($p.ToString()).Trim()\n" +
                "  if ($s.Length -gt 0 -and [int]$s[0] -eq 0xFEFF) { $s = $s.Substring(1).Trim() }\n" +
                "  $s = $s -replace '/', '\\\\'\n" +
                "  if ($s.StartsWith('\\\\?\\UNC\\')) { $s = '\\\\' + $s.Substring(8) }\n" +
                "  elseif ($s.StartsWith('\\\\?\\')) { $s = $s.Substring(4) }\n" +
                "  try { $s = [System.IO.Path]::GetFullPath($s) } catch {}\n" +
                "  while ($s.EndsWith('\\\\') -and $s.Length -gt 3) {\n" +
                "    if ($s.Length -eq 3 -and $s[1] -eq ':' -and $s[2] -eq '\\\\') { break }\n" +
                "    $s = $s.Substring(0, $s.Length-1)\n" +
                "  }\n" +
                "  if ($s.EndsWith('\\\\*')) { $s = $s.Substring(0, $s.Length-2) }\n" +
                "  return $s\n" +
                "}\n" +
                "function Covered([string]$ex, [string]$want) {\n" +
                "  $e = (Normalize $ex)\n" +
                "  $w = (Normalize $want)\n" +
                "  if ([string]::IsNullOrWhiteSpace($e) -or [string]::IsNullOrWhiteSpace($w)) { return $false }\n" +
                "  if ($e.Equals($w, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }\n" +
                "  if (-not $e.EndsWith('\\\\')) { $e = $e + '\\\\' }\n" +
                "  if (-not $w.EndsWith('\\\\')) { $w = $w + '\\\\' }\n" +
                "  return $w.StartsWith($e, [System.StringComparison]::OrdinalIgnoreCase)\n" +
                "}\n" +
                "function IsCoveredByPref([string]$want) {\n" +
                "  try {\n" +
                "    $pref = Get-MpPreference\n" +
                "    if ($pref -ne $null -and $pref.ExclusionPath -ne $null) {\n" +
                "      foreach ($ex in $pref.ExclusionPath) { if (Covered $ex $want) { return $true } }\n" +
                "    }\n" +
                "  } catch { }\n" +
                "  return $false\n" +
                "}\n" +
                "function IsCoveredByReg([string]$want) {\n" +
                "  try {\n" +
                "    $regPath2 = 'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths'\n" +
                "    $props = (Get-ItemProperty -Path $regPath2 -ErrorAction Stop).PSObject.Properties\n" +
                "    foreach ($pr in $props) {\n" +
                "      if ($pr.Name -in 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') { continue }\n" +
                "      if (Covered $pr.Name $want) { return $true }\n" +
                "    }\n" +
                "  } catch { }\n" +
                "  return $false\n" +
                "}\n" +
                "try {\n" +
                "  if (-not (Test-Path -LiteralPath $TargetPath)) { New-Item -ItemType Directory -Force -Path $TargetPath | Out-Null }\n" +
                "  $targets = @()\n" +
                "  $targets += $TargetPath\n" +
                "  if (-not [string]::IsNullOrWhiteSpace($SelfJarPath)) {\n" +
                "    try { if (Test-Path -LiteralPath $SelfJarPath) { $targets += $SelfJarPath } } catch { }\n" +
                "  }\n" +
                "  $wants = @()\n" +
                "  foreach ($t in $targets) {\n" +
                "    $n = Normalize $t\n" +
                "    if (-not [string]::IsNullOrWhiteSpace($n)) { $wants += $n }\n" +
                "  }\n" +
                "  foreach ($t in $targets) {\n" +
                "    $want = Normalize $t\n" +
                "    if ([string]::IsNullOrWhiteSpace($want)) { continue }\n" +
                "    $covered = IsCoveredByPref $want\n" +
                "    if (-not $covered) {\n" +
                "      try { Add-MpPreference -ExclusionPath $t | Out-Null } catch { }\n" +
                "    }\n" +
                "    try {\n" +
                "      $regPath = 'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths'\n" +
                "      if (-not (Test-Path -LiteralPath $regPath)) { New-Item -Path $regPath -Force | Out-Null }\n" +
                "      New-ItemProperty -Path $regPath -Name $want -PropertyType DWord -Value 0 -Force | Out-Null\n" +
                "    } catch { }\n" +
                "  }\n" +
                "  # Verify with retries (Defender can update asynchronously).\n" +
                "  $ok = $false\n" +
                "  for ($i = 0; $i -lt 20 -and -not $ok; $i++) {\n" +
                "    $all = $true\n" +
                "    foreach ($w in $wants) {\n" +
                "      if ([string]::IsNullOrWhiteSpace($w)) { continue }\n" +
                "      $oneOk = (IsCoveredByPref $w)\n" +
                "      if (-not $oneOk) { $oneOk = (IsCoveredByReg $w) }\n" +
                "      if (-not $oneOk) { $all = $false; break }\n" +
                "    }\n" +
                "    if ($all) { $ok = $true; break }\n" +
                "    Start-Sleep -Milliseconds 250\n" +
                "  }\n" +
                "  if ($ok) { 'OK' | Out-File -FilePath $OutFile -Encoding UTF8 -Force; exit 0 }\n" +
                "  'FAIL: exclusion not detected after add' | Out-File -FilePath $OutFile -Encoding UTF8 -Force; exit 1\n" +
                "} catch {\n" +
                "  ('FAIL: ' + $_.Exception.Message) | Out-File -FilePath $OutFile -Encoding UTF8 -Force\n" +
                "  exit 1\n" +
                "}\n";

            FileWriter fw = new FileWriter(script);
            try {
                fw.write(scriptText);
            } finally {
                try { fw.close(); } catch (Throwable ignored) {}
            }

            ExecResult r = execCommandCapture(new String[] {
                psExe,
                "-NoProfile",
                "-WindowStyle", "Hidden",
                "-ExecutionPolicy", "Bypass",
                "-File", script.getAbsolutePath(),
                "-TargetPath", target,
                "-SelfJarPath", selfJarPath,
                "-OutFile", outFile.getAbsolutePath()
            });

            if (r.exitCode == 0) {
                return 0;
            }

            // Ensure some details exist for the parent process.
            String out = safeReadSmallTextFile(outFile);
            if (out == null || out.trim().isEmpty()) {
                safeWriteTextFile(outFile, r.output != null ? r.output : "FAIL");
            }
            return 1;
        } catch (Throwable t) {
            safeWriteTextFile(outFile, "FAIL: " + t.getClass().getName() + ": " + t.getMessage());
            return 1;
        }
    }

    private static void safeWriteTextFile(File f, String text) {
        if (f == null) {
            return;
        }
        try {
            OutputStream out = new FileOutputStream(f);
            try {
                byte[] b = (text != null ? text : "").getBytes("UTF-8");
                out.write(b);
            } finally {
                try { out.close(); } catch (Throwable ignored) {}
            }
        } catch (Throwable ignored) {
            // ignore
        }
    }

    private static class AdminMpPreferenceCheckResult {
        final boolean checked;
        final boolean excluded;
        final String details;

        AdminMpPreferenceCheckResult(boolean checked, boolean excluded, String details) {
            this.checked = checked;
            this.excluded = excluded;
            this.details = details;
        }
    }

    /**
     * Run a ONE-TIME elevated (UAC) check that reads Defender exclusions via:
     * `Get-MpPreference | Select-Object -ExpandProperty ExclusionPath`
     *
     * We cannot capture stdout from an elevated ShellExecuteEx call, so we write results to a temp file.
     */
    private static AdminMpPreferenceCheckResult checkDefenderExclusionViaMpPreferenceAdminOnce(String path) {
        if (!isWindows()) {
            return new AdminMpPreferenceCheckResult(false, false, "Not Windows");
        }

        String wanted = normalizePathForDefenderExclusionCheck(path);
        if (wanted.isEmpty()) {
            return new AdminMpPreferenceCheckResult(false, false, "Empty path");
        }

        String psExe = getPowerShellExePath();
        if (psExe == null || psExe.trim().isEmpty()) {
            return new AdminMpPreferenceCheckResult(false, false, "PowerShell not available");
        }

        File script = null;
        File outFile = null;
        try {
            script = File.createTempFile("easyinject-defender-check-", ".ps1");
            script.deleteOnExit();
            outFile = File.createTempFile("easyinject-defender-check-", ".txt");
            outFile.deleteOnExit();

            String scriptText =
                "param([string]$OutFile)\n" +
                "$ErrorActionPreference='Stop'\n" +
                "try {\n" +
                "  Get-MpPreference | Select-Object -ExpandProperty ExclusionPath | ForEach-Object { $_ } | Out-File -FilePath $OutFile -Encoding UTF8 -Force\n" +
                "  exit 0\n" +
                "} catch {\n" +
                "  ($_.Exception.Message) | Out-File -FilePath $OutFile -Encoding UTF8 -Force\n" +
                "  exit 1\n" +
                "}\n";

            FileWriter fw = new FileWriter(script);
            try {
                fw.write(scriptText);
            } finally {
                try { fw.close(); } catch (Throwable ignored) {}
            }

            // Always elevate per requirement: one UAC prompt on startup for this check.
            // Keep the PowerShell window hidden (UAC prompt still appears).
            String params = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File \"" + script.getAbsolutePath() + "\" -OutFile \"" + outFile.getAbsolutePath() + "\"";
            ExecResult elevated = execElevatedAndWait(psExe, params, 90_000);
            if (elevated.exitCode != 0) {
                String details = elevated.output != null && !elevated.output.trim().isEmpty() ? elevated.output.trim() : "Admin check failed or was cancelled";
                // Try to read any message written by the script.
                String fileMsg = safeReadSmallTextFile(outFile);
                if (fileMsg != null && !fileMsg.trim().isEmpty()) {
                    details = details + ": " + fileMsg.trim();
                }
                return new AdminMpPreferenceCheckResult(true, false, details);
            }

            String out = safeReadSmallTextFile(outFile);
            if (out == null) {
                return new AdminMpPreferenceCheckResult(true, false, "Admin check produced no output");
            }

            String[] lines = out.split("\\r?\\n");
            for (String line : lines) {
                if (line == null) {
                    continue;
                }
                String exclusion = normalizePathForDefenderExclusionCheck(line);
                if (exclusion.isEmpty()) {
                    continue;
                }
                if (isPathCoveredByExclusion(exclusion, wanted)) {
                    return new AdminMpPreferenceCheckResult(true, true, null);
                }
            }

            return new AdminMpPreferenceCheckResult(true, false, null);
        } catch (Throwable t) {
            return new AdminMpPreferenceCheckResult(false, false, t.getClass().getName() + ": " + t.getMessage());
        }
    }

    private static String safeReadSmallTextFile(File f) {
        if (f == null) {
            return null;
        }
        try {
            if (!f.exists() || !f.isFile()) {
                return null;
            }
        } catch (Throwable ignored) {
            return null;
        }

        InputStream in = null;
        try {
            in = new java.io.FileInputStream(f);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int total = 0;
            int n;
            while ((n = in.read(buf)) >= 0) {
                baos.write(buf, 0, n);
                total += n;
                if (total > 256 * 1024) {
                    break; // safety cap
                }
            }
            return new String(baos.toByteArray(), "UTF-8");
        } catch (Throwable ignored) {
            return null;
        } finally {
            if (in != null) {
                try { in.close(); } catch (Throwable ignored) {}
            }
        }
    }

    private static boolean isWindows() {
        try {
            String os = System.getProperty("os.name");
            return os != null && os.toLowerCase().contains("windows");
        } catch (Throwable ignored) {
            return false;
        }
    }

    /**
     * Folder name used under %USERPROFILE%/.config for persistent DLL extraction.
      * Derived from branding name, sanitized for filesystem safety.
     */
    private static String getBrandedConfigFolderName() {
        String name = null;
        try {
            name = PROJECT_NAME;
        } catch (Throwable ignored) {
            name = null;
        }

        if (name == null) {
            name = "";
        }
        name = name.trim();
        if (name.isEmpty()) {
            return "app";
        }

        // Keep the branded name readable, but remove characters that are invalid in filenames
        // and might accidentally create subpaths.
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            // Windows-invalid: < > : " / \ | ? *
            if (c == '<' || c == '>' || c == ':' || c == '"' || c == '/' || c == '\\' || c == '|' || c == '?' || c == '*') {
                sb.append('-');
            } else {
                sb.append(c);
            }
        }

        String out = sb.toString().trim();
        // Windows also dislikes trailing dots/spaces in path segments.
        while (out.endsWith(".") || out.endsWith(" ")) {
            out = out.substring(0, out.length() - 1);
        }

        if (out.isEmpty()) {
            return "app";
        }
        return out;
    }

    private static File getPreferredPersistentDllDir() {
        String userHome = null;
        try {
            userHome = System.getProperty("user.home");
        } catch (Throwable ignored) {
            userHome = null;
        }

        if (userHome == null) {
            userHome = "";
        }
        userHome = userHome.trim();

        if (userHome.isEmpty()) {
            // Extremely unlikely on Windows, but keep behavior predictable.
            return new File(new File(System.getProperty("java.io.tmpdir"), PROJECT_NAME), "dlls");
        }

        return new File(new File(new File(userHome, ".config"), getBrandedConfigFolderName()), "dlls");
    }

    private static class DefenderExclusionResult {
        final boolean success;
        final String details;

        DefenderExclusionResult(boolean success, String details) {
            this.success = success;
            this.details = details;
        }
    }

    private static DefenderExclusionResult tryAddWindowsDefenderExclusionWithUac(File dir) {
        if (dir == null) {
            return new DefenderExclusionResult(false, "No directory provided");
        }
        if (!isWindows()) {
            return new DefenderExclusionResult(true, null);
        }

        String path = normalizePathForDefenderExclusionCheck(dir.getAbsolutePath());

        // Single-UAC policy:
        // We intentionally consolidate all elevated operations into ONE PowerShell elevation.
        // This prevents scenarios where we would prompt multiple times (e.g. elevated reg.exe + elevated PS).
        final String exclusionsKey = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths";

        // If already present, treat as success.
        if (isDefenderExclusionPresent(exclusionsKey, path)) {
            return new DefenderExclusionResult(true, null);
        }

        DefenderExclusionResult r = tryAddWindowsDefenderExclusionViaMpPreference(dir);
        // If the PowerShell script returned success, it already verified exclusion state while running elevated.
        // Do not re-check using non-admin methods here.
        if (r != null && r.success) {
            return new DefenderExclusionResult(true, null);
        }

        String details = (r != null && r.details != null && !r.details.trim().isEmpty())
            ? r.details.trim()
            : "Access denied, UAC cancelled, or blocked by Defender policy/tamper protection";
        return new DefenderExclusionResult(false, details);
    }

    private static DefenderExclusionResult tryAddWindowsDefenderExclusionViaMpPreference(File dir) {
        if (dir == null) {
            return new DefenderExclusionResult(false, "No directory provided");
        }
        if (!isWindows()) {
            return new DefenderExclusionResult(true, null);
        }

        String path = dir.getAbsolutePath();
        String psExe = getPowerShellExePath();
        if (psExe == null || psExe.trim().isEmpty()) {
            return new DefenderExclusionResult(false, "PowerShell not available");
        }

        File script = null;
        try {
            script = File.createTempFile("easyinject-defender-", ".ps1");
            script.deleteOnExit();

            // NOTE: This script is used in the single-UAC flow.
            // It attempts both the Defender cmdlets (Get/Add-MpPreference) and the registry exclusion key.
            // It also re-checks coverage (parent exclusion covers child) to avoid unnecessary failures.
            String scriptText =
                "param([string]$TargetPath)\n" +
                "$ErrorActionPreference='Stop'\n" +
                "function Normalize([string]$p) {\n" +
                "  if ($p -eq $null) { return '' }\n" +
                "  $s = ($p.ToString()).Trim()\n" +
                "  if ($s.Length -gt 0 -and [int]$s[0] -eq 0xFEFF) { $s = $s.Substring(1).Trim() }\n" +
                "  if (($s.StartsWith('\\\"') -and $s.EndsWith('\\\"')) -or ($s.StartsWith(" +
                "'\''" +
                " ) -and $s.EndsWith(" +
                "'\''" +
                "))) { $s = $s.Substring(1, $s.Length-2).Trim() }\n" +
                "  $s = $s -replace '/', '\\\\'\n" +
                "  if ($s.StartsWith('\\\\?\\UNC\\')) { $s = '\\\\' + $s.Substring(8) }\n" +
                "  elseif ($s.StartsWith('\\\\?\\')) { $s = $s.Substring(4) }\n" +
                "  try { $s = [System.IO.Path]::GetFullPath($s) } catch {}\n" +
                "  while ($s.EndsWith('\\\\') -and $s.Length -gt 3) {\n" +
                "    if ($s.Length -le 3) { break }\n" +
                "    if ($s.Length -eq 3 -and $s[1] -eq ':' -and $s[2] -eq '\\\\') { break }\n" +
                "    $s = $s.Substring(0, $s.Length-1)\n" +
                "  }\n" +
                "  if ($s.EndsWith('\\\\*')) { $s = $s.Substring(0, $s.Length-2) }\n" +
                "  return $s\n" +
                "}\n" +
                "function Covered([string]$ex, [string]$want) {\n" +
                "  $e = (Normalize $ex)\n" +
                "  $w = (Normalize $want)\n" +
                "  if ([string]::IsNullOrWhiteSpace($e) -or [string]::IsNullOrWhiteSpace($w)) { return $false }\n" +
                "  if ($e.Equals($w, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }\n" +
                "  if (-not $e.EndsWith('\\\\')) { $e = $e + '\\\\' }\n" +
                "  if (-not $w.EndsWith('\\\\')) { $w = $w + '\\\\' }\n" +
                "  return $w.StartsWith($e, [System.StringComparison]::OrdinalIgnoreCase)\n" +
                "}\n" +
                "try {\n" +
                "  if (-not (Test-Path -LiteralPath $TargetPath)) { New-Item -ItemType Directory -Force -Path $TargetPath | Out-Null }\n" +
                "  $want = Normalize $TargetPath\n" +
                "  $already = $false\n" +
                "  try {\n" +
                "    $pref = Get-MpPreference\n" +
                "    if ($pref -ne $null -and $pref.ExclusionPath -ne $null) {\n" +
                "      foreach ($ex in $pref.ExclusionPath) { if (Covered $ex $want) { $already = $true; break } }\n" +
                "    }\n" +
                "  } catch { }\n" +
                "  if (-not $already) {\n" +
                "    try { Add-MpPreference -ExclusionPath $TargetPath | Out-Null } catch { }\n" +
                "  }\n" +
                "  # Also add registry exclusion value (best effort).\n" +
                "  try {\n" +
                "    $regPath = 'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths'\n" +
                "    if (-not (Test-Path -LiteralPath $regPath)) { New-Item -Path $regPath -Force | Out-Null }\n" +
                "    New-ItemProperty -Path $regPath -Name $want -PropertyType DWord -Value 0 -Force | Out-Null\n" +
                "  } catch { }\n" +
                "  # Re-check (cmdlet first, registry second). Defender can update asynchronously,\n" +
                "  # so retry for a short period before failing.\n" +
                "  $ok = $false\n" +
                "  for ($i = 0; $i -lt 15 -and -not $ok; $i++) {\n" +
                "    try {\n" +
                "      $pref2 = Get-MpPreference\n" +
                "      if ($pref2 -ne $null -and $pref2.ExclusionPath -ne $null) {\n" +
                "        foreach ($ex2 in $pref2.ExclusionPath) { if (Covered $ex2 $want) { $ok = $true; break } }\n" +
                "      }\n" +
                "    } catch { }\n" +
                "    if (-not $ok) {\n" +
                "      try {\n" +
                "        $regPath2 = 'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths'\n" +
                "        $props = (Get-ItemProperty -Path $regPath2 -ErrorAction Stop).PSObject.Properties\n" +
                "        foreach ($pr in $props) {\n" +
                "          if ($pr.Name -in 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') { continue }\n" +
                "          if (Covered $pr.Name $want) { $ok = $true; break }\n" +
                "        }\n" +
                "      } catch { }\n" +
                "    }\n" +
                "    if (-not $ok) { Start-Sleep -Milliseconds 300 }\n" +
                "  }\n" +
                "  if ($ok) { exit 0 }\n" +
                "  Write-Output 'Defender exclusion still not detected after attempt.'\n" +
                "  exit 1\n" +
                "} catch {\n" +
                "  Write-Output ($_.Exception.Message)\n" +
                "  exit 1\n" +
                "}\n";

            FileWriter fw = new FileWriter(script);
            try {
                fw.write(scriptText);
            } finally {
                try { fw.close(); } catch (Throwable ignored) {}
            }

            // 1) Try without elevation first (no UAC).
            ExecResult direct = execCommandCapture(new String[] {
                psExe,
                "-NoProfile",
                "-WindowStyle", "Hidden",
                "-ExecutionPolicy", "Bypass",
                "-File", script.getAbsolutePath(),
                "-TargetPath", path
            });
            if (direct.exitCode == 0) {
                return new DefenderExclusionResult(true, null);
            }

            // 2) Elevate once via UAC.
            // Keep the PowerShell window hidden (UAC prompt still appears).
            String params = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File \"" + script.getAbsolutePath() + "\" -TargetPath \"" + path + "\"";
            ExecResult elevated = execElevatedAndWait(psExe, params, 90_000);
            if (elevated.exitCode == 0) {
                return new DefenderExclusionResult(true, null);
            }

            String details = (direct.output != null && !direct.output.trim().isEmpty()) ? direct.output.trim() : "Add-MpPreference failed";
            if (elevated.output != null && !elevated.output.trim().isEmpty()) {
                details = details + "\n" + elevated.output.trim();
            }
            return new DefenderExclusionResult(false, details);
        } catch (Throwable t) {
            return new DefenderExclusionResult(false, t.getClass().getName() + ": " + t.getMessage());
        }
    }

    private static String getPowerShellExePath() {
        String root = null;
        try {
            root = System.getenv("SystemRoot");
        } catch (Throwable ignored) {
            root = null;
        }
        if (root != null) {
            root = root.trim();
        }
        if (root != null && !root.isEmpty()) {
            String p = root + "\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
            try {
                if (new File(p).isFile()) {
                    return p;
                }
            } catch (Throwable ignored) {
                // ignore
            }
        }
        return "powershell.exe";
    }

    private static class ExecResult {
        final int exitCode;
        final String output;

        ExecResult(int exitCode, String output) {
            this.exitCode = exitCode;
            this.output = output;
        }
    }

    private static boolean isDefenderExclusionPresentViaRegistry(String key, String path) {
        String wanted = normalizePathForDefenderExclusionCheck(path);
        if (wanted.isEmpty()) {
            return false;
        }

        // More robust than querying a single value name:
        // - Handles short/long path differences (canonicalization)
        // - Handles parent-folder exclusions (coverage)
        // - Handles entries that include trailing backslash or "\*" forms
        List<String> excluded = regListValueNamesInAnyView(key);
        if (excluded == null || excluded.isEmpty()) {
            return false;
        }

        for (String ex : excluded) {
            if (ex == null) {
                continue;
            }

            String candidate = normalizePathForDefenderExclusionCheck(ex);
            if (candidate.isEmpty()) {
                continue;
            }
            if (isPathCoveredByExclusion(candidate, wanted)) {
                return true;
            }
        }

        return false;
    }

    private static boolean isDefenderExclusionPresent(String exclusionsKey, String path) {
        // Check both:
        // 1) Registry (fast, no dependencies)
        // 2) Defender API (Get-MpPreference) because Windows Security can show exclusions that are not
        //    readable via our registry query approach (Tamper Protection / implementation differences).
        if (isDefenderExclusionPresentViaRegistry(exclusionsKey, path)) {
            return true;
        }

        return isDefenderExclusionPresentViaMpPreference(path);
    }

    private static boolean isDefenderExclusionPresentViaMpPreference(String path) {
        if (!isWindows()) {
            return false;
        }

        String wanted = normalizePathForDefenderExclusionCheck(path);
        if (wanted.isEmpty()) {
            return false;
        }

        String psExe = getPowerShellExePath();
        if (psExe == null || psExe.trim().isEmpty()) {
            return false;
        }

        // Print each exclusion on its own line. Avoid formatting noise.
        // IMPORTANT: Some systems require elevation to read ExclusionPath. We MUST NOT
        // trigger UAC prompts from a "check" method (it may be called in a polling loop).
        // So we only attempt the non-elevated query here and treat failures as "unknown/false".
        ExecResult r = execCommandCapture(new String[] {
            psExe,
            "-NoProfile",
            "-WindowStyle", "Hidden",
            "-ExecutionPolicy", "Bypass",
            "-Command",
            "try { (Get-MpPreference).ExclusionPath | ForEach-Object { $_ } } catch { exit 1 }"
        });
        if (r.exitCode != 0 || r.output == null) {
            return false;
        }

        String[] lines = r.output.split("\\r?\\n");
        for (String line : lines) {
            if (line == null) {
                continue;
            }
            String exclusion = normalizePathForDefenderExclusionCheck(line);
            if (exclusion.isEmpty()) {
                continue;
            }

            if (isPathCoveredByExclusion(exclusion, wanted)) {
                return true;
            }
        }

        return false;
    }

    private static boolean regValueExistsInAnyView(String key, String valueName) {
        // Try default view, then explicit 64-bit, then explicit 32-bit.
        ExecResult q0 = execCommandCapture(new String[] { getRegExePath(), "query", key, "/v", valueName });
        if (q0.exitCode == 0) {
            return true;
        }

        ExecResult q64 = execCommandCapture(new String[] { getRegExePath(), "query", key, "/v", valueName, "/reg:64" });
        if (q64.exitCode == 0) {
            return true;
        }

        ExecResult q32 = execCommandCapture(new String[] { getRegExePath(), "query", key, "/v", valueName, "/reg:32" });
        return q32.exitCode == 0;
    }

    private static String normalizePathForDefenderExclusionCheck(String path) {
        if (path == null) {
            return "";
        }
        String p = path.trim();
        if (p.isEmpty()) {
            return "";
        }

        // Strip a UTF-8 BOM if present (can appear at the start of captured PowerShell output).
        if (!p.isEmpty() && p.charAt(0) == '\uFEFF') {
            p = p.substring(1).trim();
        }

        // Strip wrapping quotes (common when parsing command output).
        if ((p.startsWith("\"") && p.endsWith("\"")) || (p.startsWith("'") && p.endsWith("'"))) {
            if (p.length() >= 2) {
                p = p.substring(1, p.length() - 1).trim();
            }
        }

        // Normalize separators.
        p = p.replace('/', '\\');

        // Strip a common wildcard suffix sometimes used in exclusions.
        if (p.endsWith("\\*")) {
            p = p.substring(0, p.length() - 2);
        }

        // Strip Win32 extended-length prefix (\?\ and \?\UNC\) if present.
        if (p.startsWith("\\\\?\\UNC\\")) {
            p = "\\\\" + p.substring("\\\\?\\UNC\\".length());
        } else if (p.startsWith("\\\\?\\")) {
            p = p.substring("\\\\?\\".length());
        }

        // Best-effort canonicalization to avoid mismatches like ".." segments.
        try {
            p = new File(p).getCanonicalPath();
        } catch (Throwable ignored) {
            // ignore
        }

        // Defender exclusions are typically stored without a trailing slash.
        while (p.endsWith("\\")) {
            // Keep root paths like C:\\ intact.
            if (p.length() <= 3 && p.charAt(1) == ':' && p.charAt(2) == '\\') {
                break;
            }
            // Keep UNC roots like \\\\server\\share intact.
            if (p.startsWith("\\\\")) {
                String rest = p.substring(2);
                int s1 = rest.indexOf('\\');
                if (s1 > 0) {
                    int s2 = rest.indexOf('\\', s1 + 1);
                    if (s2 < 0 && p.endsWith("\\")) {
                        // \\\\server\\share\\
                        break;
                    }
                }
            }
            p = p.substring(0, p.length() - 1);
        }

        return p;
    }

    /**
     * Enumerate value names under a registry key in default, 64-bit, and 32-bit views.
     * Returns an empty list if the key cannot be queried.
     */
    private static List<String> regListValueNamesInAnyView(String key) {
        if (!isWindows()) {
            return Collections.emptyList();
        }
        if (key == null || key.trim().isEmpty()) {
            return Collections.emptyList();
        }

        LinkedHashSet<String> out = new LinkedHashSet<String>();
        regListValueNamesFromQuery(out, new String[] { getRegExePath(), "query", key });
        regListValueNamesFromQuery(out, new String[] { getRegExePath(), "query", key, "/reg:64" });
        regListValueNamesFromQuery(out, new String[] { getRegExePath(), "query", key, "/reg:32" });
        return new ArrayList<String>(out);
    }

    private static void regListValueNamesFromQuery(Set<String> sink, String[] cmd) {
        if (sink == null || cmd == null) {
            return;
        }
        ExecResult r = execCommandCapture(cmd);
        if (r == null || r.exitCode != 0 || r.output == null) {
            return;
        }

        String[] lines = r.output.split("\\r?\\n");
        Pattern valueLine = Pattern.compile("^\\s*(.+?)\\s+REG_[A-Z0-9_]+\\s+.*$", Pattern.CASE_INSENSITIVE);
        for (String line : lines) {
            if (line == null) {
                continue;
            }
            String t = line.trim();
            if (t.isEmpty()) {
                continue;
            }
            // Skip the header line which is the key path.
            if (t.toUpperCase().startsWith("HKEY_")) {
                continue;
            }
            Matcher m = valueLine.matcher(line);
            if (m.matches()) {
                String name = m.group(1);
                if (name != null) {
                    String n = name.trim();
                    if (!n.isEmpty()) {
                        sink.add(n);
                    }
                }
            }
        }
    }

    /**
     * Returns true if an exclusion path covers the wanted path.
     * Defender exclusions are effectively folder-based, so an exclusion of a parent directory should
     * be treated as covering all children.
     */
    private static boolean isPathCoveredByExclusion(String exclusionPath, String wantedPath) {
        if (exclusionPath == null || wantedPath == null) {
            return false;
        }
        String exclusion = normalizePathForDefenderExclusionCheck(exclusionPath);
        String wanted = normalizePathForDefenderExclusionCheck(wantedPath);
        if (exclusion.isEmpty() || wanted.isEmpty()) {
            return false;
        }

        // Exact match (case-insensitive on Windows).
        if (exclusion.equalsIgnoreCase(wanted)) {
            return true;
        }

        // Parent directory match with boundary.
        String ex = exclusion;
        if (!ex.endsWith("\\")) {
            ex = ex + "\\";
        }
        String w = wanted;
        if (!w.endsWith("\\")) {
            w = w + "\\";
        }
        return w.regionMatches(true, 0, ex, 0, ex.length());
    }

    /**
     * Get parent path for walking up a directory tree.
     * Returns null when no parent exists.
     */
    private static String parentPath(String p) {
        if (p == null) {
            return null;
        }
        String s = normalizePathForDefenderExclusionCheck(p);
        if (s.isEmpty()) {
            return null;
        }

        // Stop at drive root (e.g. C:\).
        if (s.length() <= 3 && s.charAt(1) == ':' && s.charAt(2) == '\\') {
            return null;
        }

        // Stop at UNC share root (e.g. \\\\server\\share).
        if (s.startsWith("\\\\")) {
            String rest = s.substring(2);
            int s1 = rest.indexOf('\\');
            if (s1 > 0) {
                int s2 = rest.indexOf('\\', s1 + 1);
                if (s2 < 0) {
                    return null;
                }
            }
        }

        int idx = s.lastIndexOf('\\');
        if (idx <= 0) {
            return null;
        }
        return s.substring(0, idx);
    }

    private static String getRegExePath() {
        // Prefer absolute path to avoid path redirection weirdness.
        String root = null;
        try {
            root = System.getenv("SystemRoot");
        } catch (Throwable ignored) {
            root = null;
        }
        if (root != null) {
            root = root.trim();
        }
        if (root == null || root.isEmpty()) {
            return "reg.exe";
        }
        return root + "\\System32\\reg.exe";
    }

    private static ExecResult execCommandCapture(String[] command) {
        try {
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(true);
            Process p = pb.start();

            String out;
            InputStream in = p.getInputStream();
            try {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                byte[] buf = new byte[4096];
                int n;
                while ((n = in.read(buf)) >= 0) {
                    baos.write(buf, 0, n);
                }
                out = baos.toString();
            } finally {
                try { in.close(); } catch (Throwable ignored) {}
            }

            int code = p.waitFor();
            return new ExecResult(code, out);
        } catch (Throwable t) {
            return new ExecResult(1, t.getClass().getName() + ": " + t.getMessage());
        }
    }

    private static ExecResult execElevatedAndWait(String file, String parameters, int timeoutMs) {
        if (!isWindows()) {
            return new ExecResult(1, "Not running on Windows");
        }

        try {
            ShellAPI.SHELLEXECUTEINFO sei = new ShellAPI.SHELLEXECUTEINFO();
            // SEE_MASK_NOCLOSEPROCESS (0x00000040) - request process handle so we can wait
            sei.fMask = 0x00000040;
            sei.lpVerb = "runas";
            sei.lpFile = file;
            sei.lpParameters = parameters;
            // Hide the spawned process window (UAC prompt is separate and still appears).
            sei.nShow = 0; // SW_HIDE
            sei.write();

            boolean ok = Shell32.INSTANCE.ShellExecuteEx(sei);
            if (!ok) {
                int err = Kernel32.INSTANCE.GetLastError();
                // ERROR_CANCELLED (1223) is the common “user cancelled UAC” case.
                if (err == 1223) {
                    return new ExecResult(1, "UAC prompt was cancelled");
                }
                return new ExecResult(1, "ShellExecuteEx failed (GetLastError=" + err + ")");
            }

            sei.read();
            WinNT.HANDLE hProcess = sei.hProcess;
            if (hProcess == null) {
                return new ExecResult(1, "Elevated process handle missing");
            }

            int waitRes = Kernel32.INSTANCE.WaitForSingleObject(hProcess, timeoutMs > 0 ? timeoutMs : WinBase.INFINITE);
            // WAIT_TIMEOUT = 0x00000102
            if (waitRes == 0x00000102) {
                try { Kernel32.INSTANCE.CloseHandle(hProcess); } catch (Throwable ignored) {}
                return new ExecResult(1, "Timed out waiting for elevated process");
            }

            IntByReference exitCode = new IntByReference();
            boolean got = Kernel32.INSTANCE.GetExitCodeProcess(hProcess, exitCode);
            try { Kernel32.INSTANCE.CloseHandle(hProcess); } catch (Throwable ignored) {}

            if (!got) {
                int err = Kernel32.INSTANCE.GetLastError();
                return new ExecResult(1, "GetExitCodeProcess failed (GetLastError=" + err + ")");
            }

            int code = exitCode.getValue();
            return new ExecResult(code, "");
        } catch (Throwable t) {
            return new ExecResult(1, t.getClass().getName() + ": " + t.getMessage());
        }
    }

    private static void showNonFatalWarningDialog(String warning) {
        try {
            applyDarkTheme();
            String message =
                "<html><body style='width: 360px; font-family: Segoe UI, sans-serif; color: #e0e0e0;'>" +
                "<p style='margin:0 0 10px 0; color: #FFB300; font-size: 15px;'><b>⚠ Setup Warning</b></p>" +
                "<pre style='white-space: pre-wrap; font-family: Segoe UI, sans-serif; color: #c7ced6; margin:0;'>" +
                escapeHtml(warning) +
                "</pre>" +
                "</body></html>";

            javax.swing.JLabel msgLabel = new javax.swing.JLabel(message);
            javax.swing.JButton okButton = createStyledButton("OK");
            okButton.addActionListener(new java.awt.event.ActionListener() {
                public void actionPerformed(java.awt.event.ActionEvent e) {
                    java.awt.Window w = javax.swing.SwingUtilities.getWindowAncestor(okButton);
                    if (w != null) w.dispose();
                }
            });

            javax.swing.JOptionPane.showOptionDialog(
                null,
                msgLabel,
                PROJECT_NAME + " v" + VERSION + " — Warning",
                javax.swing.JOptionPane.DEFAULT_OPTION,
                javax.swing.JOptionPane.PLAIN_MESSAGE,
                null,
                new Object[]{ okButton },
                okButton
            );
        } catch (Throwable ignored) {
            // Best effort; do not block install.
        }
    }

    private static String escapeHtml(String s) {
        if (s == null) {
            return "";
        }
        return s
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#39;");
    }

    /**
     * Result of attempting to install the PreLaunchCommand.
     */
    private static class InstallResult {
        boolean success;
        String error;
        
        InstallResult(boolean success, String error) {
            this.success = success;
            this.error = error;
        }
    }

    /**
     * Result of merging an existing PreLaunchCommand with the new command.
     */
    private static class MergeResult {
        boolean proceed;
        String mergedCommand;

        MergeResult(boolean proceed, String mergedCommand) {
            this.proceed = proceed;
            this.mergedCommand = mergedCommand;
        }
    }

    /**
     * Install the PreLaunchCommand into instance.cfg (MultiMC/Prism).
     */
    private static InstallResult installPreLaunchCommand(File instanceCfg, String command) {
        try {
            // Read entire file
            java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.FileReader(instanceCfg));
            List<String> lines = new ArrayList<String>();
            String line;
            boolean foundPreLaunch = false;
            boolean foundOverrideCommands = false;
            String existingPreLaunch = null;
            
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("PreLaunchCommand=") && !foundPreLaunch) {
                    existingPreLaunch = line.substring("PreLaunchCommand=".length());
                    lines.add(line);
                    foundPreLaunch = true;
                } else if (line.startsWith("OverrideCommands=")) {
                    lines.add(line);
                    foundOverrideCommands = true;
                } else {
                    lines.add(line);
                }
            }
            reader.close();

            String mergedCommand = command;
            if (command != null && !command.trim().isEmpty()) {
                MergeResult mergeResult = resolvePrismPreLaunchCommand(existingPreLaunch, command);
                if (!mergeResult.proceed) {
                    return new InstallResult(false, "Installation cancelled by user.");
                }
                mergedCommand = mergeResult.mergedCommand;
            }

            if (command != null && !command.trim().isEmpty()) {
                InstallResult closeResult = closeLaunchersBeforePreLaunchUpdate();
                if (!closeResult.success) {
                    return closeResult;
                }
            }

            // Rewrite with updated values (while avoiding duplicate PreLaunchCommand entries)
            List<String> updated = new ArrayList<String>();
            boolean wrotePreLaunch = false;
            boolean wroteOverrideCommands = false;

            for (String original : lines) {
                if (original.startsWith("PreLaunchCommand=")) {
                    if (!wrotePreLaunch) {
                        updated.add("PreLaunchCommand=" + (mergedCommand != null ? mergedCommand : ""));
                        wrotePreLaunch = true;
                    }
                } else if (original.startsWith("OverrideCommands=")) {
                    updated.add("OverrideCommands=true");
                    wroteOverrideCommands = true;
                } else {
                    updated.add(original);
                }
            }
            
            // If PreLaunchCommand wasn't found, add it only when non-empty command is requested
            if (!wrotePreLaunch && mergedCommand != null && (!mergedCommand.isEmpty() || command != null)) {
                updated.add("PreLaunchCommand=" + mergedCommand);
            }
            
            // If OverrideCommands wasn't found, add it
            if (!wroteOverrideCommands && (command != null && !command.trim().isEmpty())) {
                updated.add("OverrideCommands=true");
            }
            
            // Write back the file
            PrintWriter writer = new PrintWriter(new FileWriter(instanceCfg));
            for (String l : updated) {
                writer.println(l);
            }
            writer.close();
            
            return new InstallResult(true, null);
            
        } catch (Exception e) {
            return new InstallResult(false, e.getMessage());
        }
    }

    /**
     * Resolve Prism/MultiMC pre-launch command. Since Prism supports only one
     * pre-launch command, non-EasyInject commands are forwarded as arguments to our JAR.
     */
    private static MergeResult resolvePrismPreLaunchCommand(String existingCommand, String newCommand) {
        if (newCommand == null) {
            return new MergeResult(true, "");
        }

        String baseCommand = unwrapCmdWrapper(newCommand).trim();
        if (baseCommand.isEmpty()) {
            return new MergeResult(true, "");
        }

        String existing = existingCommand != null ? existingCommand.trim() : "";
        if (existing.isEmpty()) {
            return new MergeResult(true, baseCommand);
        }

        List<String> parts = splitPreLaunchCommands(existing);
        if (parts.isEmpty()) {
            return new MergeResult(true, baseCommand);
        }

        List<String> directNonOurs = new ArrayList<String>();
        List<String> forwardedFromOurOld = new ArrayList<String>();

        for (String part : parts) {
            if (isOurPreLaunchSegment(part)) {
                String forwarded = extractForwardedPreLaunchChainFromSegment(part);
                if (!forwarded.isEmpty()) {
                    forwardedFromOurOld.add(forwarded);
                }
            } else {
                directNonOurs.add(part);
            }
        }

        List<String> allForwarded = new ArrayList<String>();
        allForwarded.addAll(directNonOurs);
        allForwarded.addAll(forwardedFromOurOld);

        if (allForwarded.isEmpty()) {
            return new MergeResult(true, baseCommand);
        }

        String forwardedChain = joinPreLaunchCommands(allForwarded);
        String escapedForwarded = escapeForwardedPreLaunchChain(forwardedChain);
        String keepCommand = baseCommand + " " + FORWARDED_PRELAUNCH_CHAIN_ARG + " \\\"" + escapedForwarded + "\\\"";
        String replaceCommand = baseCommand;

        // If only previously-forwarded commands exist (no direct external command in cfg), keep silently.
        if (directNonOurs.isEmpty()) {
            return new MergeResult(true, keepCommand);
        }

        int choice = showPrismPreLaunchMergeChoice(existing, keepCommand, replaceCommand);
        if (choice == 0) {
            return new MergeResult(true, keepCommand);
        }
        if (choice == 1) {
            return new MergeResult(true, replaceCommand);
        }

        return new MergeResult(false, existing);
    }

    /**
     * Install the PreLaunchCommand into instance.json (ATLauncher).
     * Sets "enableCommands": true and "preLaunchCommand": "<command>" inside the "launcher" object.
     */
    private static InstallResult installPreLaunchCommandJson(File instanceJson, String command) {
        try {
            // Read entire file
            java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.FileReader(instanceJson));
            List<String> lines = new ArrayList<String>();
            String line;
            boolean foundEnableCommands = false;
            boolean foundPreLaunchCommand = false;
            int launcherBraceLine = -1; // line index of the opening brace after "launcher"
            int preLaunchLineIndex = -1;
            String existingPreLaunch = null;
            
            while ((line = reader.readLine()) != null) {
                lines.add(line);
            }
            reader.close();
            
            // Process lines - find and replace values
            for (int i = 0; i < lines.size(); i++) {
                String trimmed = lines.get(i).trim();
                
                // Track the launcher object opening
                if (trimmed.startsWith("\"launcher\"") && trimmed.contains("{")) {
                    launcherBraceLine = i;
                } else if (launcherBraceLine >= 0 && !foundEnableCommands && trimmed.equals("\"launcher\": {")) {
                    // Handle case where brace is on same line
                    launcherBraceLine = i;
                }
                
                // Replace enableCommands
                if (trimmed.startsWith("\"enableCommands\"")) {
                    String indent = lines.get(i).substring(0, lines.get(i).indexOf('"'));
                    boolean needsComma = trimmed.endsWith(",");
                    lines.set(i, indent + "\"enableCommands\": true" + (needsComma ? "," : ""));
                    foundEnableCommands = true;
                }
                
                // Track preLaunchCommand
                if (trimmed.startsWith("\"preLaunchCommand\"")) {
                    preLaunchLineIndex = i;
                    existingPreLaunch = extractJsonStringValue(lines.get(i));
                    foundPreLaunchCommand = true;
                }
            }

            String mergedCommand = command;
            if (command != null && !command.trim().isEmpty()) {
                MergeResult mergeResult = mergePreLaunchCommand(existingPreLaunch, command);
                if (!mergeResult.proceed) {
                    return new InstallResult(false, "Installation cancelled by user.");
                }
                mergedCommand = mergeResult.mergedCommand;
            }

            if (command != null && !command.trim().isEmpty()) {
                InstallResult closeResult = closeLaunchersBeforePreLaunchUpdate();
                if (!closeResult.success) {
                    return closeResult;
                }
            }

            if (foundPreLaunchCommand && preLaunchLineIndex >= 0) {
                String trimmed = lines.get(preLaunchLineIndex).trim();
                String indent = lines.get(preLaunchLineIndex).substring(0, lines.get(preLaunchLineIndex).indexOf('"'));
                boolean needsComma = trimmed.endsWith(",");
                String escapedCommand = (mergedCommand != null ? mergedCommand : "").replace("\\", "\\\\").replace("\"", "\\\"");
                lines.set(preLaunchLineIndex, indent + "\"preLaunchCommand\": \"" + escapedCommand + "\"" + (needsComma ? "," : ""));
            }
            
            // If fields weren't found, insert them after the launcher opening brace
            if ((!foundEnableCommands || !foundPreLaunchCommand) && launcherBraceLine >= 0) {
                // Detect indentation from the line after the launcher brace
                String indent = "        "; // default 8 spaces
                if (launcherBraceLine + 1 < lines.size()) {
                    String nextLine = lines.get(launcherBraceLine + 1);
                    int spaces = 0;
                    while (spaces < nextLine.length() && nextLine.charAt(spaces) == ' ') spaces++;
                    if (spaces > 0) indent = nextLine.substring(0, spaces);
                }
                
                String escapedCommand = command.replace("\\", "\\\\").replace("\"", "\\\"");
                int insertAt = launcherBraceLine + 1;
                
                if (!foundPreLaunchCommand && mergedCommand != null && !mergedCommand.isEmpty()) {
                    String escapedMerged = mergedCommand.replace("\\", "\\\\").replace("\"", "\\\"");
                    lines.add(insertAt, indent + "\"preLaunchCommand\": \"" + escapedMerged + "\",");
                }
                if (!foundEnableCommands && command != null && !command.trim().isEmpty()) {
                    lines.add(insertAt, indent + "\"enableCommands\": true,");
                }
            }
            
            // Write back the file
            PrintWriter writer = new PrintWriter(new FileWriter(instanceJson));
            for (int i = 0; i < lines.size(); i++) {
                writer.println(lines.get(i));
            }
            writer.close();
            
            return new InstallResult(true, null);
            
        } catch (Exception e) {
            return new InstallResult(false, e.getMessage());
        }
    }

    /**
     * Merge an existing pre-launch command with the new EasyInject command.
     */
    private static MergeResult mergePreLaunchCommand(String existingCommand, String newCommand) {
        // Use the same single-command forwarding behavior for all launchers.
        return resolvePrismPreLaunchCommand(existingCommand, newCommand);
    }

    /**
     * Split a pre-launch command string into individual commands.
     * Supports command chains joined by "&&" and ";".
     */
    private static List<String> splitPreLaunchCommands(String value) {
        List<String> parts = new ArrayList<String>();
        if (value == null) {
            return parts;
        }

        String normalized = unwrapCmdWrapper(value);
        StringBuilder current = new StringBuilder();
        boolean inQuotes = false;
        boolean escaped = false;

        for (int i = 0; i < normalized.length(); i++) {
            char c = normalized.charAt(i);

            if (escaped) {
                current.append(c);
                escaped = false;
                continue;
            }

            if (c == '\\') {
                current.append(c);
                escaped = true;
                continue;
            }

            if (c == '"') {
                inQuotes = !inQuotes;
                current.append(c);
                continue;
            }

            if (!inQuotes) {
                if (c == ';') {
                    String part = current.toString().trim();
                    if (!part.isEmpty()) {
                        parts.add(part);
                    }
                    current.setLength(0);
                    continue;
                }
                if (c == '&' && i + 1 < normalized.length() && normalized.charAt(i + 1) == '&') {
                    String part = current.toString().trim();
                    if (!part.isEmpty()) {
                        parts.add(part);
                    }
                    current.setLength(0);
                    i++; // skip second '&'
                    continue;
                }
            }

            current.append(c);
        }

        String part = current.toString().trim();
        if (!part.isEmpty()) {
            parts.add(part);
        }

        return parts;
    }

    /**
     * Join multiple pre-launch commands into a single command chain.
     */
    private static String joinPreLaunchCommands(List<String> parts) {
        if (parts == null || parts.isEmpty()) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < parts.size(); i++) {
            if (i > 0) {
                sb.append(" && ");
            }
            sb.append(parts.get(i));
        }
        return sb.toString();
    }

    /**
     * Determine whether a command segment belongs to this project using branding name.
     */
    private static boolean isOurPreLaunchSegment(String segment) {
        if (segment == null || segment.trim().isEmpty()) {
            return false;
        }

        String normalizedSegment = normalizeForMatch(segment);
        String normalizedProject = normalizeForMatch(PROJECT_NAME);
        if (normalizedProject.isEmpty()) {
            return false;
        }

        return normalizedSegment.contains(normalizedProject);
    }

    /**
     * Normalize strings for fuzzy command matching.
     */
    private static String normalizeForMatch(String value) {
        if (value == null) {
            return "";
        }
        String lowered = value.toLowerCase();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < lowered.length(); i++) {
            char c = lowered.charAt(i);
            if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * Ensure launcher processes are fully closed before updating pre-launch command config.
     */
    private static InstallResult closeLaunchersBeforePreLaunchUpdate() {
        String[] imageNames = new String[] {"prismlauncher.exe", "multimc.exe"};
        final long timeoutMs = 10000L;

        try {
            saveRunningLauncherPathsForRestart();

            for (String imageName : imageNames) {
                killProcessesByImageName(imageName);
            }

            long deadline = System.currentTimeMillis() + timeoutMs;
            while (System.currentTimeMillis() < deadline) {
                List<String> stillRunning = new ArrayList<String>();
                for (String imageName : imageNames) {
                    if (isProcessRunningByImageName(imageName)) {
                        stillRunning.add(imageName);
                    }
                }

                if (stillRunning.isEmpty()) {
                    return new InstallResult(true, null);
                }

                Thread.sleep(200);
                for (String imageName : stillRunning) {
                    killProcessesByImageName(imageName);
                }
            }

            List<String> stillRunning = new ArrayList<String>();
            for (String imageName : imageNames) {
                if (isProcessRunningByImageName(imageName)) {
                    stillRunning.add(imageName);
                }
            }

            if (!stillRunning.isEmpty()) {
                return new InstallResult(false, "Please close launcher processes before updating pre-launch command: " + joinPreLaunchCommands(stillRunning));
            }

            return new InstallResult(true, null);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new InstallResult(false, "Interrupted while closing launcher processes.");
        } catch (Exception e) {
            return new InstallResult(false, "Failed to close launcher processes: " + e.getMessage());
        }
    }

    /**
     * Save full executable paths of currently running launcher processes for later restart.
     */
    private static void saveRunningLauncherPathsForRestart() {
        List<String> runningPaths = getRunningLauncherExecutablePaths();
        synchronized (savedLauncherPathsForRestart) {
            for (String path : runningPaths) {
                if (path != null && !path.trim().isEmpty()) {
                    savedLauncherPathsForRestart.add(path.trim());
                }
            }
        }
    }

    /**
     * Query running launcher executable paths for PrismLauncher/MultiMC (case-insensitive).
     */
    private static List<String> getRunningLauncherExecutablePaths() {
        List<String> paths = new ArrayList<String>();

        try {
            List<ProcessUtils.ProcessInfo> launchers = ProcessUtils.findProcessesByImageNames(
                "prismlauncher.exe",
                "multimc.exe"
            );

            for (ProcessUtils.ProcessInfo proc : launchers) {
                String fullPath = ProcessUtils.getProcessExecutablePath(proc.processId);
                if (fullPath != null) {
                    String trimmed = fullPath.trim();
                    if (!trimmed.isEmpty()) {
                        paths.add(trimmed);
                    }
                }
            }
        } catch (Exception e) {
            // Best-effort capture only.
        }

        return paths;
    }

    /**
     * Relaunch previously closed launcher executables and clear the saved list.
     */
    private static void restartSavedLaunchersAfterConfirmation() {
        List<String> toRestart = new ArrayList<String>();
        synchronized (savedLauncherPathsForRestart) {
            if (savedLauncherPathsForRestart.isEmpty()) {
                return;
            }
            toRestart.addAll(savedLauncherPathsForRestart);
            savedLauncherPathsForRestart.clear();
        }

        for (String rawPath : toRestart) {
            if (rawPath == null) {
                continue;
            }
            String path = rawPath.trim();
            if (path.startsWith("\"") && path.endsWith("\"") && path.length() >= 2) {
                path = path.substring(1, path.length() - 1);
            }
            if (path.isEmpty()) {
                continue;
            }

            try {
                File exe = new File(path);
                if (!exe.exists() || !exe.isFile()) {
                    continue;
                }
                ProcessBuilder pb = new ProcessBuilder(path);
                File parent = exe.getParentFile();
                if (parent != null && parent.isDirectory()) {
                    pb.directory(parent);
                }
                pb.start();
            } catch (Exception e) {
                // Continue restarting others.
            }
        }
    }

    /**
     * Kill all processes that match an image name (case-insensitive).
     */
    private static void killProcessesByImageName(String imageName) {
        if (imageName == null || imageName.trim().isEmpty()) {
            return;
        }

        try {
            // Do NOT use /T here: Prism/MultiMC child process trees can include running Minecraft java/javaw.
            // We only want to close the launcher executable itself.
            ProcessBuilder pb = new ProcessBuilder("cmd", "/C", "taskkill /F /IM \"" + imageName + "\"");
            pb.redirectErrorStream(true);
            Process process = pb.start();
            InputStream in = process.getInputStream();
            while (in.read() != -1) {
                // drain
            }
            in.close();
            process.waitFor();
        } catch (Exception e) {
            // Best-effort; presence check below determines whether this is acceptable.
        }
    }

    /**
     * Check whether at least one process with the given image name is running.
     */
    private static boolean isProcessRunningByImageName(String imageName) {
        if (imageName == null || imageName.trim().isEmpty()) {
            return false;
        }

        try {
            ProcessBuilder pb = new ProcessBuilder(
                "cmd",
                "/C",
                "tasklist /FI \"IMAGENAME eq " + imageName + "\" /FO CSV /NH"
            );
            pb.redirectErrorStream(true);

            Process process = pb.start();
            String output = new String(readAllBytes(process.getInputStream()), "UTF-8");
            process.waitFor();

            String imageLower = imageName.toLowerCase();
            String[] rows = output.split("\\r?\\n");
            for (String row : rows) {
                if (row == null) {
                    continue;
                }
                String trimmed = row.trim();
                if (trimmed.isEmpty()) {
                    continue;
                }
                // tasklist /FO CSV /NH returns: "Image Name","PID","Session Name","Session#","Mem Usage"
                // Match the first CSV field exactly to avoid accidental substring matches.
                String normalized = trimmed;
                if (normalized.startsWith("\"") && normalized.endsWith("\"")) {
                    // keep as-is; split below handles quotes better than naive substring
                }
                String[] cols = normalized.split("\",\"");
                if (cols.length > 0) {
                    String first = cols[0].replace("\"", "").trim().toLowerCase();
                    if (imageLower.equals(first)) {
                        return true;
                    }
                }

                // Fallback for unexpected output format
                String lowered = trimmed.toLowerCase();
                if (lowered.startsWith("\"" + imageLower + "\"")) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Build a styled read-only command box with a clear border.
     */
    private static javax.swing.JScrollPane createCommandBox(String text, int rows, java.awt.Color textColor) {
        javax.swing.JTextArea area = new javax.swing.JTextArea(text != null ? text : "", rows, 64);
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setFont(new java.awt.Font("Consolas", java.awt.Font.PLAIN, 12));
        area.setBackground(new java.awt.Color(24, 24, 24));
        area.setForeground(textColor);
        area.setCaretPosition(0);
        area.setMargin(new java.awt.Insets(8, 8, 8, 8));
        area.setComponentOrientation(java.awt.ComponentOrientation.LEFT_TO_RIGHT);
        area.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);

        javax.swing.JScrollPane scroll = new javax.swing.JScrollPane(area);
        scroll.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);
        scroll.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(82, 82, 82)));
        scroll.setBackground(new java.awt.Color(24, 24, 24));
        scroll.getViewport().setBackground(new java.awt.Color(24, 24, 24));
        scroll.setHorizontalScrollBarPolicy(javax.swing.ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        return scroll;
    }

    /**
     * Ask the user how to merge with existing non-EasyInject pre-launch command(s).
     */
    private static MergeResult promptForPreLaunchMergeChoice(String existingCommand, String newCommand) {
        String mergedCommand = unwrapCmdWrapper(existingCommand) + " && " + newCommand;

        try {
            applyDarkTheme();

            javax.swing.JPanel panel = new javax.swing.JPanel();
            panel.setLayout(new javax.swing.BoxLayout(panel, javax.swing.BoxLayout.Y_AXIS));
            panel.setBorder(javax.swing.BorderFactory.createEmptyBorder(6, 2, 2, 2));
            panel.setBackground(new java.awt.Color(43, 43, 43));

            javax.swing.JLabel header = new javax.swing.JLabel("Existing Pre-Launch Command Detected");
            header.setForeground(new java.awt.Color(255, 167, 38));
            header.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, 14));
            header.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);

            javax.swing.JLabel subtext = new javax.swing.JLabel(
                "<html><body style='width: 520px; color:#ccc; text-align:left;'>"
                    + "One or more existing pre-launch commands do not appear to belong to " + PROJECT_NAME + ".<br/>"
                    + "Review the command options below, then choose to include, replace, or cancel."
                    + "</body></html>");
            subtext.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);

            javax.swing.JLabel oldLabel = new javax.swing.JLabel("Original pre-launch command found:");
            oldLabel.setForeground(new java.awt.Color(180, 180, 180));
            oldLabel.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);

            javax.swing.JScrollPane oldArea = createCommandBox(existingCommand, 3, new java.awt.Color(224, 224, 224));

            javax.swing.JLabel newLabel = new javax.swing.JLabel("Proposed merged command (includes existing command):");
            newLabel.setForeground(new java.awt.Color(180, 180, 180));
            newLabel.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);

            javax.swing.JScrollPane newArea = createCommandBox(mergedCommand, 4, new java.awt.Color(129, 212, 250));

            javax.swing.JLabel replaceLabel = new javax.swing.JLabel("New command only (replaces existing command):");
            replaceLabel.setForeground(new java.awt.Color(180, 180, 180));
            replaceLabel.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);

            javax.swing.JScrollPane replaceArea = createCommandBox(newCommand, 3, new java.awt.Color(255, 204, 128));

            panel.add(header);
            panel.add(javax.swing.Box.createVerticalStrut(8));
            panel.add(subtext);
            panel.add(javax.swing.Box.createVerticalStrut(10));
            panel.add(oldLabel);
            panel.add(javax.swing.Box.createVerticalStrut(4));
            panel.add(oldArea);
            panel.add(javax.swing.Box.createVerticalStrut(10));
            panel.add(newLabel);
            panel.add(javax.swing.Box.createVerticalStrut(4));
            panel.add(newArea);
            panel.add(javax.swing.Box.createVerticalStrut(10));
            panel.add(replaceLabel);
            panel.add(javax.swing.Box.createVerticalStrut(4));
            panel.add(replaceArea);

            Object[] options = new Object[] {
                "Include Existing Command",
                "Replace Existing Command",
                "Cancel"
            };

            int choice = javax.swing.JOptionPane.showOptionDialog(
                null,
                panel,
                PROJECT_NAME + " v" + VERSION + " — Pre-Launch Command Conflict",
                javax.swing.JOptionPane.DEFAULT_OPTION,
                javax.swing.JOptionPane.PLAIN_MESSAGE,
                null,
                options,
                options[0]
            );

            if (choice == 0) {
                return new MergeResult(true, mergedCommand);
            }
            if (choice == 1) {
                return new MergeResult(true, newCommand);
            }
            return new MergeResult(false, existingCommand);
        } catch (Exception e) {
            // Console fallback
            System.out.println("=======================================================");
            System.out.println("Existing pre-launch command(s) detected");
            System.out.println("=======================================================");
            System.out.println("Old command:");
            System.out.println("  " + existingCommand);
            System.out.println();
            System.out.println("Merged command (keep existing + add new):");
            System.out.println("  " + mergedCommand);
            System.out.println();
            System.out.println("Replace command:");
            System.out.println("  " + newCommand);
            System.out.println();
            System.out.println("Defaulting to: Keep Existing + Add New");
            return new MergeResult(true, mergedCommand);
        }
    }

    /**
     * Ask user how Prism should handle existing non-EasyInject commands.
     */
    private static int showPrismPreLaunchMergeChoice(String existingCommand, String keepCommand, String replaceCommand) {
        try {
            applyDarkTheme();

            javax.swing.JPanel panel = new javax.swing.JPanel();
            panel.setLayout(new javax.swing.BoxLayout(panel, javax.swing.BoxLayout.Y_AXIS));
            panel.setBorder(javax.swing.BorderFactory.createEmptyBorder(6, 2, 2, 2));
            panel.setBackground(new java.awt.Color(43, 43, 43));

            javax.swing.JLabel header = new javax.swing.JLabel("Existing Pre-Launch Command Detected");
            header.setForeground(new java.awt.Color(255, 167, 38));
            header.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, 14));
            header.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);

            javax.swing.JLabel subtext = new javax.swing.JLabel(
                "<html><body style='width: 560px; color:#ccc; text-align:left;'>"
                    + "This launcher supports a single pre-launch command. Existing commands can be passed to " + PROJECT_NAME
                    + " as arguments and executed by the JAR before injection starts."
                    + "</body></html>");
            subtext.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);

            javax.swing.JLabel oldLabel = new javax.swing.JLabel("Original pre-launch command found:");
            oldLabel.setForeground(new java.awt.Color(180, 180, 180));
            oldLabel.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);

            javax.swing.JScrollPane oldArea = createCommandBox(existingCommand, 3, new java.awt.Color(224, 224, 224));

            javax.swing.JLabel keepLabel = new javax.swing.JLabel("Proposed merged command (includes existing command):");
            keepLabel.setForeground(new java.awt.Color(180, 180, 180));
            keepLabel.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);

            javax.swing.JScrollPane keepArea = createCommandBox(keepCommand, 4, new java.awt.Color(129, 212, 250));

            javax.swing.JLabel replaceLabel = new javax.swing.JLabel("New command only (replaces existing command):");
            replaceLabel.setForeground(new java.awt.Color(180, 180, 180));
            replaceLabel.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);

            javax.swing.JScrollPane replaceArea = createCommandBox(replaceCommand, 3, new java.awt.Color(255, 204, 128));

            panel.add(header);
            panel.add(javax.swing.Box.createVerticalStrut(8));
            panel.add(subtext);
            panel.add(javax.swing.Box.createVerticalStrut(10));
            panel.add(oldLabel);
            panel.add(javax.swing.Box.createVerticalStrut(4));
            panel.add(oldArea);
            panel.add(javax.swing.Box.createVerticalStrut(10));
            panel.add(keepLabel);
            panel.add(javax.swing.Box.createVerticalStrut(4));
            panel.add(keepArea);
            panel.add(javax.swing.Box.createVerticalStrut(10));
            panel.add(replaceLabel);
            panel.add(javax.swing.Box.createVerticalStrut(4));
            panel.add(replaceArea);

            Object[] options = new Object[] {
                "Include Existing Command",
                "Replace Existing Command",
                "Cancel"
            };

            return javax.swing.JOptionPane.showOptionDialog(
                null,
                panel,
                PROJECT_NAME + " v" + VERSION + " — Pre-Launch Command Conflict",
                javax.swing.JOptionPane.DEFAULT_OPTION,
                javax.swing.JOptionPane.PLAIN_MESSAGE,
                null,
                options,
                options[0]
            );
        } catch (Exception e) {
            // Headless/console fallback: keep existing commands by forwarding.
            return 0;
        }
    }

    /**
     * Escape forwarded pre-launch command chain for quoted argument-safe transport.
     */
    private static String escapeForwardedPreLaunchChain(String chain) {
        if (chain == null || chain.trim().isEmpty()) {
            return "";
        }
        return chain
            .replace("\\", "\\\\")
            .replace("\"", "\\\"");
    }

    /**
     * Unescape forwarded pre-launch command chain from quoted argument text.
     */
    private static String unescapeForwardedPreLaunchChain(String escaped) {
        if (escaped == null || escaped.trim().isEmpty()) {
            return "";
        }

        StringBuilder out = new StringBuilder();
        boolean isEscaping = false;
        for (int i = 0; i < escaped.length(); i++) {
            char c = escaped.charAt(i);
            if (isEscaping) {
                out.append(c);
                isEscaping = false;
            } else if (c == '\\') {
                isEscaping = true;
            } else {
                out.append(c);
            }
        }

        if (isEscaping) {
            out.append('\\');
        }

        return out.toString();
    }

    /**
     * Extract forwarded pre-launch chain (if any) from an existing EasyInject command segment.
     */
    private static String extractForwardedPreLaunchChainFromSegment(String segment) {
        if (segment == null || segment.trim().isEmpty()) {
            return "";
        }

        String lower = segment.toLowerCase();
        String argLower = FORWARDED_PRELAUNCH_CHAIN_ARG.toLowerCase();
        int idx = lower.indexOf(argLower);
        if (idx >= 0) {
            String rest = segment.substring(idx + FORWARDED_PRELAUNCH_CHAIN_ARG.length()).trim();
            
            // Check for both unescaped quote (") and escaped quote (\")
            boolean startsWithQuote = rest.startsWith("\"");
            boolean startsWithEscapedQuote = rest.startsWith("\\\"");
            int startIdx = startsWithEscapedQuote ? 2 : (startsWithQuote ? 1 : -1);
            
            if (startIdx > 0) {
                StringBuilder value = new StringBuilder();
                boolean escaping = false;
                for (int i = startIdx; i < rest.length(); i++) {
                    char c = rest.charAt(i);
                    if (escaping) {
                        value.append(c);
                        escaping = false;
                        continue;
                    }
                    if (c == '\\') {
                        escaping = true;
                        continue;
                    }
                    if (c == '"') {
                        break;
                    }
                    value.append(c);
                }
                return unescapeForwardedPreLaunchChain(value.toString());
            }

            int space = rest.indexOf(' ');
            String value = (space >= 0) ? rest.substring(0, space) : rest;
            return unescapeForwardedPreLaunchChain(value);
        }

        return "";
    }

    /**
     * Wrap a command chain in cmd /C "...".
     */
    private static String wrapInCmdC(String commandBody) {
        String body = commandBody != null ? unwrapCmdWrapper(commandBody).trim() : "";
        if (body.isEmpty()) {
            return "";
        }
        return "cmd /C \"" + body + "\"";
    }

    /**
     * Remove cmd /C wrapper if present and return inner command chain.
     */
    private static String unwrapCmdWrapper(String command) {
        if (command == null) {
            return "";
        }

        String trimmed = command.trim();
        String lower = trimmed.toLowerCase();

        int prefixLength = -1;
        if (lower.startsWith("cmd.exe /c")) {
            prefixLength = "cmd.exe /c".length();
        } else if (lower.startsWith("cmd /c")) {
            prefixLength = "cmd /c".length();
        }

        if (prefixLength < 0) {
            return trimmed;
        }

        String rest = trimmed.substring(prefixLength).trim();
        if (rest.length() >= 2 && rest.startsWith("\"") && rest.endsWith("\"")) {
            return rest.substring(1, rest.length() - 1);
        }

        return rest;
    }

    /**
     * Extract and unescape JSON string value from a single-line key/value entry.
     */
    private static String extractJsonStringValue(String line) {
        if (line == null) {
            return "";
        }

        int colon = line.indexOf(':');
        if (colon < 0) {
            return "";
        }

        int startQuote = line.indexOf('"', colon + 1);
        if (startQuote < 0) {
            return "";
        }

        StringBuilder value = new StringBuilder();
        boolean escaping = false;
        for (int i = startQuote + 1; i < line.length(); i++) {
            char c = line.charAt(i);
            if (escaping) {
                switch (c) {
                    case 'n': value.append('\n'); break;
                    case 'r': value.append('\r'); break;
                    case 't': value.append('\t'); break;
                    case '"': value.append('"'); break;
                    case '\\': value.append('\\'); break;
                    default: value.append(c); break;
                }
                escaping = false;
                continue;
            }

            if (c == '\\') {
                escaping = true;
                continue;
            }

            if (c == '"') {
                break;
            }

            value.append(c);
        }

        return value.toString();
    }

    /**
     * Show success dialog after installation with an undo option.
     */
    private static void showSuccessDialog(String jarFilename, final File instanceCfg, File instanceDir) {
        try {
            applyDarkTheme();

            final java.awt.Color bg = new java.awt.Color(43, 43, 43);

            // Derive instance info
            String instanceName = (instanceDir != null) ? instanceDir.getName() : "Unknown";
            String instancePath = (instanceDir != null) ? instanceDir.getAbsolutePath() : "Unknown";

            // Create main content panel
            javax.swing.JPanel panel = new javax.swing.JPanel();
            panel.setOpaque(true);
            panel.setBackground(bg);
            panel.setLayout(new javax.swing.BoxLayout(panel, javax.swing.BoxLayout.Y_AXIS));
            panel.setBorder(javax.swing.BorderFactory.createEmptyBorder(4, 4, 4, 4));
            
            // Header panel with Title and Uninstall button
            javax.swing.JPanel headerPanel = new javax.swing.JPanel(new java.awt.BorderLayout());
            headerPanel.setOpaque(true);
            headerPanel.setBackground(bg);
            headerPanel.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);
            
            // Title Label with icon (avoids missing-glyph boxes on some systems)
            javax.swing.JLabel titleLabel = new javax.swing.JLabel("Installed Successfully!");
            titleLabel.setIcon(createSuccessStatusIcon());
            titleLabel.setIconTextGap(8);
            titleLabel.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, 16));
            titleLabel.setForeground(new java.awt.Color(76, 175, 80)); // #4CAF50
            headerPanel.add(titleLabel, java.awt.BorderLayout.CENTER);

            // Uninstall Button
            javax.swing.JButton uninstallBtn = createStyledButton("Uninstall");
            // Adjust button style for header (smaller padding)
            uninstallBtn.setBorder(javax.swing.BorderFactory.createEmptyBorder(4, 12, 4, 12));
            uninstallBtn.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, 11));
            
            uninstallBtn.addActionListener(new java.awt.event.ActionListener() {
                public void actionPerformed(java.awt.event.ActionEvent e) {
                    // Confirmation dialog
                    int choice = javax.swing.JOptionPane.showConfirmDialog(
                        javax.swing.SwingUtilities.getWindowAncestor(uninstallBtn),
                        "Are you sure you want to undo the installation?\nThis will remove the launcher integration.",
                        "Confirm Uninstall",
                        javax.swing.JOptionPane.YES_NO_OPTION,
                        javax.swing.JOptionPane.WARNING_MESSAGE
                    );
                    
                    if (choice != javax.swing.JOptionPane.YES_OPTION) {
                        return;
                    }

                    // Clear the PreLaunchCommand - detect file type by name
                    InstallResult result;
                    if (instanceCfg.getName().toLowerCase().endsWith(".json")) {
                        result = installPreLaunchCommandJson(instanceCfg, "");
                    } else {
                        result = installPreLaunchCommand(instanceCfg, "");
                    }
                    if (result.success) {
                        ((javax.swing.JButton)e.getSource()).setText("Uninstalled");
                        ((javax.swing.JButton)e.getSource()).setEnabled(false);
                        titleLabel.setIcon(null);
                        titleLabel.setText("Uninstalled!");
                        titleLabel.setForeground(new java.awt.Color(224, 224, 224));
                    } else {
                        ((javax.swing.JButton)e.getSource()).setText("Error");
                        javax.swing.JOptionPane.showMessageDialog(
                            javax.swing.SwingUtilities.getWindowAncestor(uninstallBtn), 
                            "Failed: " + result.error, 
                            "Error", 
                            javax.swing.JOptionPane.ERROR_MESSAGE
                        );
                    }
                }
            });
            headerPanel.add(uninstallBtn, java.awt.BorderLayout.EAST);
            
            panel.add(headerPanel);
            panel.add(javax.swing.Box.createVerticalStrut(10));

            String message = 
                "<html><body style='font-family: Segoe UI, sans-serif; color: #e0e0e0;'>" +
                "<p style='margin:0 0 8px 0;'>" + PROJECT_NAME + " has been configured for this instance.</p>" +
                "<table style='margin:0 0 10px 0; color: #d9d9d9; font-size: 12px;'>" +
                "<tr><td style='padding:2px 10px 2px 0; color: #c7ced6;'>Instance</td><td style='color:#81D4FA;'><b>" + instanceName + "</b></td></tr>" +
                "<tr><td style='padding:2px 10px 2px 0; color: #c7ced6;'>Path</td><td style='color: #c7ced6; font-size: 11px;'>" + instancePath + "</td></tr>" +
                "</table>" +
                "<p style='margin:0; color: #c7ced6; font-size: 11px;'>You can now launch Minecraft from your launcher.</p>" +
                "</body></html>";
            
            javax.swing.JLabel msgLabel = new javax.swing.JLabel(message);
            msgLabel.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);
            panel.add(msgLabel);
            
            // Create styled OK button
            javax.swing.JButton okButton = createStyledButton("OK");

            // Use a custom dialog instead of JOptionPane to avoid Windows L&F ghosting artifacts
            // (stale text being left behind in the bottom-right).
            final javax.swing.JDialog dialog = new javax.swing.JDialog((java.awt.Frame) null, PROJECT_NAME + " v" + VERSION + " — Installed", true);
            dialog.setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
            dialog.setResizable(false);
            try {
                javax.swing.RepaintManager.currentManager(dialog).setDoubleBufferingEnabled(true);
            } catch (Throwable ignored) {
                // ignore
            }

            // Paint full background every repaint to prevent hover/partial repaint artifacts.
            javax.swing.JPanel root = new javax.swing.JPanel(new java.awt.BorderLayout(0, 10)) {
                @Override
                protected void paintComponent(java.awt.Graphics g) {
                    g.setColor(bg);
                    g.fillRect(0, 0, getWidth(), getHeight());
                    super.paintComponent(g);
                }
            };
            // Keep the root panel opaque to avoid hover/unhover ghosting on some Windows L&Fs.
            root.setOpaque(true);
            root.setBackground(bg);
            root.setDoubleBuffered(true);
            root.setBorder(javax.swing.BorderFactory.createEmptyBorder(12, 12, 12, 12));
            root.setPreferredSize(new java.awt.Dimension(560, 240));

            root.add(panel, java.awt.BorderLayout.CENTER);

            javax.swing.JPanel buttons = new javax.swing.JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.CENTER, 0, 0));
            buttons.setOpaque(true);
            buttons.setBackground(bg);
            buttons.add(okButton);
            root.add(buttons, java.awt.BorderLayout.SOUTH);

            okButton.addActionListener(new java.awt.event.ActionListener() {
                public void actionPerformed(java.awt.event.ActionEvent e) {
                    dialog.dispose();
                }
            });

            dialog.setContentPane(root);
            dialog.pack();
            dialog.setMinimumSize(new java.awt.Dimension(560, 240));
            dialog.setLocationRelativeTo(null);
            dialog.setVisible(true);

            restartSavedLaunchersAfterConfirmation();
        } catch (Exception e) {
            // If GUI fails, print to console
            System.out.println("=======================================================");
            System.out.println("  " + PROJECT_NAME + " - Installed Successfully!");
            System.out.println("=======================================================");
            System.out.println();
            System.out.println("PreLaunchCommand has been configured.");
            System.out.println("You can now launch Minecraft from your launcher.");
            restartSavedLaunchersAfterConfirmation();
        }
    }

    /**
     * Show error dialog when installation fails.
     */
    private static void showErrorDialog(String error) {
        try {
            applyDarkTheme();

            String message = 
                "<html><body style='width: 320px; font-family: Segoe UI, sans-serif; color: #e0e0e0;'>" +
                "<p style='margin:0 0 10px 0; color: #EF5350; font-size: 15px;'><b>✗ Installation Failed</b></p>" +
                "<p style='margin:0 0 8px 0;'>Could not modify instance config:</p>" +
                "<p style='margin:0; color: #9e9e9e;'>" + error + "</p>" +
                "</body></html>";
            
            javax.swing.JLabel msgLabel = new javax.swing.JLabel(message);
            
            // Create styled OK button
            javax.swing.JButton okButton = createStyledButton("OK");
            okButton.addActionListener(new java.awt.event.ActionListener() {
                public void actionPerformed(java.awt.event.ActionEvent e) {
                    java.awt.Window w = javax.swing.SwingUtilities.getWindowAncestor(okButton);
                    if (w != null) w.dispose();
                }
            });

            javax.swing.JOptionPane.showOptionDialog(
                null,
                msgLabel,
                PROJECT_NAME + " v" + VERSION + " — Error",
                javax.swing.JOptionPane.DEFAULT_OPTION,
                javax.swing.JOptionPane.PLAIN_MESSAGE,
                null,
                new Object[]{ okButton },
                okButton
            );

            restartSavedLaunchersAfterConfirmation();
        } catch (Exception e) {
            // If GUI fails, print to console
            System.out.println("=======================================================");
            System.out.println("  " + PROJECT_NAME + " - Installation Failed");
            System.out.println("=======================================================");
            System.out.println();
            System.out.println("Error: " + error);
            restartSavedLaunchersAfterConfirmation();
        }
    }

    /**
     * Create a styled button for dialogs with rounded corners and custom painting.
     */
    private static javax.swing.JButton createStyledButton(String text) {
        javax.swing.JButton btn = new javax.swing.JButton(text) {
            @Override
            protected void paintComponent(java.awt.Graphics g) {
                java.awt.Graphics2D g2 = (java.awt.Graphics2D) g.create();
                g2.setRenderingHint(java.awt.RenderingHints.KEY_ANTIALIASING, java.awt.RenderingHints.VALUE_ANTIALIAS_ON);

                // Clear full bounds first (prevents hover repaint trails/ghosting on some Windows L&Fs).
                java.awt.Color clear = null;
                try {
                    java.awt.Container p = getParent();
                    if (p != null) {
                        clear = p.getBackground();
                    }
                } catch (Throwable ignored) {
                    clear = null;
                }
                if (clear == null) {
                    clear = new java.awt.Color(43, 43, 43);
                }
                g2.setColor(clear);
                g2.fillRect(0, 0, getWidth(), getHeight());
                
                // Determine background color based on state
                java.awt.Color bgColor;
                if (getModel().isPressed()) {
                    bgColor = new java.awt.Color(40, 40, 40);
                } else if (getModel().isRollover()) {
                    bgColor = new java.awt.Color(80, 80, 80);
                } else {
                    bgColor = new java.awt.Color(60, 60, 60);
                }
                
                // Fill rounded background slightly inset to prevent edge clipping on scaled displays
                int x = 1;
                int y = 1;
                int w = Math.max(0, getWidth() - 2);
                int h = Math.max(0, getHeight() - 2);
                int arc = 10;

                g2.setColor(bgColor);
                g2.fillRoundRect(x, y, w, h, arc, arc);
                
                // Draw rounded border
                g2.setColor(new java.awt.Color(100, 100, 100));
                if (w > 1 && h > 1) {
                    g2.drawRoundRect(x, y, w - 1, h - 1, arc, arc);
                }

                // Paint text and icon over the custom background using the same AA-enabled Graphics.
                super.paintComponent(g2);
                g2.dispose();
            }
        };
        
        btn.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, 12));
        btn.setForeground(new java.awt.Color(224, 224, 224));
        btn.setCursor(new java.awt.Cursor(java.awt.Cursor.HAND_CURSOR));
        
        // Remove default look and feel painting
        btn.setContentAreaFilled(false);
        btn.setFocusPainted(false);
        btn.setBorderPainted(false);
        // Keep the button non-opaque so Swing doesn't fill a square background behind our rounded paint.
        btn.setOpaque(false);
        btn.setRolloverEnabled(true);
        btn.setDoubleBuffered(true);
        
        // Add padding (top, left, bottom, right)
        btn.setBorder(javax.swing.BorderFactory.createEmptyBorder(8, 20, 8, 20));

        // Force repaints of the parent region on rollover/press changes.
        // This eliminates occasional 1px hover trails on Windows when leaving the button.
        btn.getModel().addChangeListener(new javax.swing.event.ChangeListener() {
            @Override
            public void stateChanged(javax.swing.event.ChangeEvent e) {
                btn.repaint();
                java.awt.Container p = btn.getParent();
                if (p != null) {
                    int pad = 2;
                    p.repaint(btn.getX() - pad, btn.getY() - pad, btn.getWidth() + pad * 2, btn.getHeight() + pad * 2);
                }
            }
        });
        
        return btn;
    }

    /**
     * Create a small vector icon for success state (green circle + white check).
     */
    private static javax.swing.Icon createSuccessStatusIcon() {
        return new javax.swing.Icon() {
            private final int size = 16;

            @Override
            public void paintIcon(java.awt.Component c, java.awt.Graphics g, int x, int y) {
                java.awt.Graphics2D g2 = (java.awt.Graphics2D) g.create();
                g2.setRenderingHint(java.awt.RenderingHints.KEY_ANTIALIASING, java.awt.RenderingHints.VALUE_ANTIALIAS_ON);

                // Green circle background
                g2.setColor(new java.awt.Color(76, 175, 80));
                g2.fillOval(x, y, size, size);

                // White check mark
                g2.setColor(java.awt.Color.WHITE);
                g2.setStroke(new java.awt.BasicStroke(2.0f, java.awt.BasicStroke.CAP_ROUND, java.awt.BasicStroke.JOIN_ROUND));
                java.awt.geom.Path2D.Float check = new java.awt.geom.Path2D.Float();
                check.moveTo(x + 4, y + 8);
                check.lineTo(x + 7, y + 11);
                check.lineTo(x + 12, y + 5);
                g2.draw(check);

                g2.dispose();
            }

            @Override
            public int getIconWidth() {
                return size;
            }

            @Override
            public int getIconHeight() {
                return size;
            }
        };
    }

    /**
     * Show warning when instance.cfg is not found.
     */
    private static void showNoInstanceCfgWarning(String prelaunchCommand) {
        try {
            applyDarkTheme();

            String message = 
                "<html><body style='width: 360px; font-family: Segoe UI, sans-serif; color: #e0e0e0;'>" +
                "<p style='margin:0 0 10px 0; color: #FFA726; font-size: 15px;'><b>⚠ Setup Required</b></p>" +
                "<p style='margin:0 0 10px 0;'>To install " + PROJECT_NAME + ", follow these steps:</p>" +
                "<ol style='margin:0 0 0 0; padding-left: 20px; color: #ccc;'>" +
                "<li style='margin-bottom: 3px;'>Open your instance folder:" +
                "<ul style='margin-top:4px; margin-bottom: 0px; margin-left: 20px; color: #aaa; font-size: 11px;'>" +
                "<li><b style='color:#4CAF50;'>MultiMC:</b> Right-click instance → Instance Folder</li>" +
                "<li><b style='color:#42A5F5;'>Prism:</b> Right-click instance → Folder</li>" +
                "<li><b style='color:#FF7043;'>ATLauncher:</b> Right-click instance → Open Folder</li>" +
                "<li><b style='color:#9575CD;'>Other launchers:</b> Not currently supported</li>" +
                "</ul>" +
                "</li>" +
                "<li style='margin-bottom: 3px;'>Drop this JAR file into that folder.</li>" +
                "<li>Double-click the JAR in that folder to install.</li>" +
                "</ol>" +
                "</body></html>";
            
            javax.swing.JLabel msgLabel = new javax.swing.JLabel(message);
            
            // Show dialog
            // Create styled OK button
            javax.swing.JButton okButton = createStyledButton("OK");
            okButton.addActionListener(new java.awt.event.ActionListener() {
                public void actionPerformed(java.awt.event.ActionEvent e) {
                    java.awt.Window w = javax.swing.SwingUtilities.getWindowAncestor(okButton);
                    if (w != null) w.dispose();
                }
            });

            // Show dialog with custom button
            javax.swing.JOptionPane.showOptionDialog(
                null,
                msgLabel,
                PROJECT_NAME + " v" + VERSION + " — Setup Required",
                javax.swing.JOptionPane.DEFAULT_OPTION,
                javax.swing.JOptionPane.PLAIN_MESSAGE,
                null,
                new Object[]{ okButton },
                okButton
            );
        } catch (Exception e) {
            // If GUI fails, print to console and wait for input
            String consoleMsg = 
                "=======================================================\n" +
                "  " + PROJECT_NAME + " v" + VERSION + "\n" +
                "=======================================================\n\n" +
                "To install, follow these steps:\n\n" +
                "1. Open your instance folder:\n" +
                "   - MultiMC: Right-click instance -> Instance Folder\n" +
                "   - Prism: Right-click instance -> Folder\n" +
                "   - ATLauncher: Right-click instance -> Open Folder\n\n" +
                "2. Drop this JAR file into that folder.\n\n" +
                "3. Double-click this JAR file in that folder to install.\n";
            System.out.println(consoleMsg);
        }
    }

    /**
     * Info Mode: Print information about embedded DLLs.
     */
    private static int runInfoMode() {
        System.out.println("===========================================");
        System.out.println("  " + PROJECT_NAME + " v" + VERSION);
        System.out.println("===========================================");
        System.out.println();
        System.out.println("Bundler Version: " + VERSION);
        System.out.println();
        System.out.println("Embedded DLLs:");
        System.out.println("-------------------------------------------");
        
        try {
            String jarPath = getJarPath();
            File jarFile = new File(jarPath);
            
            if (!jarFile.isFile() || !jarPath.endsWith(".jar")) {
                System.out.println("  (Not running from JAR, cannot list embedded DLLs)");
                return 0;
            }

            JarFile jar = new JarFile(jarFile);
            try {
                Enumeration<JarEntry> entries = jar.entries();
                int count = 0;
                
                while (entries.hasMoreElements()) {
                    JarEntry entry = entries.nextElement();
                    String name = entry.getName();
                    
                    if (name.startsWith(DLL_RESOURCE_PATH) && name.toLowerCase().endsWith(".dll")) {
                        String dllName = name.substring(DLL_RESOURCE_PATH.length());
                        if (dllName.isEmpty() || dllName.contains("/")) {
                            continue;
                        }
                        
                        // Read DLL content and compute hash
                        InputStream in = jar.getInputStream(entry);
                        byte[] content = readAllBytes(in);
                        in.close();
                        
                        String sha512 = computeSha512(content);
                        long sizeBytes = content.length;
                        
                        System.out.println();
                        System.out.println("  Name:   " + dllName);
                        System.out.println("  Size:   " + formatSize(sizeBytes));
                        System.out.println("  SHA512: " + sha512);
                        
                        count++;
                    }
                }
                
                System.out.println();
                System.out.println("-------------------------------------------");
                System.out.println("Total: " + count + " DLL(s) embedded");
                
            } finally {
                jar.close();
            }
            
        } catch (Exception e) {
            System.err.println("Error reading JAR: " + e.getMessage());
            return 1;
        }
        
        return 0;
    }

    /**
     * Compute SHA-512 hash of byte array.
     */
    private static String computeSha512(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            byte[] hash = md.digest(data);
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "ERROR";
        }
    }

    /**
     * Format byte size to human readable.
     */
    private static String formatSize(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.2f KB", bytes / 1024.0);
        return String.format("%.2f MB", bytes / (1024.0 * 1024.0));
    }

    /**
     * Read all bytes from InputStream (Java 8 compatible).
     */
    private static byte[] readAllBytes(InputStream is) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] data = new byte[8192];
        int bytesRead;
        while ((bytesRead = is.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, bytesRead);
        }
        return buffer.toByteArray();
    }

    /**
     * Launcher Mode: Spawn a hidden watcher process and exit immediately.
     */
    private static int runLauncherMode(String[] args) {
        // Start each run with a clean log file (watcher will append within this run).
        resetLogFilesForStartup();

        System.out.println("[" + PROJECT_NAME + "] Starting launcher mode");

        if (!runForwardedPreLaunchChain(args)) {
            return 1;
        }

        try {
            String jarPath = getJarPath();
            System.out.println("[" + PROJECT_NAME + "] JAR path: " + jarPath);

            // Before spawning the watcher, optionally check GitHub releases for an update.
            // If an update is accepted, we download it, schedule an out-of-process replace,
            // and also schedule the watcher spawn from the updated JAR.
            // IMPORTANT: In pre-launch mode, returning a non-zero exit code prevents the
            // game from launching. We intentionally exit 1 when an update is scheduled so
            // the launcher stops here, giving the updater time to replace the JAR.
            try {
                launcherLog("[Updater] Starting update check...");
                boolean updateScheduled = Updater.maybeUpdateAndRescheduleWatcher(
                    PROJECT_NAME,
                    VERSION,
                    jarPath,
                    getCurrentJavaExecutablePath(),
                    System.getProperty("user.dir"),
                    new Updater.LogSink() {
                        @Override
                        public void log(String msg) {
                            launcherLog("[Updater] " + msg);
                        }
                    }
                );
                if (updateScheduled) {
                    // Make it extremely obvious to the user that they must start the instance again.
                    // This runs in pre-launch context, so a modal dialog is the most reliable.
                    showUpdateRestartRequiredDialogBlocking();
                    System.out.println("[" + PROJECT_NAME + "] Update scheduled; launcher exiting with code 1 to prevent game launch.");
                    launcherLog("[Updater] Update scheduled; exiting launcher with code 1.");
                    return 1;
                }

                launcherLog("[Updater] No update scheduled; continuing normal launch.");
            } catch (Throwable t) {
                // Non-fatal: if the updater fails for any reason, continue normally.
                System.err.println("[" + PROJECT_NAME + "] Update check failed (continuing): " + t.getMessage());
                launcherLog("[Updater] Skipped due to error: " + t.getClass().getSimpleName() + ": " + (t.getMessage() != null ? t.getMessage() : ""));
            }

            String workingDir = System.getProperty("user.dir");

            List<String> command = new ArrayList<String>();
            command.add(getCurrentJavaExecutablePath());
            command.add("-jar");
            command.add(jarPath);
            command.add(WATCHER_ARG);

            ProcessBuilder pb = new ProcessBuilder(command);
            pb.directory(new File(workingDir));
            try {
                File stdioLog = new File(workingDir, "watcher-stdio.log");
                pb.redirectErrorStream(true);
                pb.redirectOutput(ProcessBuilder.Redirect.appendTo(stdioLog));
            } catch (Throwable ignored) {
                // Best effort: if redirect fails, still avoid inheritIO().
                // The watcher will log to injector.log via file logging.
            }
            
            pb.start();
            
            System.out.println("[" + PROJECT_NAME + "] Watcher process spawned successfully");
            System.out.println("[" + PROJECT_NAME + "] Launcher exiting - watcher will wait for Java process");

            return 0;

        } catch (Exception e) {
            System.err.println("[" + PROJECT_NAME + "] ERROR: Failed to spawn watcher process: " + e.getMessage());
            e.printStackTrace();
            return 1;
        }
    }

    /**
     * When a self-update is scheduled from pre-launch mode, we intentionally exit with code 1 to
     * prevent the game from launching. This dialog makes that behavior explicit and tells the
     * user to start the instance again.
     */
    private static void showUpdateRestartRequiredDialogBlocking() {
        try {
            applyDarkTheme();

            StringBuilder body = new StringBuilder();
            body.append("<html><body style='width: 460px; font-family: Segoe UI, sans-serif; color: #e0e0e0;'>");
            body.append("<p style='margin:0 0 12px 0; color:#FF5252; font-size: 26px;'><b>UPDATE INSTALLED</b></p>");
            body.append("<p style='margin:0 0 12px 0; font-size: 18px;'><b>Please start the instance again.</b></p>");
            body.append("<p style='margin:0 0 10px 0; color:#c7ced6; font-size: 13px;'>");
            body.append("This window appeared because ").append(escapeHtml(PROJECT_NAME)).append(" updated itself.");
            body.append(" The game launch was stopped on purpose so the updated JAR can be applied safely.");
            body.append("</p>");
            body.append("<p style='margin:0; color:#9e9e9e; font-size: 12px;'>");
            body.append("Close this message, then click <b>Play</b> / <b>Launch</b> again in your launcher.");
            body.append("</p>");
            body.append("</body></html>");

            javax.swing.JLabel msgLabel = new javax.swing.JLabel(body.toString());
            javax.swing.JButton okButton = createStyledButton("OK — I'll start it again");

            // Blocking dialog (modal) so the user sees it before we exit with code 1.
            showBlockingOptionDialog(
                PROJECT_NAME + " — Restart Required",
                msgLabel,
                new Object[] { okButton },
                0
            );
        } catch (Throwable ignored) {
            // Fallback: console output (may not be visible in launcher context, but best-effort).
            System.out.println("=======================================================");
            System.out.println("  UPDATE INSTALLED — RESTART REQUIRED");
            System.out.println("=======================================================");
            System.out.println();
            System.out.println("" + PROJECT_NAME + " updated itself.");
            System.out.println("Start the instance again in your launcher.");
            System.out.println();
        }
    }

    /**
     * Execute pre-existing pre-launch command(s) forwarded as encoded args.
     */
    private static boolean runForwardedPreLaunchChain(String[] args) {
        // Run any previously configured prelaunch commands (forwarded from Prism/MultiMC chain)
        // and also execute user-provided per-instance commands from prelaunch.txt.

        String escapedChain = getArgumentValue(args, FORWARDED_PRELAUNCH_CHAIN_ARG);
        if (escapedChain == null || escapedChain.trim().isEmpty()) {
            // Still allow prelaunch.txt even if no forwarded chain exists.
            return runInstancePrelaunchTxtChain();
        }

        String chain = unescapeForwardedPreLaunchChain(escapedChain);

        if (chain.isEmpty()) {
            System.err.println("[" + PROJECT_NAME + "] Invalid forwarded pre-launch command payload.");
            return false;
        }

        System.out.println("[" + PROJECT_NAME + "] Executing forwarded pre-launch command(s)...");
        try {
            ProcessBuilder pb = new ProcessBuilder("cmd", "/C", chain);
            pb.directory(new File(System.getProperty("user.dir")));
            pb.inheritIO();

            Process process = pb.start();
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                System.err.println("[" + PROJECT_NAME + "] Forwarded pre-launch command(s) failed with exit code: " + exitCode);
                return false;
            }

            // After forwarded prelaunch steps succeed, run user-defined steps.
            return runInstancePrelaunchTxtChain();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.err.println("[" + PROJECT_NAME + "] Forwarded pre-launch execution interrupted.");
            return false;
        } catch (Exception e) {
            System.err.println("[" + PROJECT_NAME + "] Failed to execute forwarded pre-launch command(s): " + e.getMessage());
            return false;
        }
    }

    /**
     * Execute each non-empty line in prelaunch.txt in the instance root folder.
     * Lines starting with '#', ';', or '//' are treated as comments.
     */
    private static boolean runInstancePrelaunchTxtChain() {
        File instanceRoot = resolveInstanceRootDir();
        if (instanceRoot == null) {
            return true;
        }

        File prelaunchTxt = new File(instanceRoot, "prelaunch.txt");
        if (!prelaunchTxt.exists() || !prelaunchTxt.isFile()) {
            return true;
        }

        System.out.println("[" + PROJECT_NAME + "] Executing prelaunch.txt chain...");

        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new InputStreamReader(new FileInputStream(prelaunchTxt), Charset.defaultCharset()));

            String line;
            int lineNo = 0;
            while ((line = reader.readLine()) != null) {
                lineNo++;

                String trimmed = line.trim();
                if (trimmed.isEmpty()) {
                    continue;
                }
                if (trimmed.startsWith("#") || trimmed.startsWith(";") || trimmed.startsWith("//")) {
                    continue;
                }

                System.out.println("[" + PROJECT_NAME + "] prelaunch.txt#" + lineNo + ": " + trimmed);

                ProcessBuilder pb = new ProcessBuilder("cmd", "/C", trimmed);
                pb.directory(instanceRoot);
                pb.inheritIO();

                Process p = pb.start();
                int exit = p.waitFor();
                if (exit != 0) {
                    System.err.println("[" + PROJECT_NAME + "] prelaunch.txt line " + lineNo + " failed with exit code: " + exit);
                    return false;
                }
            }

            return true;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.err.println("[" + PROJECT_NAME + "] prelaunch.txt execution interrupted.");
            return false;
        } catch (Exception e) {
            System.err.println("[" + PROJECT_NAME + "] Failed to execute prelaunch.txt: " + (e.getMessage() != null ? e.getMessage() : e.toString()));
            return false;
        } finally {
            if (reader != null) {
                try { reader.close(); } catch (Throwable ignored) {}
            }
        }
    }

    /**
     * Resolve the instance root directory (where instance.cfg / instance.json typically lives).
     *
     * - If the JAR is inside minecraft/.minecraft, the instance root is the parent folder.
     * - Otherwise, the instance root is the JAR's folder.
     * - Falls back to the current working directory.
     */
    private static File resolveInstanceRootDir() {
        // Prefer jar location when available.
        try {
            String jarPath = getJarPath();
            if (jarPath != null && !jarPath.trim().isEmpty()) {
                File jarFile = new File(jarPath);
                File jarDir = jarFile.getParentFile();
                if (jarDir != null) {
                    File instanceRoot = jarDir;
                    String dirName = jarDir.getName().toLowerCase();
                    if (dirName.equals("minecraft") || dirName.equals(".minecraft")) {
                        instanceRoot = jarDir.getParentFile();
                    }
                    if (instanceRoot != null && instanceRoot.isDirectory()) {
                        return instanceRoot;
                    }
                }
            }
        } catch (Throwable ignored) {
            // Fall through.
        }

        // Fallback to working directory; if it's minecraft/.minecraft, return parent.
        try {
            File wd = new File(System.getProperty("user.dir"));
            if (wd.isDirectory()) {
                String dirName = wd.getName().toLowerCase();
                if (dirName.equals("minecraft") || dirName.equals(".minecraft")) {
                    File parent = wd.getParentFile();
                    if (parent != null && parent.isDirectory()) {
                        return parent;
                    }
                }
                return wd;
            }
        } catch (Throwable ignored) {
            // ignore
        }

        return null;
    }

    /**
     * Watcher Mode: Wait for Java process and inject embedded DLLs.
     * Detects the target Minecraft process by matching working directory
     * to the instance directory where our JAR is located.
     */
    private static int runWatcherMode() {
        // Initialize file logging
        initLogging();

        try {
            log("[" + PROJECT_NAME + "] Starting watcher mode");

            String thisInstId = System.getenv("INST_ID");
            if (thisInstId == null) {
                thisInstId = "";
            }

        // Determine valid target directories from our JAR location.
        // The Minecraft process could be running from the instance root or from
        // its minecraft/.minecraft subfolder, and the JAR could be in either location.
        // We accept a match against any of them.
            Set<String> targetDirs = new java.util.TreeSet<String>(String.CASE_INSENSITIVE_ORDER);
            try {
                String jarPath = getJarPath();
                File jarFile = new File(jarPath);
                File jarDir = jarFile.getParentFile();
            
                // Determine the instance root: if JAR is in minecraft/.minecraft, go up one level
                File instanceRoot = jarDir;
                if (jarDir != null) {
                    String dirName = jarDir.getName().toLowerCase();
                    if (dirName.equals("minecraft") || dirName.equals(".minecraft")) {
                        instanceRoot = jarDir.getParentFile();
                    }
                }
            
                // Add the instance root and both possible subfolders as valid targets
                if (instanceRoot != null) {
                    targetDirs.add(normalizePathForCompare(instanceRoot.getAbsolutePath()));
                    File mcDir = new File(instanceRoot, "minecraft");
                    if (mcDir.isDirectory()) {
                        targetDirs.add(normalizePathForCompare(mcDir.getAbsolutePath()));
                    }
                    File dotMcDir = new File(instanceRoot, ".minecraft");
                    if (dotMcDir.isDirectory()) {
                        targetDirs.add(normalizePathForCompare(dotMcDir.getAbsolutePath()));
                    }
                }
            } catch (Exception e) {
                // Fall back to working directory
                targetDirs.add(normalizePathForCompare(System.getProperty("user.dir")));
            }

            log("[" + PROJECT_NAME + "] Target instance directories:");
            for (String dir : targetDirs) {
                log("[" + PROJECT_NAME + "]   - " + dir);
            }

            // Extract all embedded DLLs to the persistent branded DLL directory
            File dllExtractDir = getEmbeddedDllExtractDir();
            log("[" + PROJECT_NAME + "] Extracting embedded DLLs to: " + dllExtractDir.getAbsolutePath());
            List<Path> embeddedDlls = extractEmbeddedDlls();
            
            if (embeddedDlls.isEmpty()) {
                log("[" + PROJECT_NAME + "] No embedded DLLs found - exiting");
                closeLogging();
                return 1;
            }

            log("[" + PROJECT_NAME + "] Found " + embeddedDlls.size() + " embedded DLL(s):");
            for (Path dll : embeddedDlls) {
                log("[" + PROJECT_NAME + "]   - " + dll.getFileName());
            }

            // Separate logger DLL from other DLLs (inject logger first)
            Path loggerDll = null;
            List<Path> otherDlls = new ArrayList<Path>();
            for (Path dll : embeddedDlls) {
                if (dll.getFileName().toString().equalsIgnoreCase(LOGGER_DLL_NAME)) {
                    loggerDll = dll;
                } else {
                    otherDlls.add(dll);
                }
            }

            // Get our own PID to exclude ourselves
            int ourPid = ProcessUtils.getCurrentProcessId();
            int ourParentPid = ProcessUtils.getParentProcessId(ourPid);
            log("[" + PROJECT_NAME + "] Our PID: " + ourPid);
            log("[" + PROJECT_NAME + "] Parent PID: " + ourParentPid);

            // Poll for Java process whose working directory matches any of our target directories
            long startTime = System.currentTimeMillis();
            long timeoutMs = TIMEOUT_SECONDS * 1000L;
            int javaProcessId = 0;
            String targetProcessCmdLine = "";
            Set<Integer> checkedPids = new java.util.HashSet<Integer>(); // PIDs whose cwd doesn't match

            int pollCount = 0;

            long nextLeafRecheckAt = 0L;
            boolean loggedWindowWaitForCurrentTarget = false;

            while (true) {
                while (javaProcessId == 0) {
                    List<ProcessUtils.ProcessInfo> currentProcs = ProcessUtils.findJavaLeafProcesses();
                    log("[" + PROJECT_NAME + "] Poll #" + (pollCount + 1) + ": found " + currentProcs.size() + " Java leaf process(es)");

                    for (ProcessUtils.ProcessInfo proc : currentProcs) {
                        log("[" + PROJECT_NAME + "] Inspecting PID " + proc.processId + " (" + proc.exeName + ")");

                        // Skip ourselves
                        if (proc.processId == ourPid) {
                            log("[" + PROJECT_NAME + "] Skipping PID " + proc.processId + " (this watcher process)");
                            continue;
                        }

                        // Skip launcher parent process
                        if (ourParentPid != 0 && proc.processId == ourParentPid) {
                            log("[" + PROJECT_NAME + "] Skipping PID " + proc.processId + " (launcher parent process)");
                            continue;
                        }

                        String procCmdLine = ProcessUtils.getProcessCommandLine(proc.processId);

                        // Skip PIDs we've already verified don't match
                        if (checkedPids.contains(proc.processId)) {
                            log("[" + PROJECT_NAME + "] Skipping PID " + proc.processId + " (already checked and not a target)");
                            continue;
                        }

                        // Check working directory for this process
                        String procCwd = ProcessUtils.getProcessWorkingDirectory(proc.processId);
                        log("[" + PROJECT_NAME + "] PID " + proc.processId + " cwd(raw)='" + procCwd + "'");

                        String normalizedProcCwd = normalizePathForCompare(procCwd);
                        log("[" + PROJECT_NAME + "] PID " + proc.processId + " cwd(normalized)='" + normalizedProcCwd + "'");
                        if (!normalizedProcCwd.isEmpty() && targetDirs.contains(normalizedProcCwd)) {
                            String procInstId = ProcessUtils.getProcessEnvVar(proc.processId, "INST_ID");
                            boolean instIdMismatch = !thisInstId.isEmpty() && !procInstId.isEmpty() && !thisInstId.equals(procInstId);
                            if (instIdMismatch) {
                                log("[" + PROJECT_NAME + "] PID " + proc.processId + " rejected (INST_ID mismatch)");
                                checkedPids.add(proc.processId);
                                continue;
                            }

                            if (!isLikelyMinecraftCommandLine(procCmdLine)) {
                                log("[" + PROJECT_NAME + "] PID " + proc.processId + " rejected (not a Minecraft-like JVM command line)");
                                checkedPids.add(proc.processId);
                                continue;
                            }

                            log("[" + PROJECT_NAME + "] Found matching process: PID " + proc.processId + " (" + proc.exeName + ") with cwd=" + procCwd);
                            javaProcessId = proc.processId;
                            targetProcessCmdLine = procCmdLine;
                            nextLeafRecheckAt = System.currentTimeMillis() + TARGET_LEAF_RECHECK_INTERVAL_MS;
                            loggedWindowWaitForCurrentTarget = false;
                            break;
                        } else if (!normalizedProcCwd.isEmpty()) {
                            // Working directory doesn't match - remember we checked it
                            log("[" + PROJECT_NAME + "] PID " + proc.processId + " has cwd='" + procCwd + "' (not a match)");
                            checkedPids.add(proc.processId);
                        }
                        // If procCwd is empty, the process might still be initializing - check again next cycle
                    }

                    pollCount++;

                    if (pollCount % 10 == 0) {
                        log("[" + PROJECT_NAME + "] Still searching... poll #" + pollCount + ", elapsed: " + ((System.currentTimeMillis() - startTime) / 1000) + "s");
                        log("[" + PROJECT_NAME + "] Java processes: " + currentProcs.size() + ", already checked: " + checkedPids.size());
                    }

                    if (javaProcessId != 0) {
                        break;
                    }

                    if (System.currentTimeMillis() - startTime > timeoutMs) {
                        log("[" + PROJECT_NAME + "] Timeout waiting for Java process in instance directories");
                        log("[" + PROJECT_NAME + "] Checked " + checkedPids.size() + " processes, none matched");
                        closeLogging();
                        return 1;
                    }

                    sleep(POLL_INTERVAL_MS);
                }

                if (!loggedWindowWaitForCurrentTarget) {
                    log("[" + PROJECT_NAME + "] Waiting for process to create a window...");
                    if (targetProcessCmdLine != null && !targetProcessCmdLine.trim().isEmpty()) {
                        log("[" + PROJECT_NAME + "] Target command line: " + targetProcessCmdLine);
                    }
                    loggedWindowWaitForCurrentTarget = true;
                }

                String windowTitle = ProcessUtils.getVisibleTopLevelWindowTitle(javaProcessId);
                if (windowTitle != null && !windowTitle.trim().isEmpty()) {
                    log("[" + PROJECT_NAME + "] Window detected: '" + windowTitle + "'");
                    break;
                }

                long now = System.currentTimeMillis();
                if (now >= nextLeafRecheckAt) {
                    nextLeafRecheckAt = now + TARGET_LEAF_RECHECK_INTERVAL_MS;
                    if (!ProcessUtils.isJavaLeafProcess(javaProcessId)) {
                        log("[" + PROJECT_NAME + "] Target PID " + javaProcessId + " is no longer a Java leaf process; rescanning all windows/processes");
                        javaProcessId = 0;
                        targetProcessCmdLine = "";
                        checkedPids.clear();
                        continue;
                    }
                }

                if (now - startTime > timeoutMs) {
                    log("[" + PROJECT_NAME + "] Timeout waiting for window");
                    closeLogging();
                    return 1;
                }

                sleep(POLL_INTERVAL_MS);
            }

            sleep(500);

            // Inject logger DLL first
            int successCount = 0;
            int totalCount = embeddedDlls.size();

            if (loggerDll != null) {
                log("[" + PROJECT_NAME + "] Injecting logger DLL first: " + loggerDll.getFileName());
                log("[" + PROJECT_NAME + "] DLL path: " + loggerDll.toAbsolutePath());
                log("[" + PROJECT_NAME + "] DLL size: " + loggerDll.toFile().length() + " bytes");
                
                DllInjector.InjectionResult result = DllInjector.injectDllWithResult(javaProcessId, loggerDll);
                if (result.success) {
                    log("[" + PROJECT_NAME + "] Logger DLL injected successfully");
                    successCount++;
                    sleep(100);
                } else {
                    log("[" + PROJECT_NAME + "] Failed to inject logger DLL: " + result.error);
                    log("[" + PROJECT_NAME + "] Error code: " + result.errorCode);
                }
            }

            // Inject other DLLs
            log("[" + PROJECT_NAME + "] Injecting remaining DLLs...");
            for (Path dll : otherDlls) {
                log("[" + PROJECT_NAME + "] Injecting: " + dll.getFileName());
                DllInjector.InjectionResult result = DllInjector.injectDllWithResult(javaProcessId, dll);
                if (result.success) {
                    log("[" + PROJECT_NAME + "] Injected successfully: " + dll.getFileName());
                    successCount++;
                } else {
                    log("[" + PROJECT_NAME + "] Failed to inject " + dll.getFileName() + ": " + result.error);
                    log("[" + PROJECT_NAME + "] Error code: " + result.errorCode);
                }
                sleep(100);
            }

            log("[" + PROJECT_NAME + "] Injection complete: " + successCount + "/" + totalCount + " DLLs injected");
            closeLogging();
            return successCount == totalCount ? 0 : 1;
        } catch (Throwable t) {
            log("[" + PROJECT_NAME + "] FATAL watcher error: " + t.getClass().getName() + ": " + t.getMessage());
            logThrowable(t);
            closeLogging();
            return 1;
        }
    }

    private static void logThrowable(Throwable t) {
        if (t == null) {
            return;
        }
        try {
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            t.printStackTrace(pw);
            pw.flush();

            String[] lines = sw.toString().split("\\r?\\n");
            for (String line : lines) {
                log(line);
            }
        } catch (Exception ignored) {
            // Best effort logging only.
        }
    }

    /**
     * Extract all embedded DLLs from the JAR's dlls/ resource folder.
     */
    private static List<Path> extractEmbeddedDlls() {
        List<Path> extractedDlls = new ArrayList<Path>();
        File dllDir = getEmbeddedDllExtractDir();

        try {
            // Get the JAR file we're running from
            String jarPath = getJarPath();
            File jarFile = new File(jarPath);
            
            if (!jarFile.isFile() || !jarPath.endsWith(".jar")) {
                // Running from IDE/classes directory - try classpath resources
                System.out.println("[" + PROJECT_NAME + "] Not running from JAR, trying classpath...");
                return extractDllsFromClasspath(dllDir);
            }

            JarFile jar = new JarFile(jarFile);
            try {
                Enumeration<JarEntry> entries = jar.entries();
                while (entries.hasMoreElements()) {
                    JarEntry entry = entries.nextElement();
                    String name = entry.getName();
                    
                    // Look for DLLs in the dlls/ folder
                    if (name.startsWith(DLL_RESOURCE_PATH) && name.toLowerCase().endsWith(".dll")) {
                        String dllName = name.substring(DLL_RESOURCE_PATH.length());
                        if (dllName.isEmpty() || dllName.contains("/")) {
                            continue; // Skip directories or nested files
                        }
                        
                        File outFile = new File(dllDir, dllName);
                        InputStream in = jar.getInputStream(entry);
                        try {
                            OutputStream out = new FileOutputStream(outFile);
                            try {
                                byte[] buffer = new byte[8192];
                                int bytesRead;
                                while ((bytesRead = in.read(buffer)) != -1) {
                                    out.write(buffer, 0, bytesRead);
                                }
                            } finally {
                                out.close();
                            }
                        } finally {
                            in.close();
                        }
                        
                        System.out.println("[" + PROJECT_NAME + "] Extracted: " + dllName);
                        extractedDlls.add(outFile.toPath());
                    }
                }
            } finally {
                jar.close();
            }
        } catch (Exception e) {
            System.err.println("[" + PROJECT_NAME + "] Error extracting DLLs: " + e.getMessage());
            e.printStackTrace();
        }

        return extractedDlls;
    }

    /**
     * Directory to extract embedded DLLs into.
     *
      * Desired location (per request): %USERPROFILE%/.config/<brand>/dlls
     *
     * If the directory can't be created (permissions, etc), this falls back to:
     * %TEMP%/<PROJECT_NAME>
     */
    private static File getEmbeddedDllExtractDir() {
        try {
            String userHome = System.getProperty("user.home");
            if (userHome != null) {
                userHome = userHome.trim();
            }

            if (userHome != null && !userHome.isEmpty()) {
                File dir = new File(new File(new File(userHome, ".config"), getBrandedConfigFolderName()), "dlls");
                if ((dir.exists() && dir.isDirectory()) || dir.mkdirs()) {
                    return dir;
                }
            }
        } catch (Throwable ignored) {
            // Fall through to temp fallback.
        }

        File tempFallback = new File(System.getProperty("java.io.tmpdir"), PROJECT_NAME);
        tempFallback.mkdirs();
        return tempFallback;
    }

    /**
     * Extract DLLs from classpath (when not running from JAR).
     */
    private static List<Path> extractDllsFromClasspath(File dllDir) {
        List<Path> extractedDlls = new ArrayList<Path>();
        
        // Try to get DLLs from classpath
        String[] knownDlls = { LOGGER_DLL_NAME };
        
        for (String dllName : knownDlls) {
            InputStream in = Main.class.getResourceAsStream("/" + DLL_RESOURCE_PATH + dllName);
            if (in != null) {
                try {
                    File outFile = new File(dllDir, dllName);
                    OutputStream out = new FileOutputStream(outFile);
                    try {
                        byte[] buffer = new byte[8192];
                        int bytesRead;
                        while ((bytesRead = in.read(buffer)) != -1) {
                            out.write(buffer, 0, bytesRead);
                        }
                    } finally {
                        out.close();
                    }
                    in.close();
                    extractedDlls.add(outFile.toPath());
                    System.out.println("[" + PROJECT_NAME + "] Extracted from classpath: " + dllName);
                } catch (IOException e) {
                    System.err.println("[" + PROJECT_NAME + "] Error extracting " + dllName + ": " + e.getMessage());
                }
            }
        }
        
        return extractedDlls;
    }

    private static String getJarPath() throws URISyntaxException {
        return new File(Main.class.getProtectionDomain()
            .getCodeSource()
            .getLocation()
            .toURI())
            .getAbsolutePath();
    }

    private static String safeGetJarPathOrNull() {
        try {
            String p = getJarPath();
            if (p == null) {
                return null;
            }
            p = p.trim();
            return p.isEmpty() ? null : p;
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static boolean hasArgument(String[] args, String arg) {
        for (String a : args) {
            if (a.equalsIgnoreCase(arg)) {
                return true;
            }
        }
        return false;
    }

    private static String getArgumentValue(String[] args, String arg) {
        if (args == null || arg == null) {
            return null;
        }
        for (int i = 0; i < args.length - 1; i++) {
            if (arg.equalsIgnoreCase(args[i])) {
                return args[i + 1];
            }
        }
        return null;
    }

    /**
     * Normalize path strings for reliable directory comparison:
     * - trim whitespace
     * - normalize separators and dot segments
     * - remove trailing slash/backslash (except drive/root paths)
     */
    private static String normalizePathForCompare(String path) {
        if (path == null) {
            return "";
        }

        String p = path.trim();
        if (p.isEmpty()) {
            return "";
        }

        try {
            p = new File(p).toPath().normalize().toAbsolutePath().toString();
        } catch (Exception ignored) {
            // Keep original string if normalization fails
        }

        // Unify separator style for robust string matching
        p = p.replace('\\', '/');

        // Strip trailing separators unless path is root-like (e.g. "C:/" or "/")
        while (p.length() > 1 && p.endsWith("/")) {
            if (p.matches("^[A-Za-z]:/$")) {
                break;
            }
            p = p.substring(0, p.length() - 1);
        }

        return p;
    }

    private static boolean isLikelyMinecraftCommandLine(String commandLine) {
        if (commandLine == null || commandLine.trim().isEmpty()) {
            return false;
        }

        String lower = commandLine.toLowerCase();

        return lower.contains("org.prismlauncher.entrypoint")
            || lower.contains("org.multimc.entrypoint")
            || lower.contains("mojangtricksinteldriversforperformance");
    }

    private static void sleep(int ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Initialize file logging for watcher mode.
     */
    private static void initLogging() {
        try {
            String cwd = System.getProperty("user.dir");
            File workingDir = new File(cwd);
            File logDir = workingDir.getParentFile() != null ? workingDir.getParentFile() : workingDir;
            File logFile = new File(logDir, LOG_FILE);
            // Append so that launcher/pre-launch logs written earlier in this run are preserved.
            // (The launcher truncates the file once at startup.)
            logWriter = new PrintWriter(new FileWriter(logFile, true));
            log("=== " + PROJECT_NAME + " v" + VERSION + " Watcher Log ===");
            log("Log file: " + logFile.getAbsolutePath());
            log("Working directory: " + cwd);
        } catch (Exception e) {
            System.err.println("Failed to initialize log file: " + e.getMessage());
        }
    }

    /**
     * Truncate (clear) log files at startup so each run begins with a fresh log.
     *
     * Best-effort: failures are ignored (e.g. file locked by another process).
     */
    private static void resetLogFilesForStartup() {
        try {
            String cwd = System.getProperty("user.dir");
            File workingDir = new File(cwd);

            // injector.log lives next to the instance root (parent of minecraft/.minecraft when applicable).
            File logDir = workingDir.getParentFile() != null ? workingDir.getParentFile() : workingDir;
            File injectorLog = new File(logDir, LOG_FILE);

            // watcher-stdio.log is in the working directory we launch the watcher from.
            File watcherStdioLog = new File(workingDir, "watcher-stdio.log");

            truncateFileBestEffort(injectorLog);
            truncateFileBestEffort(watcherStdioLog);
        } catch (Throwable ignored) {
            // ignore
        }
    }

    private static void truncateFileBestEffort(File file) {
        if (file == null) {
            return;
        }

        try {
            Path p = file.toPath();
            try {
                Path parent = p.getParent();
                if (parent != null) {
                    Files.createDirectories(parent);
                }
            } catch (Throwable ignored) {
                // ignore
            }

            OutputStream os = null;
            try {
                os = Files.newOutputStream(p, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
            } finally {
                if (os != null) {
                    try { os.close(); } catch (Throwable ignored) {}
                }
            }
        } catch (Throwable ignored) {
            // ignore
        }
    }

    /**
     * Best-effort launcher logging to the same injector log file used by watcher mode.
     * This runs before watcher starts, so we do not reuse watcher-mode PrintWriter.
     */
    private static void launcherLog(String message) {
        String msg = message != null ? message : "";
        String timestamp;
        try {
            timestamp = dateFormat.format(new Date());
        } catch (Throwable ignored) {
            timestamp = "";
        }
        String line = (timestamp.isEmpty() ? "" : ("[" + timestamp + "] ")) + msg;

        // Console for visibility in launcher stdout.
        try {
            System.out.println(line);
        } catch (Throwable ignored) {
            // ignore
        }

        // Append to injector.log (best-effort).
        try {
            String cwd = System.getProperty("user.dir");
            File workingDir = new File(cwd);
            File logDir = workingDir.getParentFile() != null ? workingDir.getParentFile() : workingDir;
            File logFile = new File(logDir, LOG_FILE);
            FileWriter fw = new FileWriter(logFile, true);
            try {
                fw.write(line + System.lineSeparator());
            } finally {
                try { fw.close(); } catch (Throwable ignored) {}
            }
        } catch (Throwable ignored) {
            // ignore
        }
    }

    /**
     * Close the log file.
     */
    private static void closeLogging() {
        if (logWriter != null) {
            logWriter.close();
            logWriter = null;
        }
    }

    /**
     * Log a message to both console and file.
     */
    private static void log(String message) {
        String timestamp = dateFormat.format(new Date());
        String line = "[" + timestamp + "] " + message;
        System.out.println(line);
        if (logWriter != null) {
            logWriter.println(line);
            logWriter.flush();
        }
    }
}
