package com.easyinject;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import java.util.concurrent.CountDownLatch;
import java.util.regex.Pattern;

/**
 * Optional self-updater for the pre-launch (launcher) mode.
 *
 * Design goals:
 * - Never block game launch unless the user explicitly confirms the update.
 * - No hardcoded repository URLs: all endpoints come from branding.properties.
 * - Windows-friendly replace flow: the running JAR cannot overwrite itself, so we
 *   download to a temp file and then spawn a detached script which replaces the
 *   JAR after this process exits, then spawns the watcher.
 */
public final class Updater {

    private Updater() {
    }

    /**
     * Simple logging callback used by the launcher to record update decisions.
     */
    public interface LogSink {
        void log(String msg);
    }

    private static void log(LogSink sink, String msg) {
        if (sink == null) {
            return;
        }
        try {
            sink.log(msg != null ? msg : "");
        } catch (Throwable ignored) {
            // ignore
        }
    }

    /**
     * @return true if an update was accepted and we scheduled replacement + watcher spawn.
     */
    public static boolean maybeUpdateAndRescheduleWatcher(
        String projectName,
        String currentVersion,
        String currentJarPath,
        String javaExe,
        String workingDir
    ) {
        return maybeUpdateAndRescheduleWatcher(projectName, currentVersion, currentJarPath, javaExe, workingDir, null);
    }

    /**
     * @return true if an update was accepted and we scheduled replacement + watcher spawn.
     */
    public static boolean maybeUpdateAndRescheduleWatcher(
        String projectName,
        String currentVersion,
        String currentJarPath,
        String javaExe,
        String workingDir,
        LogSink logSink
    ) {
        if (projectName == null) {
            projectName = "EasyInject";
        }
        if (currentVersion == null) {
            currentVersion = "";
        }

        if (isHeadless()) {
            log(logSink, "Skipped: headless environment");
            return false;
        }

        File jarFile = safeFile(currentJarPath);
        if (jarFile == null || !jarFile.isFile() || !jarFile.getName().toLowerCase().endsWith(".jar")) {
            log(logSink, "Skipped: current path is not a JAR");
            return false;
        }

        // Always target a stable filename in the same folder, so that the launcher
        // PreLaunchCommand can keep pointing to <brand>.jar forever.
        File targetJar = resolveStableTargetJar(projectName, jarFile);

        Properties props = loadBrandingProperties();
        String apiUrl = trimToNull(props.getProperty("update.latestReleaseApiUrl"));
        String releasesUrl = trimToNull(props.getProperty("update.releasesUrl"));
        String assetNameRegex = trimToNull(props.getProperty("update.assetNameRegex"));

        if (apiUrl == null) {
            apiUrl = deriveLatestReleaseApiUrl(releasesUrl);
        }
        if (apiUrl == null) {
            log(logSink, "Skipped: no update.latestReleaseApiUrl configured");
            return false;
        }

        log(logSink, "Checking latest release via: " + apiUrl);

        LatestRelease latest;
        try {
            latest = fetchLatestRelease(apiUrl);
        } catch (Exception e) {
            log(logSink, "Skipped: network/API error while checking latest release: " + e.getClass().getSimpleName() + ": " + (e.getMessage() != null ? e.getMessage() : ""));
            return false;
        }

        if (latest == null || latest.tagName == null || latest.tagName.trim().isEmpty()) {
            log(logSink, "Skipped: API returned no tag_name");
            return false;
        }

        String remoteVersion = normalizeVersion(latest.tagName);
        String localVersion = normalizeVersion(currentVersion);
        log(logSink, "Current=" + (localVersion.isEmpty() ? currentVersion : localVersion) + ", Latest=" + remoteVersion);
        if (compareVersions(remoteVersion, localVersion) <= 0) {
            log(logSink, "No update available");
            return false; // up to date
        }

        log(logSink, "Update available");

        // Confirm with user.
        try {
            Main.applyDarkTheme();
        } catch (Throwable ignored) {
            // non-fatal
        }

        boolean accepted = showUpdateConfirmDialog(
            projectName,
            localVersion.isEmpty() ? currentVersion : localVersion,
            remoteVersion,
            releasesUrl
        );
        if (!accepted) {
            log(logSink, "User declined update");
            return false;
        }

        Asset asset = chooseAsset(latest.assetsJson, assetNameRegex, targetJar.getName());
        if (asset == null || asset.browserDownloadUrl == null) {
            log(logSink, "Update found but no matching .jar asset was found");
            JOptionPane.showMessageDialog(
                null,
                "Update found, but no downloadable .jar asset was found in the release.\n\n" +
                    "Tag: " + latest.tagName,
                projectName + " Updater",
                JOptionPane.WARNING_MESSAGE
            );
            return false;
        }

        log(logSink, "Selected asset: " + asset.name);

        File tempDir = new File(System.getProperty("java.io.tmpdir"), projectName + "-update");
        //noinspection ResultOfMethodCallIgnored
        tempDir.mkdirs();

        File downloadedJar = new File(tempDir, "update-" + remoteVersion + ".jar");

        DownloadResult dl = downloadWithProgressUI(projectName, asset, downloadedJar);
        if (dl == null || !dl.success) {
            log(logSink, "Download failed: " + (dl != null ? dl.message : "Unknown error"));
            JOptionPane.showMessageDialog(
                null,
                "Update download failed.\n\n" + (dl != null ? dl.message : "Unknown error"),
                projectName + " Updater",
                JOptionPane.ERROR_MESSAGE
            );
            return false;
        }

        log(logSink, "Download complete: " + downloadedJar.getAbsolutePath());

        try {
            scheduleReplaceAndWatcherSpawn(
                projectName,
                javaExe,
                workingDir,
                downloadedJar,
                targetJar
            );
            log(logSink, "Scheduled replace of: " + targetJar.getAbsolutePath());
            return true;
        } catch (Exception e) {
            log(logSink, "Failed to schedule update install: " + e.getClass().getSimpleName() + ": " + (e.getMessage() != null ? e.getMessage() : ""));
            JOptionPane.showMessageDialog(
                null,
                "Downloaded the update, but failed to schedule installation.\n\n" + e.getMessage(),
                projectName + " Updater",
                JOptionPane.ERROR_MESSAGE
            );
            return false;
        }
    }

    private static Properties loadBrandingProperties() {
        Properties props = new Properties();
        InputStream is = null;
        try {
            is = Updater.class.getResourceAsStream("/branding.properties");
            if (is != null) {
                props.load(is);
            }
        } catch (Throwable ignored) {
            // ignore
        } finally {
            if (is != null) {
                try {
                    is.close();
                } catch (Throwable ignored) {
                    // ignore
                }
            }
        }
        return props;
    }

    private static boolean isHeadless() {
        try {
            return GraphicsEnvironment.isHeadless();
        } catch (Throwable ignored) {
            return true;
        }
    }

    private static File safeFile(String path) {
        if (path == null) {
            return null;
        }
        String p = path.trim();
        if (p.isEmpty()) {
            return null;
        }
        try {
            return new File(p);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static File resolveStableTargetJar(String projectName, File currentJar) {
        if (currentJar == null) {
            return null;
        }

        File dir = null;
        try {
            dir = currentJar.getParentFile();
        } catch (Throwable ignored) {
            dir = null;
        }

        if (dir == null) {
            return currentJar;
        }

        String base = (projectName != null) ? projectName.trim() : "";
        if (base.isEmpty()) {
            base = "Toolscreen";
        }

        // Windows filename sanitize.
        base = base.replaceAll("[\\\\/:*\\\"<>|]", "_");

        return new File(dir, base + ".jar");
    }

    private static String trimToNull(String s) {
        if (s == null) {
            return null;
        }
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    private static String deriveLatestReleaseApiUrl(String releasesUrl) {
        // Accept forms like:
        // https://github.com/owner/repo/releases
        // https://github.com/owner/repo/releases/latest
        if (releasesUrl == null) {
            return null;
        }
        String u = releasesUrl.trim();
        if (u.isEmpty()) {
            return null;
        }
        try {
            URL url = new URL(u);
            String host = url.getHost();
            if (host == null || !host.toLowerCase().endsWith("github.com")) {
                return null;
            }
            String path = url.getPath();
            if (path == null) {
                return null;
            }
            // /owner/repo/releases...
            String[] parts = path.split("/");
            // parts[0] is "" due to leading slash
            if (parts.length < 4) {
                return null;
            }
            String owner = parts[1];
            String repo = parts[2];
            if (owner.isEmpty() || repo.isEmpty()) {
                return null;
            }
            return "https://api.github.com/repos/" + owner + "/" + repo + "/releases/latest";
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static final class LatestRelease {
        final String tagName;
        final JsonArray assetsJson;

        LatestRelease(String tagName, JsonArray assetsJson) {
            this.tagName = tagName;
            this.assetsJson = assetsJson;
        }
    }

    private static final class Asset {
        final String name;
        final String browserDownloadUrl;
        final long size;

        Asset(String name, String browserDownloadUrl, long size) {
            this.name = name;
            this.browserDownloadUrl = browserDownloadUrl;
            this.size = size;
        }
    }

    private static LatestRelease fetchLatestRelease(String apiUrl) throws IOException {
        HttpURLConnection conn = openHttp(new URL(apiUrl));
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Accept", "application/vnd.github+json");
        conn.setRequestProperty("User-Agent", "EasyInject-Updater");
        conn.setConnectTimeout(10_000);
        conn.setReadTimeout(15_000);

        int code = conn.getResponseCode();
        InputStream in = (code >= 200 && code < 300) ? conn.getInputStream() : conn.getErrorStream();
        if (in == null) {
            return null;
        }

        String json;
        try {
            json = readAllUtf8(in);
        } finally {
            try {
                in.close();
            } catch (Throwable ignored) {
                // ignore
            }
        }

        if (json == null || json.trim().isEmpty()) {
            return null;
        }

        JsonElement el = JsonParser.parseString(json);
        if (!el.isJsonObject()) {
            return null;
        }
        JsonObject obj = el.getAsJsonObject();
        String tag = optString(obj, "tag_name");
        JsonArray assets = null;
        JsonElement assetsEl = obj.get("assets");
        if (assetsEl != null && assetsEl.isJsonArray()) {
            assets = assetsEl.getAsJsonArray();
        }
        return new LatestRelease(tag, assets);
    }

    private static Asset chooseAsset(JsonArray assetsJson, String assetNameRegex, String currentJarName) {
        if (assetsJson == null || assetsJson.size() == 0) {
            return null;
        }

        Pattern pat = null;
        try {
            if (assetNameRegex != null && !assetNameRegex.trim().isEmpty()) {
                pat = Pattern.compile(assetNameRegex, Pattern.CASE_INSENSITIVE);
            }
        } catch (Throwable ignored) {
            pat = null;
        }

        // First pass: regex match
        if (pat != null) {
            for (JsonElement e : assetsJson) {
                Asset a = assetFromJson(e);
                if (a != null && a.name != null && pat.matcher(a.name).matches()) {
                    return a;
                }
            }
        }

        // Second pass: prefer same filename as current jar if present
        if (currentJarName != null) {
            String cur = currentJarName.trim();
            for (JsonElement e : assetsJson) {
                Asset a = assetFromJson(e);
                if (a != null && a.name != null && a.name.equalsIgnoreCase(cur)) {
                    return a;
                }
            }
        }

        // Third pass: any .jar
        for (JsonElement e : assetsJson) {
            Asset a = assetFromJson(e);
            if (a != null && a.name != null && a.name.toLowerCase().endsWith(".jar")) {
                return a;
            }
        }

        return null;
    }

    private static Asset assetFromJson(JsonElement e) {
        if (e == null || !e.isJsonObject()) {
            return null;
        }
        JsonObject o = e.getAsJsonObject();
        String name = optString(o, "name");
        String url = optString(o, "browser_download_url");
        long size = optLong(o, "size");
        if (name == null || url == null) {
            return null;
        }
        return new Asset(name, url, size);
    }

    private static String optString(JsonObject obj, String key) {
        if (obj == null || key == null) {
            return null;
        }
        JsonElement el = obj.get(key);
        if (el == null || el.isJsonNull()) {
            return null;
        }
        try {
            String s = el.getAsString();
            return (s != null && !s.trim().isEmpty()) ? s : null;
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static long optLong(JsonObject obj, String key) {
        if (obj == null || key == null) {
            return -1;
        }
        JsonElement el = obj.get(key);
        if (el == null || el.isJsonNull()) {
            return -1;
        }
        try {
            return el.getAsLong();
        } catch (Throwable ignored) {
            return -1;
        }
    }

    private static String normalizeVersion(String v) {
        if (v == null) {
            return "";
        }
        String t = v.trim();
        if (t.startsWith("v") || t.startsWith("V")) {
            t = t.substring(1);
        }
        return t.trim();
    }

    /**
     * Version compare intended for dotted numeric versions like 1.2.3.
     * Returns &gt;0 if a &gt; b.
     */
    private static int compareVersions(String a, String b) {
        if (a == null) {
            a = "";
        }
        if (b == null) {
            b = "";
        }
        String[] ap = a.trim().split("\\.");
        String[] bp = b.trim().split("\\.");
        int n = Math.max(ap.length, bp.length);
        for (int i = 0; i < n; i++) {
            int ai = (i < ap.length) ? parseIntOrZero(ap[i]) : 0;
            int bi = (i < bp.length) ? parseIntOrZero(bp[i]) : 0;
            if (ai != bi) {
                return ai - bi;
            }
        }
        // If numeric parts equal, do a stable string compare as tie-breaker.
        return a.compareToIgnoreCase(b);
    }

    private static int parseIntOrZero(String s) {
        if (s == null) {
            return 0;
        }
        String t = s.trim();
        if (t.isEmpty()) {
            return 0;
        }
        // Strip any suffix like "1-alpha" -> "1"
        int cut = -1;
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            if (c < '0' || c > '9') {
                cut = i;
                break;
            }
        }
        if (cut > 0) {
            t = t.substring(0, cut);
        }
        try {
            return Integer.parseInt(t);
        } catch (Throwable ignored) {
            return 0;
        }
    }

    private static final class DownloadResult {
        final boolean success;
        final String message;

        DownloadResult(boolean success, String message) {
            this.success = success;
            this.message = message;
        }
    }

    private static boolean showUpdateConfirmDialog(String projectName, String localVersion, String remoteVersion, String releasesUrl) {
        final String pName = (projectName == null || projectName.trim().isEmpty()) ? "EasyInject" : projectName.trim();
        final String lVer = (localVersion != null) ? localVersion : "";
        final String rVer = (remoteVersion != null) ? remoteVersion : "";
        final String rUrl = (releasesUrl != null) ? releasesUrl : null;

        final Color bg = new Color(43, 43, 43);
        final Color fg = new Color(224, 224, 224);
        final Color subtle = new Color(199, 206, 214);
        final Color accent = new Color(129, 212, 250);
        final Color green = new Color(76, 175, 80);

        final boolean[] accepted = new boolean[] { false };
        final CountDownLatch done = new CountDownLatch(1);

        try {
            SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run() {
                    final JDialog dialog = new JDialog((Frame) null, pName + " — Update", true);
                    dialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
                    dialog.setResizable(false);

                    JPanel root = new JPanel(new BorderLayout(0, 12)) {
                        @Override
                        protected void paintComponent(Graphics g) {
                            g.setColor(bg);
                            g.fillRect(0, 0, getWidth(), getHeight());
                            super.paintComponent(g);
                        }
                    };
                    root.setOpaque(false);
                    root.setDoubleBuffered(true);
                    root.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
                    root.setPreferredSize(new Dimension(560, 260));

                    // Header
                    JPanel header = new JPanel(new BorderLayout(10, 0));
                    header.setOpaque(true);
                    header.setBackground(bg);

                    JLabel title = new JLabel("Update available");
                    title.setFont(new Font("Segoe UI", Font.BOLD, 16));
                    title.setForeground(green);
                    title.setIcon(createUpdateStatusIcon());
                    title.setIconTextGap(8);
                    header.add(title, BorderLayout.WEST);
                    root.add(header, BorderLayout.NORTH);

                    // Body
                    JPanel body = new JPanel();
                    body.setOpaque(true);
                    body.setBackground(bg);
                    body.setLayout(new BoxLayout(body, BoxLayout.Y_AXIS));

                    JLabel line1 = new JLabel("<html><body style='width: 480px; font-family: Segoe UI, sans-serif;'>" +
                        "<p style='margin:0 0 10px 0; color:#e0e0e0;'>A newer version of <b>" + escapeHtml(pName) + "</b> is available.</p>" +
                        "</body></html>");
                    line1.setForeground(fg);
                    line1.setAlignmentX(Component.LEFT_ALIGNMENT);
                    body.add(line1);

                    JPanel table = new JPanel(new GridBagLayout());
                    table.setOpaque(true);
                    table.setBackground(bg);
                    table.setAlignmentX(Component.LEFT_ALIGNMENT);

                    GridBagConstraints gc = new GridBagConstraints();
                    gc.gridx = 0;
                    gc.gridy = 0;
                    gc.anchor = GridBagConstraints.WEST;
                    gc.insets = new Insets(2, 0, 2, 10);

                    JLabel curKey = new JLabel("Current");
                    curKey.setFont(new Font("Segoe UI", Font.PLAIN, 12));
                    curKey.setForeground(subtle);
                    table.add(curKey, gc);

                    gc.gridx = 1;
                    JLabel curVal = new JLabel("v" + lVer);
                    curVal.setFont(new Font("Segoe UI", Font.BOLD, 12));
                    curVal.setForeground(accent);
                    table.add(curVal, gc);

                    gc.gridx = 0;
                    gc.gridy = 1;
                    JLabel newKey = new JLabel("Latest");
                    newKey.setFont(new Font("Segoe UI", Font.PLAIN, 12));
                    newKey.setForeground(subtle);
                    table.add(newKey, gc);

                    gc.gridx = 1;
                    JLabel newVal = new JLabel("v" + rVer);
                    newVal.setFont(new Font("Segoe UI", Font.BOLD, 12));
                    newVal.setForeground(accent);
                    table.add(newVal, gc);

                    if (rUrl != null && !rUrl.trim().isEmpty()) {
                        gc.gridx = 0;
                        gc.gridy = 2;
                        JLabel urlKey = new JLabel("Release page");
                        urlKey.setFont(new Font("Segoe UI", Font.PLAIN, 12));
                        urlKey.setForeground(subtle);
                        table.add(urlKey, gc);

                        gc.gridx = 1;
                        JLabel urlVal = new JLabel(rUrl);
                        urlVal.setFont(new Font("Consolas", Font.PLAIN, 11));
                        urlVal.setForeground(new Color(180, 180, 180));
                        table.add(urlVal, gc);
                    }

                    body.add(table);
                    body.add(Box.createVerticalStrut(8));

                    JLabel hint = new JLabel("<html><body style='width: 480px; font-family: Segoe UI, sans-serif; color:#c7ced6; font-size: 11px;'>" +
                        "If you choose <b>Update</b>, the new JAR will be downloaded, replace <b>" + escapeHtml(pName) + ".jar</b>, and the watcher will be started automatically." +
                        "</body></html>");
                    hint.setAlignmentX(Component.LEFT_ALIGNMENT);
                    body.add(hint);

                    root.add(body, BorderLayout.CENTER);

                    // Buttons
                    JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
                    buttons.setOpaque(true);
                    buttons.setBackground(bg);

                    JButton skip = createStyledButton("Not now");
                    JButton update = createStyledButton("Update");

                    // Make primary action a bit more prominent.
                    update.setFont(new Font("Segoe UI", Font.BOLD, 12));

                    skip.addActionListener(new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            accepted[0] = false;
                            dialog.dispose();
                        }
                    });
                    update.addActionListener(new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            accepted[0] = true;
                            dialog.dispose();
                        }
                    });

                    buttons.add(skip);
                    buttons.add(update);
                    root.add(buttons, BorderLayout.SOUTH);

                    dialog.setContentPane(root);
                    dialog.pack();
                    dialog.setMinimumSize(new Dimension(560, 260));
                    dialog.setLocationRelativeTo(null);
                    dialog.setAlwaysOnTop(true);
                    dialog.setVisible(true);

                    done.countDown();
                }
            });

            done.await();
        } catch (Throwable ignored) {
            return false;
        }

        return accepted[0];
    }

    private static DownloadResult downloadWithProgressUI(String projectName, Asset asset, File outFile) {
        final ProgressDialog dialog = new ProgressDialog(projectName, "Downloading " + asset.name);
        final CountDownLatch done = new CountDownLatch(1);
        final DownloadResult[] result = new DownloadResult[1];

        SwingWorker<Void, Integer> worker = new SwingWorker<Void, Integer>() {
            @Override
            protected Void doInBackground() {
                try {
                    //noinspection ResultOfMethodCallIgnored
                    outFile.getParentFile().mkdirs();

                    downloadToFile(asset.browserDownloadUrl, outFile, new ProgressCallback() {
                        @Override
                        public void onProgress(long bytesRead, long totalBytes) {
                            int pct = -1;
                            if (totalBytes > 0) {
                                pct = (int) Math.min(100, (bytesRead * 100L) / totalBytes);
                            }
                            dialog.setProgress(bytesRead, totalBytes, pct);
                        }

                        @Override
                        public void onStatus(String status) {
                            dialog.setStatus(status);
                        }
                    });

                    result[0] = new DownloadResult(true, "OK");
                } catch (Exception e) {
                    result[0] = new DownloadResult(false, e.getMessage());
                }
                return null;
            }

            @Override
            protected void done() {
                try {
                    dialog.close();
                } finally {
                    done.countDown();
                }
            }
        };

        // Show the dialog on the EDT.
        try {
            SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run() {
                    dialog.open();
                }
            });
        } catch (Throwable ignored) {
            // ignore
        }

        worker.execute();

        try {
            done.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new DownloadResult(false, "Interrupted");
        }

        if (result[0] == null) {
            return new DownloadResult(false, "Unknown error");
        }

        if (result[0].success) {
            if (!outFile.isFile() || outFile.length() <= 0) {
                return new DownloadResult(false, "Downloaded file is missing or empty");
            }
        }

        return result[0];
    }

    private interface ProgressCallback {
        void onProgress(long bytesRead, long totalBytes);

        void onStatus(String status);
    }

    private static void downloadToFile(String urlStr, File outFile, ProgressCallback cb) throws IOException {
        if (cb != null) {
            cb.onStatus("Connecting...");
        }

        URL url = new URL(urlStr);
        HttpURLConnection conn = openHttp(url);
        conn.setInstanceFollowRedirects(true);
        conn.setRequestProperty("User-Agent", "EasyInject-Updater");
        conn.setRequestProperty("Accept", "application/octet-stream");
        conn.setConnectTimeout(10_000);
        conn.setReadTimeout(30_000);

        int code = conn.getResponseCode();
        if (code >= 300 && code < 400) {
            String loc = conn.getHeaderField("Location");
            if (loc != null && !loc.trim().isEmpty()) {
                downloadToFile(loc.trim(), outFile, cb);
                return;
            }
        }

        if (code < 200 || code >= 300) {
            InputStream err = conn.getErrorStream();
            String msg = "HTTP " + code;
            if (err != null) {
                try {
                    msg += ": " + readAllUtf8(err);
                } catch (Throwable ignored) {
                    // ignore
                } finally {
                    try {
                        err.close();
                    } catch (Throwable ignored) {
                        // ignore
                    }
                }
            }
            throw new IOException(msg);
        }

        long total = conn.getContentLengthLong();
        if (cb != null) {
            cb.onStatus("Downloading...");
        }

        InputStream in = conn.getInputStream();
        FileOutputStream out = null;
        try {
            out = new FileOutputStream(outFile);
            byte[] buf = new byte[64 * 1024];
            long read = 0;
            int n;
            while ((n = in.read(buf)) >= 0) {
                out.write(buf, 0, n);
                read += n;
                if (cb != null) {
                    cb.onProgress(read, total);
                }
            }
        } finally {
            try {
                in.close();
            } catch (Throwable ignored) {
                // ignore
            }
            if (out != null) {
                try {
                    out.close();
                } catch (Throwable ignored) {
                    // ignore
                }
            }
        }
    }

    private static HttpURLConnection openHttp(URL url) throws IOException {
        return (HttpURLConnection) url.openConnection();
    }

    private static String readAllUtf8(InputStream in) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) >= 0) {
            baos.write(buf, 0, n);
        }
        return new String(baos.toByteArray(), StandardCharsets.UTF_8);
    }

    private static void scheduleReplaceAndWatcherSpawn(
        String projectName,
        String javaExe,
        String workingDir,
        File downloadedJar,
        File targetJar
    ) throws IOException {
        // Create a detached .cmd script so we can overwrite the target after this JVM exits.
        File scriptDir = downloadedJar.getParentFile();
        File script = new File(scriptDir, "apply-update-" + System.currentTimeMillis() + ".cmd");

        String javaPath = (javaExe == null || javaExe.trim().isEmpty()) ? "javaw.exe" : javaExe.trim();
        String wd = (workingDir == null || workingDir.trim().isEmpty()) ? new File(".").getAbsolutePath() : workingDir.trim();

        String scriptText = buildWindowsUpdateScript(projectName, javaPath, wd, downloadedJar, targetJar);

        writeTextFile(script, scriptText);

        // Run detached.
        ProcessBuilder pb = new ProcessBuilder(
            "cmd",
            "/C",
            "start",
            "\"\"",
            "/B",
            script.getAbsolutePath()
        );
        pb.directory(new File(wd));
        pb.start();
    }

    private static String buildWindowsUpdateScript(
        String projectName,
        String javaExe,
        String workingDir,
        File downloadedJar,
        File targetJar
    ) {
        // Retry copy for a bit in case the file is still locked while this process is shutting down.
        // Then start watcher from the replaced jar.
        String dl = downloadedJar.getAbsolutePath();
        String tgt = targetJar.getAbsolutePath();

        StringBuilder sb = new StringBuilder();
        sb.append("@echo off\r\n");
        sb.append("setlocal enableextensions enabledelayedexpansion\r\n");
        sb.append("set \"DL=").append(escapeForCmdSet(dl)).append("\"\r\n");
        sb.append("set \"TGT=").append(escapeForCmdSet(tgt)).append("\"\r\n");
        sb.append("set \"JAVA=").append(escapeForCmdSet(javaExe)).append("\"\r\n");
        sb.append("set \"WD=").append(escapeForCmdSet(workingDir)).append("\"\r\n");
        sb.append("set \"NAME=").append(escapeForCmdSet(projectName)).append("\"\r\n");
        sb.append("\r\n");
        sb.append("set /a tries=0\r\n");
        sb.append(":retry\r\n");
        sb.append("set /a tries+=1\r\n");
        sb.append("copy /Y \"%DL%\" \"%TGT%\" >nul 2>nul\r\n");
        sb.append("if %errorlevel%==0 goto ok\r\n");
        sb.append("if %tries% GEQ 30 goto fail\r\n");
        sb.append("timeout /t 1 /nobreak >nul\r\n");
        sb.append("goto retry\r\n");
        sb.append("\r\n");
        sb.append(":ok\r\n");
        sb.append("del /f /q \"%DL%\" >nul 2>nul\r\n");
        sb.append("pushd \"%WD%\"\r\n");
        sb.append("start \"\" /B \"%JAVA%\" -jar \"%TGT%\" --watcher\r\n");
        sb.append("popd\r\n");
        sb.append("goto cleanup\r\n");
        sb.append("\r\n");
        sb.append(":fail\r\n");
        sb.append("REM If we cannot replace, still try to start watcher from current jar.\r\n");
        sb.append("pushd \"%WD%\"\r\n");
        sb.append("start \"\" /B \"%JAVA%\" -jar \"%TGT%\" --watcher\r\n");
        sb.append("popd\r\n");
        sb.append("\r\n");
        sb.append(":cleanup\r\n");
        sb.append("endlocal\r\n");
        sb.append("del /f /q \"%~f0\" >nul 2>nul\r\n");
        return sb.toString();
    }

    private static String escapeForCmdSet(String s) {
        // For: set "VAR=..."
        // Only need to escape embedded quotes. Other metacharacters are okay inside quoted value.
        if (s == null) {
            return "";
        }
        return s.replace("\"", "\"\"");
    }

    private static void writeTextFile(File f, String text) throws IOException {
        OutputStream out = new FileOutputStream(f);
        try {
            out.write(text.getBytes(StandardCharsets.UTF_8));
        } finally {
            try {
                out.close();
            } catch (Throwable ignored) {
                // ignore
            }
        }
    }

    /**
     * Minimal progress UI.
     */
    private static final class ProgressDialog {
        private final String title;
        private final String initialStatus;
        private JDialog dialog;
        private JLabel status;
        private JProgressBar bar;

        ProgressDialog(String title, String initialStatus) {
            this.title = title;
            this.initialStatus = initialStatus;
        }

        void open() {
            if (dialog != null) {
                return;
            }

            final Color bg = new Color(43, 43, 43);
            final Color fg = new Color(224, 224, 224);
            final Color subtle = new Color(199, 206, 214);

            dialog = new JDialog((Frame) null, title + " Updater", false);
            dialog.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
            dialog.setSize(560, 160);
            dialog.setLocationRelativeTo(null);

            JPanel root = new JPanel();
            root = new JPanel(new BorderLayout(0, 10)) {
                @Override
                protected void paintComponent(Graphics g) {
                    g.setColor(bg);
                    g.fillRect(0, 0, getWidth(), getHeight());
                    super.paintComponent(g);
                }
            };
            root.setOpaque(false);
            root.setDoubleBuffered(true);
            root.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
            root.setPreferredSize(new Dimension(560, 160));

            status = new JLabel(initialStatus);
            status.setFont(new Font("Segoe UI", Font.PLAIN, 12));
            status.setForeground(fg);
            root.add(status, BorderLayout.NORTH);

            bar = new JProgressBar(0, 100);
            bar.setStringPainted(true);
            bar.setValue(0);
            bar.setIndeterminate(true);
            bar.setBackground(new Color(30, 30, 30));
            bar.setForeground(new Color(76, 175, 80));
            bar.setBorder(BorderFactory.createLineBorder(new Color(82, 82, 82)));
            root.add(bar, BorderLayout.CENTER);

            JLabel hint = new JLabel("Please wait...", SwingConstants.LEFT);
            hint.setFont(new Font("Segoe UI", Font.PLAIN, 11));
            hint.setForeground(subtle);
            root.add(hint, BorderLayout.SOUTH);

            dialog.setContentPane(root);
            dialog.setAlwaysOnTop(true);
            dialog.setVisible(true);
        }

        void setStatus(final String s) {
            if (s == null) {
                return;
            }
            SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run() {
                    if (status != null) {
                        status.setText(s);
                    }
                }
            });
        }

        void setProgress(final long bytesRead, final long totalBytes, final int pct) {
            SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run() {
                    if (bar == null) {
                        return;
                    }
                    if (pct >= 0) {
                        bar.setIndeterminate(false);
                        bar.setValue(pct);
                        if (totalBytes > 0) {
                            bar.setString(pct + "% (" + formatBytes(bytesRead) + " / " + formatBytes(totalBytes) + ")");
                        } else {
                            bar.setString(pct + "%");
                        }
                    } else {
                        bar.setIndeterminate(true);
                        bar.setString(formatBytes(bytesRead));
                    }
                }
            });
        }

        void close() {
            try {
                SwingUtilities.invokeLater(new Runnable() {
                    @Override
                    public void run() {
                        if (dialog != null) {
                            dialog.setVisible(false);
                            dialog.dispose();
                            dialog = null;
                        }
                    }
                });
            } catch (Throwable ignored) {
                // ignore
            }
        }

        private static String formatBytes(long b) {
            if (b < 0) {
                return "?";
            }
            if (b < 1024) {
                return b + " B";
            }
            if (b < 1024L * 1024L) {
                return String.format("%.1f KB", b / 1024.0);
            }
            return String.format("%.1f MB", b / (1024.0 * 1024.0));
        }
    }

    /**
     * Create a styled button matching the installer UI.
     */
    private static JButton createStyledButton(String text) {
        JButton btn = new JButton(text) {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

                // Clear full bounds first (prevents hover repaint trails/ghosting on some Windows L&Fs).
                Color clear = null;
                try {
                    Container p = getParent();
                    if (p != null) {
                        clear = p.getBackground();
                    }
                } catch (Throwable ignored) {
                    clear = null;
                }
                if (clear == null) {
                    clear = new Color(43, 43, 43);
                }
                g2.setColor(clear);
                g2.fillRect(0, 0, getWidth(), getHeight());

                Color bgColor;
                if (getModel().isPressed()) {
                    bgColor = new Color(40, 40, 40);
                } else if (getModel().isRollover()) {
                    bgColor = new Color(80, 80, 80);
                } else {
                    bgColor = new Color(60, 60, 60);
                }

                int x = 1;
                int y = 1;
                int w = Math.max(0, getWidth() - 2);
                int h = Math.max(0, getHeight() - 2);
                int arc = 10;

                g2.setColor(bgColor);
                g2.fillRoundRect(x, y, w, h, arc, arc);

                g2.setColor(new Color(100, 100, 100));
                if (w > 1 && h > 1) {
                    g2.drawRoundRect(x, y, w - 1, h - 1, arc, arc);
                }

                // Paint text and icon over the custom background using the same AA-enabled Graphics.
                super.paintComponent(g2);
                g2.dispose();
            }
        };

        btn.setFont(new Font("Segoe UI", Font.BOLD, 12));
        btn.setForeground(new Color(224, 224, 224));
        btn.setCursor(new Cursor(Cursor.HAND_CURSOR));

        btn.setContentAreaFilled(false);
        btn.setFocusPainted(false);
        btn.setBorderPainted(false);
        // Keep the button non-opaque so Swing doesn't fill a square background behind our rounded paint.
        btn.setOpaque(false);
        btn.setRolloverEnabled(true);
        btn.setBorder(BorderFactory.createEmptyBorder(8, 20, 8, 20));
        btn.setDoubleBuffered(true);

        // Force repaints of the parent region on rollover/press changes.
        btn.getModel().addChangeListener(new javax.swing.event.ChangeListener() {
            @Override
            public void stateChanged(javax.swing.event.ChangeEvent e) {
                btn.repaint();
                Container p = btn.getParent();
                if (p != null) {
                    int pad = 2;
                    p.repaint(btn.getX() - pad, btn.getY() - pad, btn.getWidth() + pad * 2, btn.getHeight() + pad * 2);
                }
            }
        });
        return btn;
    }

    private static Icon createUpdateStatusIcon() {
        return new Icon() {
            private final int size = 16;

            @Override
            public void paintIcon(Component c, Graphics g, int x, int y) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

                // Green circle
                g2.setColor(new Color(76, 175, 80));
                g2.fillOval(x, y, size, size);

                // White up arrow
                g2.setColor(Color.WHITE);
                g2.setStroke(new BasicStroke(2.0f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
                int cx = x + size / 2;
                g2.drawLine(cx, y + 12, cx, y + 5);
                g2.drawLine(cx, y + 5, cx - 3, y + 8);
                g2.drawLine(cx, y + 5, cx + 3, y + 8);
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
}
