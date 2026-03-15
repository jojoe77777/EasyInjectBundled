package com.easyinject;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import javax.swing.*;
import java.awt.*;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Properties;
import java.util.concurrent.CountDownLatch;
import java.util.regex.Pattern;

public final class ToolscreenInstallerMain {

    private static final String INSTALLER_NAME = "Toolscreen Downloader";
    private static final String TARGET_FILE_NAME = "Toolscreen.jar";
    private static final String DEFAULT_RELEASES_URL = "https://github.com/jojoe77777/Toolscreen/releases";
    private static final String DEFAULT_API_URL = "https://api.github.com/repos/jojoe77777/Toolscreen/releases/latest";
    private static final String DEFAULT_ASSET_REGEX = ".*\\.jar$";

    private ToolscreenInstallerMain() {
    }

    public static void main(String[] args) {
        try {
            applyDarkTheme();
        } catch (Throwable ignored) {
            // ignore
        }

        int exitCode = 0;
        try {
            runInstaller();
        } catch (Throwable t) {
            exitCode = 1;
            showError("Download failed.\n\n" + buildErrorMessage(t));
        }
        System.exit(exitCode);
    }

    private static void runInstaller() throws IOException {
        Properties props = loadBrandingProperties();
        String releasesUrl = trimToNull(props.getProperty("update.releasesUrl"));
        if (releasesUrl == null) {
            releasesUrl = DEFAULT_RELEASES_URL;
        }

        String apiUrl = trimToNull(props.getProperty("update.latestReleaseApiUrl"));
        if (apiUrl == null) {
            apiUrl = deriveLatestReleaseApiUrl(releasesUrl);
        }
        if (apiUrl == null) {
            apiUrl = DEFAULT_API_URL;
        }

        String assetRegex = trimToNull(props.getProperty("installer.jarAssetNameRegex"));
        if (assetRegex == null) {
            assetRegex = trimToNull(props.getProperty("update.assetNameRegex"));
        }
        if (assetRegex == null || assetRegex.toLowerCase().contains(".exe")) {
            assetRegex = DEFAULT_ASSET_REGEX;
        }

        LatestRelease latest = fetchLatestRelease(apiUrl);
        if (latest == null || latest.tagName == null || latest.tagName.trim().isEmpty()) {
            throw new IOException("Latest release information was not available from GitHub.");
        }

        Asset asset = chooseAsset(latest.assetsJson, assetRegex, TARGET_FILE_NAME);
        if (asset == null || asset.browserDownloadUrl == null || asset.browserDownloadUrl.trim().isEmpty()) {
            throw new IOException("No downloadable .jar asset was found in the latest release.");
        }

        File installDir = resolveInstallDirectory();
        if (installDir == null) {
            throw new IOException("Could not determine where to save Toolscreen.jar.");
        }
        if (!installDir.isDirectory() && !installDir.mkdirs()) {
            throw new IOException("Could not create install directory: " + installDir.getAbsolutePath());
        }

        File tempFile = new File(installDir, TARGET_FILE_NAME + ".download");
        File outFile = new File(installDir, TARGET_FILE_NAME);

        DownloadResult result = downloadWithProgressUI(asset, tempFile, outFile, latest.tagName);
        if (result == null || !result.success) {
            if (tempFile.exists()) {
                //noinspection ResultOfMethodCallIgnored
                tempFile.delete();
            }
            throw new IOException(result != null ? result.message : "Download failed.");
        }

        showSuccess(outFile);
    }

    private static void applyDarkTheme() {
        Color bg = new Color(43, 43, 43);
        Color fg = new Color(224, 224, 224);
        Color fieldBg = new Color(30, 30, 30);
        Color btnBg = new Color(60, 60, 60);
        Font baseFont = new Font("Segoe UI", Font.PLAIN, 13);
        Font btnFont = new Font("Segoe UI", Font.PLAIN, 12);

        UIManager.put("OptionPane.background", bg);
        UIManager.put("OptionPane.messageForeground", fg);
        UIManager.put("OptionPane.messageFont", baseFont);
        UIManager.put("Panel.background", bg);
        UIManager.put("Panel.foreground", fg);
        UIManager.put("Label.background", bg);
        UIManager.put("Label.foreground", fg);
        UIManager.put("Label.font", baseFont);
        UIManager.put("Button.background", btnBg);
        UIManager.put("Button.foreground", fg);
        UIManager.put("Button.font", btnFont);
        UIManager.put("Button.border", BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(80, 80, 80)),
            BorderFactory.createEmptyBorder(4, 12, 4, 12)
        ));
        UIManager.put("TextField.background", fieldBg);
        UIManager.put("TextField.foreground", fg);
        UIManager.put("TextField.caretForeground", fg);
        UIManager.put("TextField.font", new Font("Consolas", Font.PLAIN, 12));
    }

    private static Properties loadBrandingProperties() {
        Properties props = new Properties();
        InputStream is = null;
        try {
            is = ToolscreenInstallerMain.class.getResourceAsStream("/branding.properties");
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

    private static String trimToNull(String s) {
        if (s == null) {
            return null;
        }
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    private static String deriveLatestReleaseApiUrl(String releasesUrl) {
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
            String[] parts = path.split("/");
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

    private static LatestRelease fetchLatestRelease(String apiUrl) throws IOException {
        HttpURLConnection conn = openHttp(new URL(apiUrl));
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Accept", "application/vnd.github+json");
        conn.setRequestProperty("User-Agent", "Toolscreen-Downloader");
        conn.setConnectTimeout(10_000);
        conn.setReadTimeout(15_000);

        int code = conn.getResponseCode();
        InputStream in = (code >= 200 && code < 300) ? conn.getInputStream() : conn.getErrorStream();
        if (in == null) {
            throw new IOException("GitHub API returned HTTP " + code);
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

        JsonElement el = JsonParser.parseString(json);
        if (!el.isJsonObject()) {
            throw new IOException("Unexpected response from GitHub releases API.");
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

    private static Asset chooseAsset(JsonArray assetsJson, String assetNameRegex, String targetFileName) {
        if (assetsJson == null || assetsJson.size() == 0) {
            return null;
        }

        Pattern pattern = null;
        try {
            if (assetNameRegex != null && !assetNameRegex.trim().isEmpty()) {
                pattern = Pattern.compile(assetNameRegex, Pattern.CASE_INSENSITIVE);
            }
        } catch (Throwable ignored) {
            pattern = null;
        }

        if (pattern != null) {
            for (JsonElement e : assetsJson) {
                Asset asset = assetFromJson(e);
                if (asset != null && asset.name != null && pattern.matcher(asset.name).matches()) {
                    return asset;
                }
            }
        }

        if (targetFileName != null) {
            for (JsonElement e : assetsJson) {
                Asset asset = assetFromJson(e);
                if (asset != null && asset.name != null && asset.name.equalsIgnoreCase(targetFileName)) {
                    return asset;
                }
            }
        }

        for (JsonElement e : assetsJson) {
            Asset asset = assetFromJson(e);
            if (asset != null && asset.name != null && asset.name.toLowerCase().endsWith(".jar")) {
                return asset;
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

    private static File resolveInstallDirectory() {
        try {
            URL location = ToolscreenInstallerMain.class.getProtectionDomain().getCodeSource().getLocation();
            if (location != null) {
                File self = new File(location.toURI());
                File parent = self.isFile() ? self.getParentFile() : self;
                if (parent != null) {
                    return parent;
                }
            }
        } catch (Throwable ignored) {
            // ignore
        }
        try {
            return new File(".").getCanonicalFile();
        } catch (IOException ignored) {
            return new File(".").getAbsoluteFile();
        }
    }

    private static DownloadResult downloadWithProgressUI(Asset asset, File tempFile, File outFile, String tagName) {
        final ProgressDialog dialog = new ProgressDialog(INSTALLER_NAME, asset.name, outFile.getAbsolutePath(), tagName);
        final CountDownLatch done = new CountDownLatch(1);
        final DownloadResult[] result = new DownloadResult[1];

        SwingWorker<Void, Integer> worker = new SwingWorker<Void, Integer>() {
            @Override
            protected Void doInBackground() {
                try {
                    File parent = tempFile.getParentFile();
                    if (parent != null) {
                        //noinspection ResultOfMethodCallIgnored
                        parent.mkdirs();
                    }

                    downloadToFile(asset.browserDownloadUrl, tempFile, new ProgressCallback() {
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

                    try {
                        Files.move(tempFile.toPath(), outFile.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
                    } catch (IOException atomicMoveError) {
                        Files.move(tempFile.toPath(), outFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                    }
                    result[0] = new DownloadResult(true, "OK");
                } catch (Exception e) {
                    result[0] = new DownloadResult(false, e.getMessage() != null ? e.getMessage() : "Download failed");
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
        if (result[0].success && (!outFile.isFile() || outFile.length() <= 0)) {
            return new DownloadResult(false, "Downloaded file is missing or empty");
        }
        return result[0];
    }

    private interface ProgressCallback {
        void onProgress(long bytesRead, long totalBytes);

        void onStatus(String status);
    }

    private static void downloadToFile(String urlStr, File outFile, ProgressCallback cb) throws IOException {
        if (cb != null) {
            cb.onStatus("Connecting to GitHub...");
        }

        URL url = new URL(urlStr);
        HttpURLConnection conn = openHttp(url);
        conn.setInstanceFollowRedirects(true);
        conn.setRequestProperty("User-Agent", "Toolscreen-Downloader");
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
            cb.onStatus("Downloading " + outFile.getName() + "...");
        }

        InputStream in = conn.getInputStream();
        OutputStream out = null;
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

    private static void showSuccess(File outFile) {
        JOptionPane.showMessageDialog(
            null,
            "Toolscreen has been downloaded.\n\nSaved to:\n" + outFile.getAbsolutePath() +
                "\n\nYou must run that file to install Toolscreen.\nThis JAR was only the downloader.",
            INSTALLER_NAME,
            JOptionPane.INFORMATION_MESSAGE
        );
    }

    private static void showError(String message) {
        JOptionPane.showMessageDialog(
            null,
            message,
            INSTALLER_NAME,
            JOptionPane.ERROR_MESSAGE
        );
    }

    private static String buildErrorMessage(Throwable t) {
        if (t == null) {
            return "Unknown error.";
        }
        String msg = t.getMessage();
        if (msg == null || msg.trim().isEmpty()) {
            msg = t.getClass().getSimpleName();
        }
        return msg;
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

    private static final class DownloadResult {
        final boolean success;
        final String message;

        DownloadResult(boolean success, String message) {
            this.success = success;
            this.message = message;
        }
    }

    private static final class ProgressDialog {
        private final String title;
        private final String assetName;
        private final String targetPath;
        private final String releaseTag;
        private JDialog dialog;
        private JLabel status;
        private JLabel bytes;
        private JProgressBar bar;

        ProgressDialog(String title, String assetName, String targetPath, String releaseTag) {
            this.title = title;
            this.assetName = assetName;
            this.targetPath = targetPath;
            this.releaseTag = releaseTag;
        }

        void open() {
            if (dialog != null) {
                return;
            }

            final Color bg = new Color(43, 43, 43);
            final Color fg = new Color(224, 224, 224);
            final Color subtle = new Color(199, 206, 214);

            dialog = new JDialog((Frame) null, title, false);
            dialog.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
            dialog.setResizable(false);

            JPanel root = new JPanel(new BorderLayout(0, 10)) {
                @Override
                protected void paintComponent(Graphics g) {
                    g.setColor(bg);
                    g.fillRect(0, 0, getWidth(), getHeight());
                    super.paintComponent(g);
                }
            };
            root.setOpaque(false);
            root.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
            root.setPreferredSize(new Dimension(560, 220));

            JPanel info = new JPanel();
            info.setLayout(new BoxLayout(info, BoxLayout.Y_AXIS));
            info.setOpaque(true);
            info.setBackground(bg);

            JLabel heading = new JLabel("Downloading the latest Toolscreen release");
            heading.setForeground(fg);
            heading.setFont(new Font("Segoe UI", Font.BOLD, 15));
            heading.setAlignmentX(Component.LEFT_ALIGNMENT);
            info.add(heading);
            info.add(Box.createVerticalStrut(8));

            JLabel asset = new JLabel("GitHub asset: " + assetName + (releaseTag != null ? " (" + releaseTag + ")" : ""));
            asset.setForeground(subtle);
            asset.setFont(new Font("Segoe UI", Font.PLAIN, 12));
            asset.setAlignmentX(Component.LEFT_ALIGNMENT);
            info.add(asset);

            JLabel target = new JLabel("Saving as: " + targetPath);
            target.setForeground(subtle);
            target.setFont(new Font("Consolas", Font.PLAIN, 11));
            target.setAlignmentX(Component.LEFT_ALIGNMENT);
            info.add(target);
            info.add(Box.createVerticalStrut(10));

            status = new JLabel("Preparing download...");
            status.setForeground(fg);
            status.setFont(new Font("Segoe UI", Font.PLAIN, 12));
            status.setAlignmentX(Component.LEFT_ALIGNMENT);
            info.add(status);

            root.add(info, BorderLayout.NORTH);

            bar = new JProgressBar(0, 100);
            bar.setStringPainted(true);
            bar.setValue(0);
            bar.setIndeterminate(true);
            bar.setBackground(new Color(30, 30, 30));
            bar.setForeground(new Color(76, 175, 80));
            bar.setBorder(BorderFactory.createLineBorder(new Color(82, 82, 82)));
            root.add(bar, BorderLayout.CENTER);

            bytes = new JLabel("Waiting for response...");
            bytes.setForeground(subtle);
            bytes.setFont(new Font("Segoe UI", Font.PLAIN, 11));
            root.add(bytes, BorderLayout.SOUTH);

            dialog.setContentPane(root);
            dialog.pack();
            dialog.setLocationRelativeTo(null);
            dialog.setAlwaysOnTop(true);
            dialog.setVisible(true);
        }

        void setStatus(final String value) {
            SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run() {
                    if (status != null) {
                        status.setText(value);
                    }
                }
            });
        }

        void setProgress(final long bytesRead, final long totalBytes, final int pct) {
            SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run() {
                    if (bar == null || bytes == null) {
                        return;
                    }
                    if (pct >= 0) {
                        bar.setIndeterminate(false);
                        bar.setValue(pct);
                        bar.setString(pct + "%");
                    } else {
                        bar.setIndeterminate(true);
                        bar.setString("Working...");
                    }
                    if (totalBytes > 0) {
                        bytes.setText(formatBytes(bytesRead) + " / " + formatBytes(totalBytes));
                    } else {
                        bytes.setText(formatBytes(bytesRead));
                    }
                }
            });
        }

        void close() {
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
        }

        private static String formatBytes(long value) {
            if (value < 0) {
                return "?";
            }
            if (value < 1024) {
                return value + " B";
            }
            if (value < 1024L * 1024L) {
                return String.format("%.1f KB", value / 1024.0);
            }
            if (value < 1024L * 1024L * 1024L) {
                return String.format("%.1f MB", value / (1024.0 * 1024.0));
            }
            return String.format("%.2f GB", value / (1024.0 * 1024.0 * 1024.0));
        }
    }
}