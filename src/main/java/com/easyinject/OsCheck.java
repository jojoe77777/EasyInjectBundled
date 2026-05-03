package com.easyinject;

final class OsCheck {

    private static final String DISCORD_URL = "https://discord.gg/A2v6bCJg6K";

    private OsCheck() {}

    static boolean isWindows() {
        String os = System.getProperty("os.name");
        return os != null && os.toLowerCase().startsWith("windows");
    }

    static void requireWindowsOrExit(String appName) {
        if (isWindows()) {
            return;
        }
        showUnsupportedOsDialog(appName);
        System.exit(1);
    }

    private static void showUnsupportedOsDialog(String appName) {
        try {
            Main.applyDarkTheme();

            javax.swing.JPanel panel = new javax.swing.JPanel();
            panel.setLayout(new javax.swing.BoxLayout(panel, javax.swing.BoxLayout.Y_AXIS));
            panel.setBorder(javax.swing.BorderFactory.createEmptyBorder(6, 2, 2, 2));
            panel.setBackground(new java.awt.Color(43, 43, 43));

            javax.swing.JLabel header = new javax.swing.JLabel(appName + " is Windows-only");
            header.setForeground(new java.awt.Color(255, 167, 38));
            header.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, 14));
            header.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);

            javax.swing.JLabel subtext = new javax.swing.JLabel(
                "<html><body style='color:#ccc; text-align:left;'>"
                    + appName + " currently only supports Windows."
                    + "</body></html>");
            subtext.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);

            panel.add(header);
            panel.add(javax.swing.Box.createVerticalStrut(8));
            panel.add(subtext);

            Object[] options = new Object[] { "Join Discord", "Close" };

            int choice = javax.swing.JOptionPane.showOptionDialog(
                null,
                panel,
                appName + " - Unsupported OS",
                javax.swing.JOptionPane.DEFAULT_OPTION,
                javax.swing.JOptionPane.PLAIN_MESSAGE,
                null,
                options,
                options[0]
            );

            if (choice == 0) {
                openDiscord();
            }
        } catch (Exception e) {
            // Best-effort capture only.
            System.err.println(appName + " is Windows-only. Join the Discord: " + DISCORD_URL);
        }
    }

    private static void openDiscord() {
        try {
            if (java.awt.Desktop.isDesktopSupported()) {
                java.awt.Desktop.getDesktop().browse(new java.net.URI(DISCORD_URL));
            }
        } catch (Exception e) {
            // Best-effort capture only.
            System.err.println("Could not open browser. Discord: " + DISCORD_URL);
        }
    }
}
