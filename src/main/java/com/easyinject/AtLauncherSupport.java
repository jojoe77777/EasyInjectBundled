package com.easyinject;

import java.util.List;

final class AtLauncherSupport {

    private static final java.util.regex.Pattern AT_LAUNCHER_MAIN_CLASS =
        java.util.regex.Pattern.compile("(?:^|[\\s=])com\\.atlauncher\\.App(?:$|\\s)");

    private AtLauncherSupport() {}

    static boolean isRunning() {
        try {
            List<ProcessUtils.ProcessInfo> javaProcs = ProcessUtils.findProcessesByImageNames(
                "javaw.exe",
                "java.exe"
            );
            for (ProcessUtils.ProcessInfo proc : javaProcs) {
                String cmd = ProcessUtils.getProcessCommandLine(proc.processId);
                if (cmd != null && AT_LAUNCHER_MAIN_CLASS.matcher(cmd).find()) {
                    return true;
                }
            }
        } catch (Exception e) {
            // Best-effort capture only.
            System.err.println("AtLauncherSupport.isRunning: process enumeration failed: " + e);
        }
        return false;
    }

    static boolean ensureClosedInteractive() {
        while (isRunning()) {
            if (promptCloseDialog() != javax.swing.JOptionPane.OK_OPTION) {
                return false;
            }
        }
        return true;
    }

    private static int promptCloseDialog() {
        try {
            Main.applyDarkTheme();

            javax.swing.JPanel panel = new javax.swing.JPanel();
            panel.setLayout(new javax.swing.BoxLayout(panel, javax.swing.BoxLayout.Y_AXIS));
            panel.setBorder(javax.swing.BorderFactory.createEmptyBorder(6, 2, 2, 2));
            panel.setBackground(new java.awt.Color(43, 43, 43));

            javax.swing.JLabel header = new javax.swing.JLabel("ATLauncher Is Running");
            header.setForeground(new java.awt.Color(255, 167, 38));
            header.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, 14));
            header.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);

            javax.swing.JLabel subtext = new javax.swing.JLabel(
                "<html><body style='color:#ccc; text-align:left;'>"
                    + "ATLauncher must be closed before this instance config can be edited.<br/><br/>"
                    + "Close ATLauncher, then click <b>Install</b>."
                    + "</body></html>");
            subtext.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);

            panel.add(header);
            panel.add(javax.swing.Box.createVerticalStrut(8));
            panel.add(subtext);

            Object[] options = new Object[] { "Install", "Cancel" };

            return javax.swing.JOptionPane.showOptionDialog(
                null,
                panel,
                "ATLauncher Running",
                javax.swing.JOptionPane.OK_CANCEL_OPTION,
                javax.swing.JOptionPane.PLAIN_MESSAGE,
                null,
                options,
                options[0]
            );
        } catch (Exception e) {
            System.out.println("ATLauncher is running. Close it, then re-run the installer.");
            return javax.swing.JOptionPane.CANCEL_OPTION;
        }
    }
}
