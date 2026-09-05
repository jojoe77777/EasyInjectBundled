package com.easyinject;

import java.util.ArrayList;
import java.util.List;

/** Section-aware edits for Prism/MultiMC's QSettings INI format. */
final class InstanceCfg {
    private InstanceCfg() {}

    private static String normalized(String line) {
        String text = line.trim();
        return text.startsWith("\uFEFF") ? text.substring(1).trim() : text;
    }

    private static String section(String line) {
        String text = normalized(line);
        return text.startsWith("[") && text.endsWith("]")
            ? text.substring(1, text.length() - 1) : null;
    }

    private static String key(String line) {
        String text = normalized(line);
        int equals = text.indexOf('=');
        return equals < 0 ? "" : text.substring(0, equals).trim();
    }

    static String preLaunchCommand(List<String> lines) {
        String currentSection = "General";
        String misplaced = null;
        for (String line : lines) {
            String header = section(line);
            if (header != null) {
                currentSection = header;
            } else if (key(line).equals("PreLaunchCommand")) {
                String value = line.substring(line.indexOf('=') + 1);
                if (currentSection.equals("General")) return value;
                // Older installers appended these keys to the last section.
                if (misplaced == null) misplaced = value;
            }
        }
        return misplaced;
    }

    static List<String> update(List<String> lines, String command) {
        List<String> updated = new ArrayList<String>();
        int insertion = -1;
        boolean hadPreLaunch = false;
        boolean hadOverride = false;
        for (String line : lines) {
            String name = key(line);
            if (name.equals("PreLaunchCommand")) {
                hadPreLaunch = true;
            } else if (name.equals("OverrideCommands")) {
                hadOverride = true;
            } else {
                updated.add(line);
                if (insertion < 0 && "General".equals(section(line))) {
                    insertion = updated.size();
                }
            }
        }

        boolean installing = command != null && !command.trim().isEmpty();
        if (!installing && !hadPreLaunch && !hadOverride) return updated;
        if (insertion < 0) {
            // A sectionless file's existing keys also belong to General.
            String header = "[General]";
            if (!updated.isEmpty() && updated.get(0).startsWith("\uFEFF")) {
                updated.set(0, updated.get(0).substring(1));
                header = "\uFEFF" + header;
            }
            updated.add(0, header);
            insertion = 1;
        }
        if (installing || hadPreLaunch) {
            updated.add(insertion++, "PreLaunchCommand=" + (command == null ? "" : command));
        }
        if (installing || hadOverride) {
            updated.add(insertion, "OverrideCommands=true");
        }
        return updated;
    }
}
