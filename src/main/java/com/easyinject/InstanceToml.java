package com.easyinject;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Edits for Waymark's instance.toml. Waymark keeps each instance's settings there, with the
 * game in a "game" folder beside it and a waymark.lock next to both. It runs the top-level
 * preLaunch command from the game folder through cmd, with the same INST_* environment
 * variables as Prism, so only that one key is ever touched here.
 */
final class InstanceToml {
    private InstanceToml() {}

    private static final String BOM = String.valueOf((char) 0xFEFF);

    /** Where the top-level keys end: the preLaunch line, if any, and the first [table] header. */
    static final class Layout {
        final int preLaunch;
        final int firstTable;

        Layout(int preLaunch, int firstTable) {
            this.preLaunch = preLaunch;
            this.firstTable = firstTable;
        }
    }

    /** The instance.toml for a Waymark game folder, or null for anything else. */
    static File waymarkFile(File gameDir) {
        if (gameDir == null || !gameDir.getName().equalsIgnoreCase("game")) return null;
        File root = gameDir.getAbsoluteFile().getParentFile();
        if (root == null) return null;
        File toml = new File(root, "instance.toml");
        return toml.isFile() && new File(root, "waymark.lock").isFile() ? toml : null;
    }

    /**
     * Arrays can span lines, and a line inside one may start with "[", so brackets and
     * strings are followed rather than guessed.
     */
    static Layout layout(List<String> lines) {
        int preLaunch = -1;
        int depth = 0;
        int state = 0; // 0 plain, 1 inside """, 2 inside '''
        for (int index = 0; index < lines.size(); index++) {
            String line = lines.get(index);
            if (index == 0 && line.startsWith(BOM)) line = line.substring(1);
            String text = line.trim();
            if (state == 0 && depth == 0) {
                if (text.startsWith("[")) return new Layout(preLaunch, index);
                int equals = text.indexOf('=');
                if (equals >= 0 && preLaunch < 0 && text.substring(0, equals).trim().equals("preLaunch")) {
                    preLaunch = index;
                }
            }
            for (int i = 0; i < line.length(); i++) {
                char c = line.charAt(i);
                if (state == 1) {
                    if (c == '\\') i++;
                    else if (line.startsWith("\"\"\"", i)) { state = 0; i += 2; }
                } else if (state == 2) {
                    if (line.startsWith("'''", i)) { state = 0; i += 2; }
                } else if (c == '#') {
                    break;
                } else if (line.startsWith("\"\"\"", i)) {
                    state = 1;
                    i += 2;
                } else if (line.startsWith("'''", i)) {
                    state = 2;
                    i += 2;
                } else if (c == '"') {
                    for (i++; i < line.length() && line.charAt(i) != '"'; i++) {
                        if (line.charAt(i) == '\\') i++;
                    }
                } else if (c == '\'') {
                    i = line.indexOf('\'', i + 1);
                    if (i < 0) break;
                } else if (c == '[' || c == '{') {
                    depth++;
                } else if ((c == ']' || c == '}') && depth > 0) {
                    depth--;
                }
            }
        }
        return new Layout(preLaunch, lines.size());
    }

    /** The value of a one-line TOML string, with any comment after it ignored. */
    static String decode(String raw) {
        String value = raw.trim();
        if (value.startsWith("\"\"\"") || value.startsWith("'''")) {
            throw new IllegalArgumentException(
                "This instance's pre-launch command spans several lines. Change it in Waymark first.");
        }
        if (value.startsWith("'")) {
            int end = value.indexOf('\'', 1);
            if (end < 0) throw new IllegalArgumentException("Unclosed preLaunch string in instance.toml");
            return value.substring(1, end);
        }
        if (!value.startsWith("\"")) throw new IllegalArgumentException("preLaunch in instance.toml is not a string");
        StringBuilder out = new StringBuilder();
        for (int i = 1; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '"') return out.toString();
            if (c != '\\') {
                out.append(c);
                continue;
            }
            if (++i == value.length()) break;
            char escape = value.charAt(i);
            switch (escape) {
                case 'b': out.append('\b'); break;
                case 't': out.append('\t'); break;
                case 'n': out.append('\n'); break;
                case 'f': out.append('\f'); break;
                case 'r': out.append('\r'); break;
                case '"': out.append('"'); break;
                case '\\': out.append('\\'); break;
                case 'u':
                case 'U': {
                    int digits = escape == 'u' ? 4 : 8;
                    if (i + digits >= value.length()) throw new IllegalArgumentException("Invalid escape in preLaunch");
                    out.appendCodePoint(Integer.parseInt(value.substring(i + 1, i + 1 + digits), 16));
                    i += digits;
                    break;
                }
                default:
                    throw new IllegalArgumentException("Invalid escape in preLaunch");
            }
        }
        throw new IllegalArgumentException("Unclosed preLaunch string in instance.toml");
    }

    static String encode(String command) {
        StringBuilder out = new StringBuilder("\"");
        for (int i = 0; i < command.length(); i++) {
            char c = command.charAt(i);
            switch (c) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\b': out.append("\\b"); break;
                case '\t': out.append("\\t"); break;
                case '\n': out.append("\\n"); break;
                case '\f': out.append("\\f"); break;
                case '\r': out.append("\\r"); break;
                default:
                    if (c < 0x20 || c == 0x7F) out.append(String.format("\\u%04X", (int) c));
                    else out.append(c);
            }
        }
        return out.append('"').toString();
    }

    /** The current command, or null when the instance has none. */
    static String preLaunchCommand(List<String> lines) {
        Layout found = layout(lines);
        if (found.preLaunch < 0) return null;
        String line = lines.get(found.preLaunch);
        return decode(line.substring(line.indexOf('=') + 1));
    }

    /** Sets the top-level preLaunch, or removes it when the command is empty. Nothing else changes. */
    static List<String> update(List<String> lines, String command) {
        Layout found = layout(lines);
        List<String> updated = new ArrayList<String>(lines);
        boolean installing = command != null && !command.trim().isEmpty();
        String entry = "preLaunch = " + encode(installing ? command : "");
        // A byte order mark has to stay at the very start of the file.
        boolean marked = !updated.isEmpty() && updated.get(0).startsWith(BOM);
        if (marked) updated.set(0, updated.get(0).substring(1));
        if (found.preLaunch >= 0) {
            if (installing) updated.set(found.preLaunch, entry);
            else updated.remove(found.preLaunch);
        } else if (installing) {
            // Waymark leaves a blank line before its first table, so the key goes above it.
            int at = found.firstTable;
            while (at > 0 && updated.get(at - 1).trim().isEmpty()) at--;
            updated.add(at, entry);
        }
        if (marked) {
            if (updated.isEmpty()) updated.add("");
            updated.set(0, BOM + updated.get(0));
        }
        return updated;
    }

    /** Prism's escaped form, which the shared merge helpers read and write. */
    static String toIni(String command) {
        if (command == null) return null;
        return command.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    static String fromIni(String command) {
        if (command == null) return null;
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < command.length(); i++) {
            char c = command.charAt(i);
            if (c == '\\' && i + 1 < command.length()
                && (command.charAt(i + 1) == '\\' || command.charAt(i + 1) == '"')) {
                c = command.charAt(++i);
            }
            out.append(c);
        }
        return out.toString();
    }
}
