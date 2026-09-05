package com.easyinject;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;

final class ConfigFile {
    static void writeLines(Path path, List<String> lines) throws IOException {
        StringBuilder text = new StringBuilder();
        for (String line : lines) text.append(line).append(System.lineSeparator());
        write(path, text.toString());
    }

    static void write(Path path, String text) throws IOException {
        Path temporary = Files.createTempFile(path.toAbsolutePath().getParent(), ".easyinject-", ".tmp");
        try {
            Files.write(temporary, text.getBytes(StandardCharsets.UTF_8));
            try {
                Files.move(temporary, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temporary, path, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temporary);
        }
    }
}
