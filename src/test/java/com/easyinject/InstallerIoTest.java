package com.easyinject;

import com.google.gson.JsonObject;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import static org.junit.jupiter.api.Assertions.*;

class InstallerIoTest {
    @TempDir Path temp;

    @Test void compactJsonChangesOnlyLauncherAndRoundTripsCommand() {
        JsonObject root = InstanceJson.parse("{\"preLaunchCommand\":\"outside\",\"other\":{\"enableCommands\":false},\"launcher\":{\"preLaunchCommand\":\"old\",\"memory\":4096},\"name\":\"日本語\"}");
        String command = "\"$INST_JAVA\" -jar \"$INST_DIR/a b.jar\" --prelaunch\\test\nnext";
        JsonObject updated = InstanceJson.parse(InstanceJson.update(root, command));
        assertEquals(command, InstanceJson.preLaunchCommand(updated));
        assertEquals("outside", updated.get("preLaunchCommand").getAsString());
        assertEquals(root.get("other"), updated.get("other"));
        assertEquals(root.get("name"), updated.get("name"));
        assertEquals(4096, updated.getAsJsonObject("launcher").get("memory").getAsInt());
        assertEquals("old", InstanceJson.preLaunchCommand(root));
        assertTrue(updated.getAsJsonObject("launcher").get("enableCommands").getAsBoolean());
        assertEquals(updated, InstanceJson.parse(InstanceJson.update(updated, command)));
    }

    @Test void emptyOrMissingLauncherProducesValidJson() {
        for (String text : Arrays.asList("{}", "{\"launcher\":{}}", "{\"launcher\":{\"preLaunchCommand\":null}}")) {
            JsonObject root = InstanceJson.parse(InstanceJson.update(InstanceJson.parse(text), "hook"));
            assertEquals("hook", InstanceJson.preLaunchCommand(root));
        }
    }

    @Test void uninstallPreservesOtherHooksAndEnableFlag() {
        JsonObject root = InstanceJson.parse("{\"launcher\":{\"enableCommands\":false,\"preLaunchCommand\":\"old\",\"postExitCommand\":\"keep\"}}");
        JsonObject result = InstanceJson.parse(InstanceJson.update(root, ""));
        assertEquals("", InstanceJson.preLaunchCommand(result));
        assertFalse(result.getAsJsonObject("launcher").get("enableCommands").getAsBoolean());
        assertEquals("keep", result.getAsJsonObject("launcher").get("postExitCommand").getAsString());
        assertEquals(InstanceJson.parse("{}"), InstanceJson.parse(InstanceJson.update(InstanceJson.parse("{}"), "")));
    }

    @Test void malformedJsonIsRejected() {
        for (String value : Arrays.asList("[]", "null", "{", "{\"launcher\":null}", "{\"launcher\":[]}", "{\"launcher\":{},}", "{} junk"))
            assertThrows(RuntimeException.class, () -> InstanceJson.parse(value), value);
        assertThrows(RuntimeException.class, () -> InstanceJson.preLaunchCommand(InstanceJson.parse("{\"launcher\":{\"preLaunchCommand\":123}}")));
    }

    @Test void configWritesUnicodeAndLeavesOriginalOnFailure() throws Exception {
        Path path = temp.resolve("配置 with spaces.cfg");
        ConfigFile.writeLines(path, Arrays.asList("[General]", "name=日本語"));
        assertEquals(Arrays.asList("[General]", "name=日本語"), Files.readAllLines(path, StandardCharsets.UTF_8));
        Path directory = temp.resolve("directory.cfg");
        Files.createDirectory(directory);
        Files.write(directory.resolve("sentinel"), new byte[]{1});
        assertThrows(Exception.class, () -> ConfigFile.write(directory, "replacement"));
        assertTrue(Files.exists(directory.resolve("sentinel")));
        try (java.util.stream.Stream<Path> paths = Files.list(temp)) {
            assertEquals(0, paths.filter(p -> p.getFileName().toString().startsWith(".easyinject-")).count());
        }
    }

    @Test @EnabledOnOs(OS.WINDOWS) void processCaptureDrainsPipeAndReturnsExitCode() {
        ProcessCapture.Result result = ProcessCapture.run(new String[]{"cmd.exe", "/d", "/c", "for /L %i in (1,1,5000) do @echo capture-output"}, 30000);
        assertEquals(0, result.exitCode, result.output);
        assertTrue(result.output.length() > 60000);
        assertEquals(7, ProcessCapture.run(new String[]{"cmd.exe", "/d", "/c", "echo failure & exit /b 7"}, 30000).exitCode);
    }

    public static class Sleeper {
        public static void main(String[] args) throws Exception { System.out.println("waiting"); Thread.sleep(30000); }
    }

    @Test @EnabledOnOs(OS.WINDOWS) void processCaptureTimeoutActuallyInterruptsOutputRead() throws Exception {
        long start = System.nanoTime();
        String classes = Paths.get(InstallerIoTest.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        ProcessCapture.Result result = ProcessCapture.run(new String[]{
            Paths.get(System.getProperty("java.home"), "bin", "java.exe").toString(),
            "-cp", classes, Sleeper.class.getName()
        }, 250);
        assertEquals(124, result.exitCode, result.output);
        assertTrue((System.nanoTime() - start) / 1000000 < 8000);
    }

    @Test @EnabledOnOs(OS.WINDOWS) void readOnlyConfigIsPreservedAndTemporaryFileRemoved() throws Exception {
        Path path = temp.resolve("read-only.cfg");
        ConfigFile.write(path, "original");
        Files.setAttribute(path, "dos:readonly", true);
        try {
            assertThrows(Exception.class, () -> ConfigFile.write(path, "replacement"));
            assertEquals("original", new String(Files.readAllBytes(path), StandardCharsets.UTF_8));
            try (java.util.stream.Stream<Path> paths = Files.list(temp)) { assertEquals(1, paths.count()); }
        } finally { Files.setAttribute(path, "dos:readonly", false); }
    }
}
