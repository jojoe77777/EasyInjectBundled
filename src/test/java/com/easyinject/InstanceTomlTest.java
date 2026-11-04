package com.easyinject;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class InstanceTomlTest {
    private static final String COMMAND = "\"$INST_JAVA\" -jar \"$INST_MC_DIR/Toolscreen.jar\" --prelaunch";
    private static final String ENTRY = "preLaunch = \"\\\"$INST_JAVA\\\" -jar \\\"$INST_MC_DIR/Toolscreen.jar\\\" --prelaunch\"";

    // As Waymark writes it: plain keys, an array over several lines, a blank line, then tables.
    private static final List<String> WAYMARK = Arrays.asList("id = \"speedrun\"", "name = \"1.16.1 RSG\"",
        "env = [[", "    \"A\",", "    \"b\",", "]]", "", "[loader]", "kind = \"fabric\"");
    private static final List<String> INSTALLED = Arrays.asList("id = \"speedrun\"", "name = \"1.16.1 RSG\"",
        "env = [[", "    \"A\",", "    \"b\",", "]]", ENTRY, "", "[loader]", "kind = \"fabric\"");

    @Test
    void installsAboveTheFirstTableAndUninstallsCleanly() {
        assertEquals(INSTALLED, InstanceToml.update(WAYMARK, COMMAND));
        assertEquals(INSTALLED, InstanceToml.update(INSTALLED, COMMAND));
        assertEquals(COMMAND, InstanceToml.preLaunchCommand(INSTALLED));
        assertEquals(WAYMARK, InstanceToml.update(INSTALLED, ""));
        assertEquals(WAYMARK, InstanceToml.update(WAYMARK, ""));
        assertNull(InstanceToml.preLaunchCommand(WAYMARK));
    }

    @Test
    void linesInsideArraysAreNotTables() {
        List<String> nested = Arrays.asList("env = [", "    [", "    \"A\",", "    \"b\",", "],", "]", "", "[loader]");
        assertEquals(7, InstanceToml.layout(nested).firstTable);
        assertEquals(Arrays.asList("env = [", "    [", "    \"A\",", "    \"b\",", "],", "]", ENTRY, "", "[loader]"),
            InstanceToml.update(nested, COMMAND));
        List<String> tricky = Arrays.asList("name = \"[a] ]] # not a comment\"", "jvmArgs = ['[', \"]\"]", "[loader]");
        assertEquals(Arrays.asList("name = \"[a] ]] # not a comment\"", "jvmArgs = ['[', \"]\"]", ENTRY, "[loader]"),
            InstanceToml.update(tricky, COMMAND));
    }

    @Test
    void readsWhateverWaymarkSaved() {
        List<String> literal = Arrays.asList("preLaunch = '\"C:\\Tools\\obs.exe\" --minimize' # mine", "", "[loader]");
        assertEquals("\"C:\\Tools\\obs.exe\" --minimize", InstanceToml.preLaunchCommand(literal));
        assertEquals(Arrays.asList(ENTRY, "", "[loader]"), InstanceToml.update(literal, COMMAND));
        assertEquals("a\\b \"c\" \u00e9",
            InstanceToml.preLaunchCommand(Collections.singletonList("preLaunch = \"a\\\\b \\\"c\\\" \\u00e9\"")));
        assertEquals("x\ty", InstanceToml.preLaunchCommand(InstanceToml.update(Collections.<String>emptyList(), "x\ty")));
        assertThrows(IllegalArgumentException.class,
            () -> InstanceToml.preLaunchCommand(Arrays.asList("preLaunch = \"\"\"", "a", "\"\"\"")));
        assertThrows(IllegalArgumentException.class,
            () -> InstanceToml.preLaunchCommand(Collections.singletonList("preLaunch = 3")));
    }

    @Test
    void onlyTouchesTheTopLevelKey() {
        List<String> tabled = Arrays.asList("name = \"x\"", "", "[other]", "preLaunch = \"not ours\"");
        assertNull(InstanceToml.preLaunchCommand(tabled));
        assertEquals(Arrays.asList("name = \"x\"", ENTRY, "", "[other]", "preLaunch = \"not ours\""),
            InstanceToml.update(tabled, COMMAND));
        assertEquals(Arrays.asList("name = \"x\"", ENTRY, ""), InstanceToml.update(Arrays.asList("name = \"x\"", ""), COMMAND));
        assertEquals(Collections.singletonList(ENTRY), InstanceToml.update(Collections.<String>emptyList(), COMMAND));
        assertEquals(Arrays.asList("\uFEFF" + ENTRY, "[loader]"),
            InstanceToml.update(Collections.singletonList("\uFEFF[loader]"), COMMAND));
    }

    @Test
    void prismEscapingRoundTrips() {
        String command = "\"C:\\My Tools\\a.exe\" \"x \\\" y\"";
        assertEquals(command, InstanceToml.fromIni(InstanceToml.toIni(command)));
        assertEquals("\\\"$INST_JAVA\\\" -jar", InstanceToml.toIni("\"$INST_JAVA\" -jar"));
    }

    @Test
    void recognisesOnlyAWaymarkGameFolder() throws IOException {
        Path root = Files.createTempDirectory("easyinject waymark ");
        try {
            File game = root.resolve("game").toFile();
            assertEquals(true, game.mkdir());
            assertNull(InstanceToml.waymarkFile(game));
            Files.write(root.resolve("instance.toml"), "id = \"x\"\n".getBytes("UTF-8"));
            assertNull(InstanceToml.waymarkFile(game));
            Files.write(root.resolve("waymark.lock"), new byte[0]);
            assertEquals(root.resolve("instance.toml").toFile().getAbsoluteFile(), InstanceToml.waymarkFile(game));
            assertNull(InstanceToml.waymarkFile(root.toFile()));
        } finally {
            for (String name : new String[] {"game", "instance.toml", "waymark.lock"}) {
                Files.deleteIfExists(root.resolve(name));
            }
            Files.deleteIfExists(root);
        }
    }
}
