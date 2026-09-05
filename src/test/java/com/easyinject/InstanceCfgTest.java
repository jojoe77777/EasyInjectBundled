package com.easyinject;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class InstanceCfgTest {
    private static final String COMMAND = "\\\"$INST_JAVA\\\" -jar \\\"$INST_DIR/Toolscreen.jar\\\"";
    private static final String PRE = "PreLaunchCommand=" + COMMAND;

    @Test
    void freshInstallWritesToGeneralBeforeTrailingUiSection() {
        List<String> input = Arrays.asList("[General]", "name=1.16.1", "JavaRealArchitecture=aarch64",
            "", "[UI]", "mods_Page\\Columns=layout");
        assertEquals(Arrays.asList("[General]", PRE, "OverrideCommands=true", "name=1.16.1",
            "JavaRealArchitecture=aarch64", "", "[UI]", "mods_Page\\Columns=layout"),
            InstanceCfg.update(input, COMMAND));
    }

    @Test
    void repairsMisplacedAndDuplicateEntriesWithoutChangingOtherSettings() {
        List<String> input = Arrays.asList("[General]", "name=1.16.1", "[UI]", "PreLaunchCommand=old",
            "OverrideCommands=false", "mods_Page\\Columns=layout", "PreLaunchCommand=duplicate", "OverrideCommands=true");
        List<String> expected = Arrays.asList("[General]", PRE, "OverrideCommands=true", "name=1.16.1",
            "[UI]", "mods_Page\\Columns=layout");
        assertEquals("old", InstanceCfg.preLaunchCommand(input));
        assertEquals(expected, InstanceCfg.update(input, COMMAND));
        assertEquals(expected, InstanceCfg.update(expected, COMMAND));
    }

    @Test
    void commandMergePrefersGeneralEvenWhenUiAppearsFirst() {
        List<String> input = Arrays.asList("[UI]", "PreLaunchCommand=stale", "[General]",
            "PreLaunchCommand=echo user-command");
        assertEquals("echo user-command", InstanceCfg.preLaunchCommand(input));
        assertEquals(Arrays.asList("[UI]", "[General]", PRE, "OverrideCommands=true"),
            InstanceCfg.update(input, COMMAND));
        assertEquals("", InstanceCfg.preLaunchCommand(Arrays.asList("[UI]", "PreLaunchCommand=stale",
            "[General]", "PreLaunchCommand=")));
    }

    @Test
    void createsGeneralForSectionlessAndMissingGeneralConfigs() {
        assertEquals(Arrays.asList("[General]", PRE, "OverrideCommands=true", "name=legacy"),
            InstanceCfg.update(Arrays.asList("name=legacy"), COMMAND));
        assertEquals(Arrays.asList("[General]", PRE, "OverrideCommands=true", "[UI]", "layout=saved"),
            InstanceCfg.update(Arrays.asList("[UI]", "layout=saved"), COMMAND));
        assertEquals(Arrays.asList("[General]", PRE, "OverrideCommands=true"),
            InstanceCfg.update(Collections.<String>emptyList(), COMMAND));
        assertEquals("root", InstanceCfg.preLaunchCommand(Arrays.asList("PreLaunchCommand=root", "[UI]")));
    }

    @Test
    void preservesBomCommentsWhitespaceAndUnicodeSettings() {
        List<String> input = Arrays.asList("\uFEFF[General]", "; comment", "name=\u65e5\u672c\u8a9e",
            " PreLaunchCommand =old", " OverrideCommands =false", "[UI]", "layout=saved");
        assertEquals("old", InstanceCfg.preLaunchCommand(input));
        assertEquals(Arrays.asList("\uFEFF[General]", PRE, "OverrideCommands=true", "; comment",
            "name=\u65e5\u672c\u8a9e", "[UI]", "layout=saved"), InstanceCfg.update(input, COMMAND));
        assertEquals(Arrays.asList("\uFEFF[General]", PRE, "OverrideCommands=true", "name=legacy"),
            InstanceCfg.update(Arrays.asList("\uFEFFname=legacy"), COMMAND));
    }

    @Test
    void uninstallClearsBothCorrectAndMisplacedHooksInGeneral() {
        List<String> input = Arrays.asList("[General]", "PreLaunchCommand=current", "[UI]",
            "PreLaunchCommand=stale", "OverrideCommands=true", "layout=saved");
        List<String> expected = Arrays.asList("[General]", "PreLaunchCommand=", "OverrideCommands=true",
            "[UI]", "layout=saved");
        assertEquals(expected, InstanceCfg.update(input, ""));
        assertEquals(expected, InstanceCfg.update(input, null));
        List<String> untouched = Arrays.asList("[General]", "name=other", "[UI]", "layout=saved");
        assertEquals(untouched, InstanceCfg.update(untouched, ""));
        assertNull(InstanceCfg.preLaunchCommand(untouched));
    }
}
