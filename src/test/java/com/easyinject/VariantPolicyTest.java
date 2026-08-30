package com.easyinject;

import org.junit.jupiter.api.Test;

import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VariantPolicyTest {
    @Test
    void universalPayloadSelectionUsesTheRuntimeArchitecture() {
        assertEquals("arm64", Main.payloadArchitectureFor("aarch64"));
        assertEquals("arm64", Main.payloadArchitectureFor("ARM64"));
        assertEquals("x64", Main.payloadArchitectureFor("amd64"));
        assertEquals("x64", Main.payloadArchitectureFor("x86_64"));

        assertTrue(Main.isPayloadForArchitecture("Toolscreen_arm64.dll", "arm64"));
        assertTrue(Main.isPayloadForArchitecture("liblogger_x64.dll", "x64"));
        assertTrue(Main.isPayloadForArchitecture("VK_LAYER_TOOLSCREEN_obs_redirect.json", "arm64"));
        assertFalse(Main.isPayloadForArchitecture("Toolscreen_x64.dll", "arm64"));
        assertFalse(Main.isPayloadForArchitecture("liblogger_arm64.dll", "x64"));
        assertEquals("Toolscreen.dll", Main.installedPayloadName("Toolscreen_x64.dll"));
        assertEquals("Toolscreen.dll", Main.installedPayloadName("toolscreen_ARM64.dll"));
    }

    @Test
    void buildVariantAndInjectionRightsMatchPackagedPolicy() {
        // <compatibility-policy>
        assertEquals(BuildVariant.COMPATIBILITY, BuildVariant.id());
        assertEquals(0x1F0FFF, InjectionAccessPolicy.requiredProcessAccess());
        // </compatibility-policy>
        // <reduced-policy>
//|        assertEquals(BuildVariant.REDUCED_AV_HEURISTICS, BuildVariant.id());
//|        int expected = WindowsNative.PROCESS_CREATE_THREAD
//|            | WindowsNative.PROCESS_QUERY_INFORMATION
//|            | WindowsNative.PROCESS_VM_OPERATION
//|            | WindowsNative.PROCESS_VM_WRITE
//|            | WindowsNative.PROCESS_VM_READ;
//|        assertEquals(expected, InjectionAccessPolicy.requiredProcessAccess());
        // </reduced-policy>
    }

    @Test
    void updaterChoosesExactVariantBeforeBroadRegexRegardlessOfOrdering() {
        Properties properties = new Properties();
        properties.setProperty("brand.name", "Toolscreen");
        String expected = BuildVariant.canonicalJarAssetName(properties, "1.5.0");
        String compatibility = "Toolscreen-1.5.0-double-click-me.jar";
        String reduced = "Toolscreen-1.5.0-double-click-me-reduced-av-heuristics.jar";
        String json = "[{\"name\":\"" + (BuildVariant.isReducedAvHeuristics() ? compatibility : reduced)
            + "\",\"browser_download_url\":\"https://example.invalid/first\",\"size\":1},"
            + "{\"name\":\"" + expected + "\",\"browser_download_url\":\"https://example.invalid/exact\",\"size\":1}]";
        assertEquals(expected, Updater.chooseAssetNameForTest(json, expected, ".*\\.jar$", "Toolscreen.jar"));
    }

    @Test
    void compatibilityFallbackStillAcceptsLegacySingleJarRelease() {
        String json = "[{\"name\":\"legacy-name.jar\",\"browser_download_url\":\"https://example.invalid/legacy\",\"size\":1}]";
        // <compatibility-policy>
        assertEquals("legacy-name.jar", Updater.chooseAssetNameForTest(json, "missing.jar", ".*\\.jar$", "Toolscreen.jar"));
        // </compatibility-policy>
        // <reduced-policy>
//|        assertEquals(null, Updater.chooseAssetNameForTest(json, "missing.jar", ".*\\.jar$", "Toolscreen.jar"));
        // </reduced-policy>
        assertTrue(BuildVariant.id().length() > 0);
    }
}
