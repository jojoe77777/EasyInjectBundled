package com.easyinject;

import java.util.Properties;

/** Build-time variant identity used by update asset selection. */
final class BuildVariant {
    static final String COMPATIBILITY = "compatibility";
    static final String REDUCED_AV_HEURISTICS = "reduced-av-heuristics";

    private BuildVariant() {
    }

    static String id() {
        // <compatibility-policy>
        return COMPATIBILITY;
        // </compatibility-policy>
        // <reduced-policy>
//|        return REDUCED_AV_HEURISTICS;
        // </reduced-policy>
    }

    static boolean isReducedAvHeuristics() {
        return REDUCED_AV_HEURISTICS.equals(id());
    }

    static String canonicalJarAssetName(Properties properties, String version) {
        return canonicalAssetName(properties, version, ".jar");
    }

    static boolean acceptsJarAssetName(String name) {
        if (name == null || !name.toLowerCase().endsWith(".jar")) return false;
        return !isReducedAvHeuristics() || name.toLowerCase().endsWith("-reduced-av-heuristics.jar");
    }

    private static String canonicalAssetName(Properties properties, String version, String extension) {
        String brand = properties != null ? properties.getProperty("brand.name") : null;
        if (brand == null || brand.trim().isEmpty() || version == null || version.trim().isEmpty()) {
            return null;
        }
        String suffix = isReducedAvHeuristics() ? "-reduced-av-heuristics" : "";
        return brand.trim() + "-" + version.trim() + "-double-click-me" + suffix + extension;
    }
}
