package com.easyinject;

/**
 * Fabric Mod Initializer - this class is called when Fabric tries to load this JAR as a mod.
 * 
 * This JAR is NOT a Fabric mod! It's a DLL injector that should be run via MultiMC's
 * pre-launch command, not placed in the mods folder.
 * 
 * This class implements the Fabric ModInitializer interface without actually depending
 * on Fabric (the interface is simple enough to replicate). When Fabric tries to load
 * this "mod", it will throw a RuntimeException with a clear error message.
 */
public class FabricModError implements net.fabricmc.api.ModInitializer {
    
    @Override
    public void onInitialize() {
        String brandName = "EasyInjectBundled";
        try {
            java.io.InputStream is = getClass().getResourceAsStream("/branding.properties");
            if (is != null) {
                java.util.Properties props = new java.util.Properties();
                props.load(is);
                is.close();
                String name = props.getProperty("brand.name");
                if (name != null && !name.isEmpty()) {
                    brandName = name;
                }
            }
        } catch (Exception e) {
            // ignore
        }

        String errorMessage = 
            "\n\n" +
            "=======================================================================\n" +
            "  CRITICAL ERROR: THIS IS NOT A FABRIC MOD!\n" +
            "=======================================================================\n\n" +
            "  " + brandName + " is a DLL injection, NOT a Minecraft mod.\n\n" +
            "  DO NOT put this JAR in your mods folder!\n\n" +
            "  Move the JAR to your MultiMC instance folder and double click it to install.\n" +
            "=======================================================================\n\n";
        
        throw new RuntimeException(errorMessage);
    }
}
