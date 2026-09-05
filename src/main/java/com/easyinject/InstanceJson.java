package com.easyinject;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.Strictness;

final class InstanceJson {
    private static final Gson JSON = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping()
        .serializeNulls().setStrictness(Strictness.STRICT).create();

    static JsonObject parse(String text) {
        JsonElement root = JSON.fromJson(text, JsonElement.class);
        if (root == null || !root.isJsonObject()) throw new IllegalArgumentException("Instance JSON must be an object");
        JsonObject object = root.getAsJsonObject();
        if (object.has("launcher") && !object.get("launcher").isJsonObject()) {
            throw new IllegalArgumentException("Instance JSON launcher must be an object");
        }
        return object;
    }

    static String preLaunchCommand(JsonObject root) {
        if (!root.has("launcher")) return null;
        JsonElement command = root.getAsJsonObject("launcher").get("preLaunchCommand");
        if (command == null || command.isJsonNull()) return null;
        if (!command.isJsonPrimitive() || !command.getAsJsonPrimitive().isString()) {
            throw new IllegalArgumentException("preLaunchCommand must be a string");
        }
        return command.getAsString();
    }

    static String update(JsonObject root, String command) {
        JsonObject result = root.deepCopy();
        boolean installing = command != null && !command.trim().isEmpty();
        if (installing && !result.has("launcher")) result.add("launcher", new JsonObject());
        if (result.has("launcher")) {
            JsonObject launcher = result.getAsJsonObject("launcher");
            if (installing || launcher.has("preLaunchCommand")) {
                launcher.addProperty("preLaunchCommand", command == null ? "" : command);
            }
            // Uninstall must not turn on previously disabled commands.
            if (installing) launcher.addProperty("enableCommands", true);
        }
        return JSON.toJson(result) + System.lineSeparator();
    }
}
