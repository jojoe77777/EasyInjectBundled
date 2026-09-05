package com.easyinject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

final class ProcessCapture {
    static final class Result {
        final int exitCode;
        final String output;
        Result(int exitCode, String output) { this.exitCode = exitCode; this.output = output; }
    }

    static Result run(String[] command, long timeoutMs) {
        Process process = null;
        try {
            process = new ProcessBuilder(command).redirectErrorStream(true).start();
            process.getOutputStream().close(); // These helper commands are non-interactive.
            final InputStream input = process.getInputStream();
            final ByteArrayOutputStream output = new ByteArrayOutputStream();
            Thread reader = new Thread(() -> {
                byte[] buffer = new byte[4096];
                try {
                    int n;
                    while ((n = input.read(buffer)) >= 0) {
                        synchronized (output) {
                            // Drain even after the cap so the child cannot block on a full pipe.
                            int keep = Math.min(n, Math.max(0, 1024 * 1024 - output.size()));
                            output.write(buffer, 0, keep);
                        }
                    }
                } catch (java.io.IOException ignored) {
                } finally {
                    try { input.close(); } catch (java.io.IOException ignored) {}
                }
            }, "EasyInject-process-output");
            reader.setDaemon(true);
            reader.start();
            boolean finished = process.waitFor(timeoutMs, TimeUnit.MILLISECONDS);
            if (!finished) {
                process.destroyForcibly();
                process.waitFor(1000, TimeUnit.MILLISECONDS);
            }
            reader.join(1000);
            synchronized (output) {
                return new Result(finished ? process.exitValue() : 124,
                    new String(output.toByteArray(), StandardCharsets.UTF_8)
                    + (finished ? "" : "\nProcess timed out after " + timeoutMs + " ms"));
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new Result(1, "Interrupted while waiting for process");
        } catch (Exception e) {
            return new Result(1, e.toString());
        } finally {
            if (process != null && process.isAlive()) process.destroyForcibly();
        }
    }
}
