# Installer regression checks

Run the Java tests for both packaging variants from the repository root:

```powershell
mvn --batch-mode --no-transfer-progress test
```

Build and run the standalone native tests without needing bundled DLLs:

```powershell
cmake -S tests -B target/installer-tests -G "Visual Studio 17 2022" -A x64
cmake --build target/installer-tests --config Release
ctest --test-dir target/installer-tests -C Release --output-on-failure
```

For native ARM64 validation, configure a separate build directory with `-A ARM64`
and run all generated test EXEs on ARM64 Windows. Cross-compilation alone does
not test the Windows file and process APIs on the target architecture.

Coverage includes INI section placement and repair, compact/empty/malformed
ATLauncher JSON, unrelated settings, reinstall and uninstall, Unicode paths,
read-only files, failed atomic replacements, temporary-file cleanup, large
subprocess output, exit codes, and real subprocess timeouts. Windows-specific
Java I/O/process tests are skipped on other operating systems.

Native dialog tests use the actual installer UI on a separate, invisible desktop.
They close two consecutive dialogs with cross-thread Windows button messages and
fail with a bounded timeout if the modal message loop hangs.

The launcher parity suite uses real SQLite databases, including both Modrinth
schemas, JSONB overrides, WAL mode, custom and Unicode paths, a held writer lock,
missing profiles, malformed overrides, and foreign hooks. It verifies rollback
and preservation of unrelated settings during install, reinstall, and uninstall.

The three native frontend suites compile the actual compatibility, reduced, and
lite installer code. They exercise keep/replace/cancel and Modrinth install/uninstall
dialogs on private desktops, and start real child processes to verify quoting,
launcher-variable forwarding, command order, and failure handling. These local
tests do not claim to replace a live launcher/game test on ARM64.

After packaging, run `verify-packaging.ps1` against the compatibility and reduced
JARs/EXEs. Installer GUI validation should also use a backed-up instance: install,
reinstall, cancel replacement of an existing external command, uninstall, and
launch through Prism. Verify fresh watcher, injector, Minecraft, and native
payload logs separately; an installer success dialog or successful DLL injection
alone does not establish that the payload initialized or rendered correctly.

Include a cold Minecraft launch that takes longer than 60 seconds to create its
window. With REQUIRE_WINDOW_BEFORE_INJECTION enabled, watchers must wait for a window
owned by the matching leaf JVM before injection, within the existing 120-second
timeout. Set the hardcoded boolean to false to restore early injection.
