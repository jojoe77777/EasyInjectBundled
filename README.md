# EasyInjectBundled

EasyInjectBundled packages configured DLLs into complete Java and native Windows installers. Both installers copy themselves to a stable launcher filename, extract DLLs persistently, integrate with supported launchers, start the watcher, inject the DLLs, check for updates, and support uninstall.

## Build prerequisites

- JDK 8 or newer and Maven 3.8 or newer for JARs.
- CMake 3.20 or newer, Visual Studio 2022 with the C++ workload, and a Windows SDK for EXEs.
- PowerShell for packaging inspection tests.

Configure `brand.name`, `brand.version`, and update URLs in `branding.properties`. Universal installers require `liblogger_x64.dll` and `liblogger_arm64.dll` in `src/main/resources/dlls`, plus `Toolscreen_x64.dll` and `Toolscreen_arm64.dll` in `custom-dlls`. Other custom DLL and Vulkan support files also belong in `custom-dlls`.

Both architectures are packaged into each installer. At runtime EasyInject extracts only the payload matching the native injector or JVM architecture, installs the selected Toolscreen payload as `Toolscreen.dll`, and uses its matching `liblogger_<arch>.dll`. Both Windows x86-64 and ARM64 SQLite JNI libraries remain in the JARs for the same reason.

Run the normal full build from a Developer PowerShell or Command Prompt:

```bat
build.bat
```

The equivalent individual commands are:

```powershell
mvn clean package
cmake -S exe -B exe/build -A x64
cmake --build exe/build --config Release --parallel
cmake -S exe -B exe/build-arm64 -A ARM64
cmake --build exe/build-arm64 --config Release --parallel
cmake -S toolscreen-installer-exe -B toolscreen-installer-exe/build -A x64
cmake --build toolscreen-installer-exe/build --config Release --parallel
ctest --test-dir exe/build -C Release --output-on-failure
```

The Maven package lifecycle builds the compatibility installer JAR, the reduced-heuristics installer JAR, and the existing downloader JAR. To build only one JAR module, use `mvn -pl compatibility-variant package` or `mvn -pl :jar_reduced_av_heuristics package`. The existing native target remains `EasyInjectExe`; the additional native target is `installer_exe_reduced_av_heuristics`.

## Installer variants

For brand `Toolscreen` and version `1.5.0`, a full build produces:

- `target/Toolscreen-1.5.0-double-click-me.jar` (existing compatibility JAR)
- `target/Toolscreen-1.5.0-double-click-me-reduced-av-heuristics.jar`
- `target/toolscreen-downloader.jar` (existing compatibility downloader)
- `target/EasyInjectBundled-1.0.jar` and `target/EasyInjectBundled-1.0-toolscreen-downloader.jar` (existing Maven-coordinate outputs)
- `exe/build/Release/Toolscreen-1.5.0-double-click-me.exe` (existing compatibility EXE)
- `exe/build/Release/Toolscreen-1.5.0-double-click-me-reduced-av-heuristics.exe`
- `exe/build-arm64/Release/Toolscreen-1.5.0-double-click-me.exe` (ARM64 compatibility EXE)
- `exe/build-arm64/Release/Toolscreen-1.5.0-double-click-me-reduced-av-heuristics.exe`
- `toolscreen-installer-exe/build/Release/toolscreen-downloader.exe` (existing compatibility downloader)

The compatibility filenames, Maven package behavior, `EasyInjectExe` target, stable installed names (`<brand>.jar` and `<brand>.exe`), configuration locations, file formats, and runtime policy are unchanged.

The reduced-heuristics artifacts are complete installers, not downloaders. They retain DLL/support-resource extraction; the `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread` → `LoadLibraryW` injection sequence; Prism, MultiMC, ATLauncher, MCSRLauncher, and Modrinth integration; prelaunch chaining; watcher startup; updates; prompts and exit semantics; and uninstall. The difference is a compile-time security policy:

- Injection requests only `PROCESS_CREATE_THREAD`, `PROCESS_QUERY_INFORMATION`, `PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, and `PROCESS_VM_READ`.
- Only the exact persistent `<config>/<brand>/dlls` directory can be proposed for a Defender exclusion. The installer JAR/EXE is never excluded.
- The elevated helper validates that exact directory, uses `Add-MpPreference`, verifies the resulting preference, and reports failure.
- Compatibility-only Defender registry mutation, installer-file exclusion, and PowerShell execution-policy bypass code is removed before the reduced Java source is compiled and is excluded by the native compile definition `EASYINJECT_REDUCED_AV_HEURISTICS=1`.

DLL injection remains behavior commonly associated with malware. The reduced policy can lower avoidable heuristic signals, but antivirus detections are still possible and no detection count or clean result is guaranteed.

## Update and downloader selection

Each installer embeds its variant identity. The updater first requests the exact canonical release name for its own variant and remote version, then uses the legacy `update.assetNameRegex`, stable filename, and extension fallbacks. Selection therefore does not depend on GitHub asset order. Branding files without a variant property remain compatibility builds, and releases containing only the historical compatibility asset continue to work through the fallback.

The Java and native downloader artifacts are compatibility downloaders. They prefer the exact compatibility release filename before broad fallback and are not duplicated for the reduced variant.

## Tests and artifact inspection

Run Java regression tests for both compile-time policies with:

```powershell
mvn clean test
```

After packaging and native compilation, run:

```powershell
powershell -NoProfile -ExecutionPolicy RemoteSigned -File tests/verify-packaging.ps1 `
  -RepositoryRoot . `
  -CompatibilityExe exe/build/Release/Toolscreen-1.5.0-double-click-me.exe `
  -ReducedExe exe/build/Release/Toolscreen-1.5.0-double-click-me-reduced-av-heuristics.exe
ctest --test-dir exe/build -C Release --output-on-failure
```

The inspection verifies names, manifests, embedded DLL/support resources, exact variant selection policy, EXE metadata parity, required injection APIs, and absence of compatibility-owned `PROCESS_ALL_ACCESS`, registry-mutation, installer-exclusion, and execution-policy-bypass code. JNA itself defines a general-purpose `PROCESS_ALL_ACCESS` constant in its third-party `WinNT` API class; EasyInject-owned reduced classes neither declare nor use it.

## Downstream signing and publishing

The reduced artifacts use the same ordinary JAR/PE formats, branding resource, icon, and metadata as their compatibility counterparts and can be passed to the existing SignPath workflow without repackaging. The downstream ToolScreen workflow must add two explicit inputs/output records using the canonical reduced filenames, sign the reduced JAR and EXE with the same policies as the existing artifacts, verify the signed outputs retain those exact names and embedded resources, and publish all compatibility and reduced artifacts together. Release/update matching must use exact names rather than a first-match wildcard. Unsigned local builds should not be uploaded to VirusTotal; compare detections only after downstream signing.

## Launcher setup

For manual MultiMC/Prism setup, set the pre-launch command in **Settings → Custom Commands**:

```text
$INST_JAVA -jar EasyInjectBundled-1.0.jar
```

For Modrinth, place an installer in the instance profile folder and double-click it. The installer writes the pre-launch hook into that profile's `app.db`.
