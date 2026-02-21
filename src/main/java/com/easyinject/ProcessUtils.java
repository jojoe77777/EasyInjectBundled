package com.easyinject;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.*;
import com.sun.jna.ptr.IntByReference;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utility class for Windows process discovery and inspection.
 */
public class ProcessUtils {

    private static final Kernel32 kernel32 = Kernel32.INSTANCE;
    private static final WindowsNative.Kernel32Ex kernel32Ex = WindowsNative.Kernel32Ex.INSTANCE;
    private static final WindowsNative.User32Ex user32 = WindowsNative.User32Ex.INSTANCE;

    // Debug logging for window enumeration/title reads.
    // Enabled by default (opt-out) because diagnosing window detection issues is otherwise painful.
    // Disable with: -Deasyinject.debug.windows=false or environment EASYINJECT_DEBUG_WINDOWS=0
    private static final boolean DEBUG_WINDOWS = isWindowsDebugEnabled();

    private static boolean isWindowsDebugEnabled() {
        String prop = null;
        try {
            prop = System.getProperty("easyinject.debug.windows");
        } catch (Throwable ignored) {
            // ignore
        }
        if (prop != null) {
            String p = prop.trim();
            if (p.equalsIgnoreCase("false") || p.equals("0") || p.equalsIgnoreCase("off") || p.equalsIgnoreCase("no")) {
                return false;
            }
            if (p.equalsIgnoreCase("true") || p.equals("1") || p.equalsIgnoreCase("on") || p.equalsIgnoreCase("yes")) {
                return true;
            }
        }

        String env = null;
        try {
            env = System.getenv("EASYINJECT_DEBUG_WINDOWS");
        } catch (Throwable ignored) {
            // ignore
        }
        if (env != null) {
            String e = env.trim();
            if (e.equalsIgnoreCase("false") || e.equals("0") || e.equalsIgnoreCase("off") || e.equalsIgnoreCase("no")) {
                return false;
            }
            if (e.equalsIgnoreCase("true") || e.equals("1") || e.equalsIgnoreCase("on") || e.equalsIgnoreCase("yes")) {
                return true;
            }
        }

        return true; // default ON
    }

    private static void debugWindows(String msg) {
        if (DEBUG_WINDOWS) {
            System.out.println("[ProcessUtils][Windows] " + msg);
        }
    }

    private static void debugWindowsError(String msg) {
        if (DEBUG_WINDOWS) {
            int err = 0;
            try {
                err = kernel32.GetLastError();
            } catch (Throwable ignored) {
                // ignore
            }
            System.out.println("[ProcessUtils][Windows] " + msg + " (GetLastError=" + err + ")");
        }
    }

    /**
     * Process info container.
     */
    public static class ProcessInfo {
        public final int processId;
        public final String exeName;

        public ProcessInfo(int processId, String exeName) {
            this.processId = processId;
            this.exeName = exeName;
        }
    }

    /**
     * Find all Java processes (java.exe or javaw.exe).
     */
    public static List<ProcessInfo> findJavaProcesses() {
        List<ProcessInfo> javaProcesses = new ArrayList<ProcessInfo>();

        HANDLE snapshot = kernel32Ex.CreateToolhelp32Snapshot(WindowsNative.TH32CS_SNAPPROCESS, 0);
        if (snapshot == null || snapshot.equals(INVALID_HANDLE_VALUE)) {
            return javaProcesses;
        }

        try {
            WindowsNative.PROCESSENTRY32.ByReference pe32 = new WindowsNative.PROCESSENTRY32.ByReference();

            if (kernel32Ex.Process32First(snapshot, pe32)) {
                do {
                    String exeName = pe32.getExeFile();
                    if (exeName.equalsIgnoreCase("java.exe") || exeName.equalsIgnoreCase("javaw.exe")) {
                        javaProcesses.add(new ProcessInfo(pe32.th32ProcessID, exeName));
                    }
                } while (kernel32Ex.Process32Next(snapshot, pe32));
            }
        } finally {
            kernel32Ex.CloseHandle(snapshot);
        }

        return javaProcesses;
    }

    /**
     * Find Java processes (java.exe/javaw.exe) that do NOT have child processes.
     *
     * This is computed from a single Toolhelp process snapshot by:
     * 1) collecting all candidate Java PIDs
     * 2) collecting all parent PIDs (th32ParentProcessID)
     * 3) returning only Java PIDs not present in the parent PID set
     */
    public static List<ProcessInfo> findJavaLeafProcesses() {
        List<ProcessInfo> javaProcesses = new ArrayList<ProcessInfo>();
        Set<Integer> parents = new HashSet<Integer>();

        HANDLE snapshot = kernel32Ex.CreateToolhelp32Snapshot(WindowsNative.TH32CS_SNAPPROCESS, 0);
        if (snapshot == null || snapshot.equals(INVALID_HANDLE_VALUE)) {
            return javaProcesses;
        }

        try {
            WindowsNative.PROCESSENTRY32.ByReference pe32 = new WindowsNative.PROCESSENTRY32.ByReference();

            if (kernel32Ex.Process32First(snapshot, pe32)) {
                do {
                    int ppid = pe32.th32ParentProcessID;
                    if (ppid > 0) {
                        parents.add(ppid);
                    }

                    String exeName = pe32.getExeFile();
                    if (exeName != null && (exeName.equalsIgnoreCase("java.exe") || exeName.equalsIgnoreCase("javaw.exe"))) {
                        javaProcesses.add(new ProcessInfo(pe32.th32ProcessID, exeName));
                    }
                } while (kernel32Ex.Process32Next(snapshot, pe32));
            }
        } finally {
            kernel32Ex.CloseHandle(snapshot);
        }

        if (javaProcesses.isEmpty() || parents.isEmpty()) {
            // If there are no Java processes (or we couldn't build the parent set), return what we have.
            return javaProcesses;
        }

        List<ProcessInfo> leaf = new ArrayList<ProcessInfo>();
        for (ProcessInfo p : javaProcesses) {
            if (!parents.contains(p.processId)) {
                leaf.add(p);
            }
        }
        return leaf;
    }

    /**
     * Find running processes by exact image name (case-insensitive), e.g. "prismlauncher.exe".
     */
    public static List<ProcessInfo> findProcessesByImageNames(String... imageNames) {
        List<ProcessInfo> matches = new ArrayList<ProcessInfo>();
        if (imageNames == null || imageNames.length == 0) {
            return matches;
        }

        Set<String> wanted = new HashSet<String>();
        for (String s : imageNames) {
            if (s != null) {
                String t = s.trim();
                if (!t.isEmpty()) {
                    wanted.add(t.toLowerCase());
                }
            }
        }
        if (wanted.isEmpty()) {
            return matches;
        }

        HANDLE snapshot = kernel32Ex.CreateToolhelp32Snapshot(WindowsNative.TH32CS_SNAPPROCESS, 0);
        if (snapshot == null || snapshot.equals(INVALID_HANDLE_VALUE)) {
            return matches;
        }

        try {
            WindowsNative.PROCESSENTRY32.ByReference pe32 = new WindowsNative.PROCESSENTRY32.ByReference();
            if (kernel32Ex.Process32First(snapshot, pe32)) {
                do {
                    String exeName = pe32.getExeFile();
                    if (exeName != null && wanted.contains(exeName.toLowerCase())) {
                        matches.add(new ProcessInfo(pe32.th32ProcessID, exeName));
                    }
                } while (kernel32Ex.Process32Next(snapshot, pe32));
            }
        } finally {
            kernel32Ex.CloseHandle(snapshot);
        }

        return matches;
    }

    /**
     * Resolve a process's full executable path using native Win32 APIs only.
     *
     * This does not use PowerShell, WMI, CIM, or WMIC.
     */
    public static String getProcessExecutablePath(int processId) {
        HANDLE hProcess = null;

        // Prefer limited query access (works on more processes without elevation).
        try {
            hProcess = kernel32Ex.OpenProcess(WindowsNative.PROCESS_QUERY_LIMITED_INFORMATION, false, processId);
        } catch (Throwable ignored) {
            hProcess = null;
        }

        if (hProcess == null) {
            try {
                hProcess = kernel32Ex.OpenProcess(WindowsNative.PROCESS_QUERY_INFORMATION, false, processId);
            } catch (Throwable ignored) {
                hProcess = null;
            }
        }

        if (hProcess == null) {
            return "";
        }

        try {
            // Use a large buffer to handle long paths.
            char[] buf = new char[32768];
            IntByReference size = new IntByReference(buf.length);
            boolean ok = kernel32Ex.QueryFullProcessImageNameW(hProcess, 0, buf, size);
            if (!ok) {
                return "";
            }

            int len = size.getValue();
            if (len <= 0 || len > buf.length) {
                return "";
            }

            return new String(buf, 0, len).trim();
        } catch (Throwable ignored) {
            return "";
        } finally {
            try {
                kernel32Ex.CloseHandle(hProcess);
            } catch (Throwable ignored) {
                // ignore
            }
        }
    }

    // (intentionally no stream helpers here; command line is read via Win32 memory inspection)

    /**
     * Read an environment variable from a remote process using native Windows APIs.
     * This reads the PEB (Process Environment Block) directly from process memory.
     */
    public static String getProcessEnvVar(int processId, String varName) {
        // Open process with read access
        HANDLE hProcess = kernel32Ex.OpenProcess(
            WindowsNative.PROCESS_QUERY_INFORMATION | WindowsNative.PROCESS_VM_READ, 
            false, 
            processId
        );
        
        if (hProcess == null) {
            return "";
        }

        try {
            // Query process basic information to get PEB address
            WindowsNative.PROCESS_BASIC_INFORMATION pbi = new WindowsNative.PROCESS_BASIC_INFORMATION();
            IntByReference returnLength = new IntByReference();
            
            int status = WindowsNative.NtDll.INSTANCE.NtQueryInformationProcess(
                hProcess,
                WindowsNative.ProcessBasicInformation,
                pbi.getPointer(),
                pbi.size(),
                returnLength
            );
            
            if (status != 0) {
                return "";
            }
            pbi.read();
            
            if (pbi.PebBaseAddress == null) {
                return "";
            }

            // Read PEB from target process
            // We need to read the ProcessParameters pointer from PEB
            // On 64-bit, ProcessParameters is at offset 0x20 in PEB
            long pebAddr = Pointer.nativeValue(pbi.PebBaseAddress);
            
            // Read ProcessParameters pointer (at offset 0x20 for 64-bit)
            com.sun.jna.Memory processParamsPtr = new com.sun.jna.Memory(8);
            IntByReference bytesRead = new IntByReference();
            
            if (!readProcessMemory(hProcess, pebAddr + 0x20, processParamsPtr, 8, bytesRead)) {
                return "";
            }
            
            long processParamsAddr = processParamsPtr.getLong(0);
            if (processParamsAddr == 0) {
                return "";
            }
            
            // Read Environment pointer from RTL_USER_PROCESS_PARAMETERS
            // Environment is at offset 0x80 on 64-bit
            com.sun.jna.Memory envPtr = new com.sun.jna.Memory(8);
            if (!readProcessMemory(hProcess, processParamsAddr + 0x80, envPtr, 8, bytesRead)) {
                return "";
            }
            
            long envAddr = envPtr.getLong(0);
            if (envAddr == 0) {
                return "";
            }
            
            // Read environment block and search for the variable
            // Environment is stored as: VAR1=VALUE1\0VAR2=VALUE2\0\0
            String targetVar = varName.toUpperCase() + "=";
            
            // Read in chunks of 4KB at a time
            int chunkSize = 4096;
            int maxSize = 256 * 1024; // Max 256KB
            int offset = 0;
            StringBuilder envBlock = new StringBuilder();
            
            while (offset < maxSize) {
                com.sun.jna.Memory chunk = new com.sun.jna.Memory(chunkSize);
                if (!readProcessMemory(hProcess, envAddr + offset, chunk, chunkSize, bytesRead)) {
                    break;
                }
                
                if (bytesRead.getValue() == 0) {
                    break;
                }
                
                // Read as wide chars (UTF-16LE)
                byte[] bytes = chunk.getByteArray(0, bytesRead.getValue());
                String chunkStr = new String(bytes, java.nio.charset.StandardCharsets.UTF_16LE);
                envBlock.append(chunkStr);
                
                // Check for double null terminator (empty string entry)
                if (chunkStr.contains("\0\0")) {
                    break;
                }
                
                offset += chunkSize;
            }
            
            // Parse environment block to find our variable
            String[] entries = envBlock.toString().split("\0");
            for (String entry : entries) {
                if (entry.toUpperCase().startsWith(targetVar)) {
                    return entry.substring(targetVar.length());
                }
            }
            
            return "";
            
        } catch (Exception e) {
            return "";
        } finally {
            kernel32Ex.CloseHandle(hProcess);
        }
    }
    
    /**
     * Read the working directory (current directory) of a remote process.
     * Reads CurrentDirectory.DosPath from RTL_USER_PROCESS_PARAMETERS via PEB.
     */
    public static String getProcessWorkingDirectory(int processId) {
        HANDLE hProcess = kernel32Ex.OpenProcess(
            WindowsNative.PROCESS_QUERY_INFORMATION | WindowsNative.PROCESS_VM_READ | 0x1000, // + PROCESS_QUERY_LIMITED_INFORMATION
            false,
            processId
        );

        if (hProcess == null) {
            return "";
        }

        try {
            // Determine target bitness; WOW64 targets use 32-bit structures/offsets
            IntByReference wow64Ref = new IntByReference();
            boolean wow64Known = kernel32.IsWow64Process(hProcess, wow64Ref);
            boolean isWow64Target = wow64Known && wow64Ref.getValue() != 0;

            // Get PEB address
            WindowsNative.PROCESS_BASIC_INFORMATION pbi = new WindowsNative.PROCESS_BASIC_INFORMATION();
            IntByReference returnLength = new IntByReference();

            int status = WindowsNative.NtDll.INSTANCE.NtQueryInformationProcess(
                hProcess,
                WindowsNative.ProcessBasicInformation,
                pbi.getPointer(),
                pbi.size(),
                returnLength
            );

            if (status != 0) {
                return "";
            }
            pbi.read();

            if (pbi.PebBaseAddress == null) {
                return "";
            }

            long pebAddr = Pointer.nativeValue(pbi.PebBaseAddress);
            IntByReference bytesRead = new IntByReference();
            String path = "";

            if (isWow64Target) {
                path = readWorkingDirectory32(hProcess, pebAddr, bytesRead);
                if (path.isEmpty()) {
                    // Fallback if WOW64 detection/reporting is unreliable
                    path = readWorkingDirectory64(hProcess, pebAddr, bytesRead);
                }
            } else {
                path = readWorkingDirectory64(hProcess, pebAddr, bytesRead);
                if (path.isEmpty()) {
                    // Fallback if we guessed the layout wrong
                    path = readWorkingDirectory32(hProcess, pebAddr, bytesRead);
                }
            }

            if (!path.isEmpty()) {
                return path;
            }

            // Last-resort fallback: infer instance path from command-line switches
            return inferWorkingDirectoryFromCommandLine(processId);

        } catch (Exception e) {
            // Last-resort fallback: infer instance path from command-line switches
            return inferWorkingDirectoryFromCommandLine(processId);
        } finally {
            kernel32Ex.CloseHandle(hProcess);
        }
    }

    private static String readWorkingDirectory64(HANDLE hProcess, long pebAddr, IntByReference bytesRead) {
        try {
            // PEB64.ProcessParameters @ +0x20
            com.sun.jna.Memory processParamsPtr = new com.sun.jna.Memory(8);
            if (!readProcessMemory(hProcess, pebAddr + 0x20, processParamsPtr, 8, bytesRead)) {
                return "";
            }

            long processParamsAddr = processParamsPtr.getLong(0);
            if (processParamsAddr == 0) {
                return "";
            }

            // RTL_USER_PROCESS_PARAMETERS64.CurrentDirectory.DosPath @ +0x38
            return readUnicodeString64(hProcess, processParamsAddr + 0x38, bytesRead);
        } catch (Exception e) {
            return "";
        }
    }

    private static String readWorkingDirectory32(HANDLE hProcess, long pebAddr, IntByReference bytesRead) {
        try {
            // PEB32.ProcessParameters @ +0x10
            com.sun.jna.Memory processParamsPtr = new com.sun.jna.Memory(4);
            if (!readProcessMemory(hProcess, pebAddr + 0x10, processParamsPtr, 4, bytesRead)) {
                return "";
            }

            long processParamsAddr = processParamsPtr.getInt(0) & 0xFFFFFFFFL;
            if (processParamsAddr == 0) {
                return "";
            }

            // RTL_USER_PROCESS_PARAMETERS32.CurrentDirectory.DosPath @ +0x24
            return readUnicodeString32(hProcess, processParamsAddr + 0x24, bytesRead);
        } catch (Exception e) {
            return "";
        }
    }

    private static String readUnicodeString64(HANDLE hProcess, long unicodeStringAddr, IntByReference bytesRead) {
        try {
            com.sun.jna.Memory uniStr = new com.sun.jna.Memory(16);
            if (!readProcessMemory(hProcess, unicodeStringAddr, uniStr, 16, bytesRead)) {
                return "";
            }

            int length = uniStr.getShort(0) & 0xFFFF;
            long bufferAddr = uniStr.getLong(8);
            if (length <= 0 || bufferAddr == 0) {
                return "";
            }

            com.sun.jna.Memory pathBuffer = new com.sun.jna.Memory(length);
            if (!readProcessMemory(hProcess, bufferAddr, pathBuffer, length, bytesRead)) {
                return "";
            }

            String path = new String(pathBuffer.getByteArray(0, length), java.nio.charset.StandardCharsets.UTF_16LE);
            if (path.endsWith("\\")) {
                path = path.substring(0, path.length() - 1);
            }
            return path;
        } catch (Exception e) {
            return "";
        }
    }

    private static String readUnicodeString32(HANDLE hProcess, long unicodeStringAddr, IntByReference bytesRead) {
        try {
            // UNICODE_STRING32: USHORT Length, USHORT MaximumLength, ULONG Buffer
            com.sun.jna.Memory uniStr = new com.sun.jna.Memory(8);
            if (!readProcessMemory(hProcess, unicodeStringAddr, uniStr, 8, bytesRead)) {
                return "";
            }

            int length = uniStr.getShort(0) & 0xFFFF;
            long bufferAddr = uniStr.getInt(4) & 0xFFFFFFFFL;
            if (length <= 0 || bufferAddr == 0) {
                return "";
            }

            com.sun.jna.Memory pathBuffer = new com.sun.jna.Memory(length);
            if (!readProcessMemory(hProcess, bufferAddr, pathBuffer, length, bytesRead)) {
                return "";
            }

            String path = new String(pathBuffer.getByteArray(0, length), java.nio.charset.StandardCharsets.UTF_16LE);
            if (path.endsWith("\\")) {
                path = path.substring(0, path.length() - 1);
            }
            return path;
        } catch (Exception e) {
            return "";
        }
    }

    private static String inferWorkingDirectoryFromCommandLine(int processId) {
        String cmdLine = getProcessCommandLine(processId);
        if (cmdLine.isEmpty()) {
            return "";
        }

        // Common launcher argument for Minecraft
        String gameDir = extractArgValue(cmdLine, "--gameDir");
        if (!gameDir.isEmpty()) {
            return gameDir;
        }

        // Some launchers pass -Duser.dir explicitly
        Pattern p = Pattern.compile("-Duser\\.dir=(\\\"([^\\\"]+)\\\"|([^\\s]+))");
        Matcher m = p.matcher(cmdLine);
        if (m.find()) {
            String val = (m.group(2) != null) ? m.group(2) : m.group(3);
            return (val != null) ? val : "";
        }

        return "";
    }

    /**
     * Read the command line of a process via native Win32 calls.
     *
     * Uses NtQueryInformationProcess to locate the target PEB, then reads
     * RTL_USER_PROCESS_PARAMETERS.CommandLine from the remote process.
     */
    public static String getProcessCommandLine(int processId) {
        HANDLE hProcess = kernel32Ex.OpenProcess(
            WindowsNative.PROCESS_QUERY_INFORMATION | WindowsNative.PROCESS_VM_READ | 0x1000, // + PROCESS_QUERY_LIMITED_INFORMATION
            false,
            processId
        );

        if (hProcess == null) {
            return "";
        }

        try {
            // Determine target bitness; WOW64 targets use 32-bit structures/offsets
            IntByReference wow64Ref = new IntByReference();
            boolean wow64Known = kernel32.IsWow64Process(hProcess, wow64Ref);
            boolean isWow64Target = wow64Known && wow64Ref.getValue() != 0;

            // Get PEB address
            WindowsNative.PROCESS_BASIC_INFORMATION pbi = new WindowsNative.PROCESS_BASIC_INFORMATION();
            IntByReference returnLength = new IntByReference();

            int status = WindowsNative.NtDll.INSTANCE.NtQueryInformationProcess(
                hProcess,
                WindowsNative.ProcessBasicInformation,
                pbi.getPointer(),
                pbi.size(),
                returnLength
            );

            if (status != 0) {
                return "";
            }
            pbi.read();

            if (pbi.PebBaseAddress == null) {
                return "";
            }

            long pebAddr = Pointer.nativeValue(pbi.PebBaseAddress);
            IntByReference bytesRead = new IntByReference();
            String cmd;

            if (isWow64Target) {
                cmd = readCommandLine32(hProcess, pebAddr, bytesRead);
                if (cmd.isEmpty()) {
                    // Fallback if WOW64 detection/reporting is unreliable
                    cmd = readCommandLine64(hProcess, pebAddr, bytesRead);
                }
            } else {
                cmd = readCommandLine64(hProcess, pebAddr, bytesRead);
                if (cmd.isEmpty()) {
                    // Fallback if we guessed the layout wrong
                    cmd = readCommandLine32(hProcess, pebAddr, bytesRead);
                }
            }

            return (cmd != null) ? cmd.trim() : "";
        } catch (Exception e) {
            return "";
        } finally {
            kernel32Ex.CloseHandle(hProcess);
        }
    }

    private static String readCommandLine64(HANDLE hProcess, long pebAddr, IntByReference bytesRead) {
        try {
            // PEB64.ProcessParameters @ +0x20
            com.sun.jna.Memory processParamsPtr = new com.sun.jna.Memory(8);
            if (!readProcessMemory(hProcess, pebAddr + 0x20, processParamsPtr, 8, bytesRead)) {
                return "";
            }

            long processParamsAddr = processParamsPtr.getLong(0);
            if (processParamsAddr == 0) {
                return "";
            }

            // RTL_USER_PROCESS_PARAMETERS64.CommandLine (UNICODE_STRING) @ +0x70
            return readUnicodeString64(hProcess, processParamsAddr + 0x70, bytesRead);
        } catch (Exception e) {
            return "";
        }
    }

    private static String readCommandLine32(HANDLE hProcess, long pebAddr, IntByReference bytesRead) {
        try {
            // PEB32.ProcessParameters @ +0x10
            com.sun.jna.Memory processParamsPtr = new com.sun.jna.Memory(4);
            if (!readProcessMemory(hProcess, pebAddr + 0x10, processParamsPtr, 4, bytesRead)) {
                return "";
            }

            long processParamsAddr = processParamsPtr.getInt(0) & 0xFFFFFFFFL;
            if (processParamsAddr == 0) {
                return "";
            }

            // RTL_USER_PROCESS_PARAMETERS32.CommandLine (UNICODE_STRING32) @ +0x40
            return readUnicodeString32(hProcess, processParamsAddr + 0x40, bytesRead);
        } catch (Exception e) {
            return "";
        }
    }

    private static String extractArgValue(String cmdLine, String argName) {
        Pattern p = Pattern.compile(Pattern.quote(argName) + "\\s+(\\\"([^\\\"]+)\\\"|([^\\s]+))");
        Matcher m = p.matcher(cmdLine);
        if (m.find()) {
            String quoted = m.group(2);
            if (quoted != null) {
                return quoted;
            }
            String plain = m.group(3);
            return (plain != null) ? plain : "";
        }
        return "";
    }

    /**
     * Helper to read memory from a remote process.
     */
    private static boolean readProcessMemory(HANDLE hProcess, long address, com.sun.jna.Memory buffer, int size, IntByReference bytesRead) {
        return kernel32Ex.ReadProcessMemory(
            hProcess,
            new Pointer(address),
            buffer,
            size,
            bytesRead
        );
    }

    /**
     * Find Java process with matching INST_ID environment variable.
     * Uses the current process's INST_ID and finds Java processes that were
     * likely spawned with the same INST_ID (via environment inheritance from the launcher).
     */
    public static int findJavaProcessByInstId(String targetInstId) {
        List<ProcessInfo> javaProcs = findJavaProcesses();
        int ourPid = getCurrentProcessId();
        int ourParentPid = getParentProcessId(ourPid);
        
        System.out.println("[ProcessUtils] Our PID: " + ourPid + ", Parent PID: " + ourParentPid);
        System.out.println("[ProcessUtils] Found " + javaProcs.size() + " Java processes");
        
        for (ProcessInfo proc : javaProcs) {
            System.out.println("[ProcessUtils]   PID " + proc.processId + " (" + proc.exeName + ")");
            
            // Skip our own process
            if (proc.processId == ourPid) {
                System.out.println("[ProcessUtils]     -> Skipping (this is us)");
                continue;
            }
            
            // Skip our parent process (the launcher that spawned us)
            if (proc.processId == ourParentPid) {
                System.out.println("[ProcessUtils]     -> Skipping (this is our parent launcher)");
                continue;
            }
            
            // For each Java process, try to verify it has our INST_ID
            String envVar = getProcessEnvVar(proc.processId, "INST_ID");
            if (targetInstId.equals(envVar)) {
                System.out.println("[ProcessUtils]     -> MATCH! INST_ID matches");
                return proc.processId;
            } else {
                System.out.println("[ProcessUtils]     -> INST_ID='" + envVar + "' (no match)");
            }
        }
        
        // If direct env var reading fails, return the first Java process
        // that isn't us or our parent (fallback for when we can't read remote env vars)
        System.out.println("[ProcessUtils] No INST_ID match found, using fallback...");
        for (ProcessInfo proc : javaProcs) {
            if (proc.processId != ourPid && proc.processId != ourParentPid) {
                System.out.println("[ProcessUtils] Fallback: Using PID " + proc.processId);
                return proc.processId;
            }
        }
        
        return 0;
    }

    /**
     * Get the parent process ID of a given process.
     */
    public static int getParentProcessId(int processId) {
        HANDLE snapshot = kernel32Ex.CreateToolhelp32Snapshot(WindowsNative.TH32CS_SNAPPROCESS, 0);
        if (snapshot == null || snapshot.equals(INVALID_HANDLE_VALUE)) {
            return 0;
        }

        try {
            WindowsNative.PROCESSENTRY32.ByReference pe32 = new WindowsNative.PROCESSENTRY32.ByReference();

            if (kernel32Ex.Process32First(snapshot, pe32)) {
                do {
                    if (pe32.th32ProcessID == processId) {
                        return pe32.th32ParentProcessID;
                    }
                } while (kernel32Ex.Process32Next(snapshot, pe32));
            }
        } finally {
            kernel32Ex.CloseHandle(snapshot);
        }
        return 0;
    }

    /**
     * Get current process ID.
     */
    public static int getCurrentProcessId() {
        return kernel32.GetCurrentProcessId();
    }

    /**
     * Check if a process has any window handle associated with its PID.
     *
     * This intentionally does NOT require the window to be visible or to have a title.
     */
    public static boolean processHasWindow(int processId) {
        if (processId <= 0) {
            return false;
        }

        // Enumerate windows and return true as soon as we see any window owned by this PID.
        // Note: EnumWindows enumerates top-level windows; this still covers the vast majority of GUI processes.
        debugWindows("processHasWindow(pid=" + processId + "): starting EnumWindows");
        HWND hwnd = findTopLevelWindowForProcess(processId, false, false);
        if (hwnd != null) {
            debugWindows("processHasWindow(pid=" + processId + "): found hwnd=" + hwnd);
            return true;
        }

        debugWindows("processHasWindow(pid=" + processId + "): no hwnd found via EnumWindows");
        return false;
    }

    /**
     * Get the first visible top-level window title for a process.
     */
    public static String getVisibleTopLevelWindowTitle(int processId) {
        final String[] titleResult = {""};
        final int targetPid = processId;
        debugWindows("getVisibleTopLevelWindowTitle(pid=" + targetPid + "): starting EnumWindows");

        WindowsNative.User32Ex.WNDENUMPROC callback = new WindowsNative.User32Ex.WNDENUMPROC() {
            @Override
            public boolean callback(HWND hwnd, Pointer lParam) {
                try {
                    IntByReference pidRef = new IntByReference();
                    user32.GetWindowThreadProcessId(hwnd, pidRef);

                    if (pidRef.getValue() == targetPid) {
                        if (user32.IsWindowVisible(hwnd) && user32.GetParent(hwnd) == null) {
                            String title = getWindowTitle(hwnd);
                            if (!title.isEmpty()) {
                                titleResult[0] = title;
                                return false; // Stop enumeration
                            }

                            // Title can be empty legitimately, or blocked by UIPI if the target is elevated.
                            debugWindows("getVisibleTopLevelWindowTitle(pid=" + targetPid + "): matching visible window has empty/unreadable title hwnd=" + hwnd);
                        }
                    }
                } catch (Throwable t) {
                    debugWindows("getVisibleTopLevelWindowTitle(pid=" + targetPid + "): callback error: " + t);
                }
                return true; // Continue enumeration
            }
        };

        boolean ok = false;
        try {
            ok = user32.EnumWindows(callback, null);
        } catch (Throwable t) {
            debugWindows("EnumWindows threw: " + t);
            ok = false;
        }
        if (!ok) {
            debugWindowsError("EnumWindows failed while getting title for pid=" + targetPid);
        }
        debugWindows("getVisibleTopLevelWindowTitle(pid=" + targetPid + "): result='" + titleResult[0] + "'");
        return titleResult[0];
    }

    private static HWND findTopLevelWindowForProcess(int processId, boolean requireVisible, boolean requireNonEmptyTitle) {
        final HWND[] result = { null };
        final int targetPid = processId;
        final int[] totalSeen = { 0 };
        final int[] pidMatches = { 0 };
        final int[] filteredOut = { 0 };

        WindowsNative.User32Ex.WNDENUMPROC callback = new WindowsNative.User32Ex.WNDENUMPROC() {
            @Override
            public boolean callback(HWND hwnd, Pointer lParam) {
                try {
                    totalSeen[0]++;
                    IntByReference pidRef = new IntByReference();
                    user32.GetWindowThreadProcessId(hwnd, pidRef);
                    if (pidRef.getValue() != targetPid) {
                        return true;
                    }

                    pidMatches[0]++;
                    debugWindows("EnumWindows: pid match pid=" + targetPid + " hwnd=" + hwnd);

                    if (requireVisible) {
                        boolean visible = false;
                        try {
                            visible = user32.IsWindowVisible(hwnd);
                        } catch (Throwable t) {
                            debugWindows("IsWindowVisible threw for hwnd=" + hwnd + ": " + t);
                        }
                        if (!visible) {
                            filteredOut[0]++;
                            debugWindows("EnumWindows: filtered (not visible) hwnd=" + hwnd);
                            return true;
                        }
                    }

                    if (requireNonEmptyTitle) {
                        String title = getWindowTitle(hwnd);
                        if (title.isEmpty()) {
                            // On elevated targets, reading title can be blocked (UIPI); treat as empty.
                            debugWindows("findTopLevelWindowForProcess(pid=" + targetPid + "): hwnd has empty/unreadable title (possible UIPI/elevation) hwnd=" + hwnd);
                            filteredOut[0]++;
                            return true;
                        }
                    }

                    result[0] = hwnd;
                    return false; // Stop enumeration
                } catch (Throwable t) {
                    debugWindows("findTopLevelWindowForProcess(pid=" + targetPid + "): callback error: " + t);
                    return true; // Continue enumeration
                }
            }
        };

        boolean ok = false;
        try {
            ok = user32.EnumWindows(callback, null);
        } catch (Throwable t) {
            debugWindows("EnumWindows threw while searching pid=" + targetPid + ": " + t);
            ok = false;
        }
        if (!ok) {
            debugWindowsError("EnumWindows failed while searching for pid=" + targetPid);
        }
        debugWindows(
            "findTopLevelWindowForProcess(pid=" + targetPid + ") done: totalSeen=" + totalSeen[0]
                + ", pidMatches=" + pidMatches[0]
                + ", filteredOut=" + filteredOut[0]
                + ", found=" + (result[0] != null)
                + (result[0] != null ? ", hwnd=" + result[0] : "")
        );
        return result[0];
    }

    private static String getWindowTitle(HWND hwnd) {
        try {
            // Larger buffer than before to reduce truncation; title may still be empty legitimately.
            char[] title = new char[2048];
            int len = user32.GetWindowTextW(hwnd, title, title.length);
            if (len <= 0) {
                // GetWindowTextW can return 0 for empty title, or when reading is blocked (e.g., UIPI on elevated windows).
                if (DEBUG_WINDOWS) {
                    debugWindowsError("GetWindowTextW returned 0 for hwnd=" + hwnd);
                }
                return "";
            }
            String s = new String(title, 0, Math.min(len, title.length));
            String out = (s != null) ? s.trim() : "";
            debugWindows("GetWindowTextW hwnd=" + hwnd + " len=" + len + " title='" + out + "'");
            return out;
        } catch (Throwable ignored) {
            return "";
        }
    }

    private static final HANDLE INVALID_HANDLE_VALUE = new HANDLE(Pointer.createConstant(-1));
}
