package com.easyinject;

import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.*;
import com.sun.jna.platform.win32.BaseTSD.SIZE_T;
import com.sun.jna.ptr.IntByReference;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

/**
 * DLL injection implementation using CreateRemoteThread + LoadLibraryW.
 */
public class DllInjector {

    private static final WindowsNative.Kernel32Ex kernel32 = WindowsNative.Kernel32Ex.INSTANCE;

    /**
     * Result of injection attempt with error details.
     */
    public static class InjectionResult {
        public final boolean success;
        public final String error;
        public final int errorCode;
        
        public InjectionResult(boolean success, String error, int errorCode) {
            this.success = success;
            this.error = error;
            this.errorCode = errorCode;
        }
        
        public static InjectionResult success() {
            return new InjectionResult(true, null, 0);
        }
        
        public static InjectionResult failure(String error, int errorCode) {
            return new InjectionResult(false, error, errorCode);
        }
    }

    /**
     * Inject a DLL into the target process and return detailed result.
     */
    public static InjectionResult injectDllWithResult(int processId, Path dllPath) {
        String dllPathStr = dllPath.toAbsolutePath().toString();
        
        // Check if DLL file exists
        if (!dllPath.toFile().exists()) {
            return InjectionResult.failure("DLL file does not exist: " + dllPathStr, 0);
        }
        long dllSize = dllPath.toFile().length();

        // Open target process with all access
        HANDLE hProcess = kernel32.OpenProcess(
            WindowsNative.PROCESS_ALL_ACCESS,
            false,
            processId
        );

        if (hProcess == null) {
            int error = kernel32.GetLastError();
            return InjectionResult.failure("OpenProcess failed: " + getErrorMessage(error), error);
        }

        try {
            return injectDllToProcessWithResult(hProcess, dllPathStr);
        } finally {
            kernel32.CloseHandle(hProcess);
        }
    }

    /**
     * Inject a DLL into the target process.
     * 
     * @param processId Target process ID
     * @param dllPath   Full path to the DLL file
     * @return true if injection succeeded, false otherwise
     */
    public static boolean injectDll(int processId, Path dllPath) {
        InjectionResult result = injectDllWithResult(processId, dllPath);
        if (!result.success) {
            System.err.println("[Injector] Injection failed: " + result.error);
        }
        return result.success;
    }
    
    private static String getErrorMessage(int error) {
        switch (error) {
            case 5: return "ERROR_ACCESS_DENIED - Need admin rights or process protection";
            case 6: return "ERROR_INVALID_HANDLE";
            case 87: return "ERROR_INVALID_PARAMETER";
            case 299: return "ERROR_PARTIAL_COPY - 32/64-bit mismatch?";
            default: return "Error code " + error;
        }
    }

    /**
     * Inject DLL into an already-opened process handle.
     */
    private static boolean injectDllToProcess(HANDLE hProcess, String dllPath) {
        InjectionResult result = injectDllToProcessWithResult(hProcess, dllPath);
        return result.success;
    }

    /**
     * Inject DLL into an already-opened process handle, returning detailed result.
     */
    private static InjectionResult injectDllToProcessWithResult(HANDLE hProcess, String dllPath) {
        // Convert DLL path to wide string (UTF-16LE with null terminator)
        byte[] dllPathBytes = (dllPath + "\0").getBytes(StandardCharsets.UTF_16LE);
        int pathSize = dllPathBytes.length;

        // Allocate memory in target process
        Pointer remoteMem = kernel32.VirtualAllocEx(
            hProcess,
            null,
            new SIZE_T(pathSize),
            WindowsNative.MEM_COMMIT | WindowsNative.MEM_RESERVE,
            WindowsNative.PAGE_READWRITE
        );

        if (remoteMem == null) {
            int error = kernel32.GetLastError();
            return InjectionResult.failure("VirtualAllocEx failed: " + getErrorMessage(error), error);
        }

        try {
            // Write DLL path to allocated memory
            IntByReference bytesWritten = new IntByReference();
            boolean writeSuccess = kernel32.WriteProcessMemory(
                hProcess,
                remoteMem,
                dllPathBytes,
                pathSize,
                bytesWritten
            );

            if (!writeSuccess) {
                int error = kernel32.GetLastError();
                return InjectionResult.failure("WriteProcessMemory failed: " + getErrorMessage(error), error);
            }

            // Get LoadLibraryW address from kernel32.dll
            // Use Kernel32Ascii interface because GetProcAddress expects ANSI function names
            HMODULE hKernel32 = WindowsNative.Kernel32Ascii.INSTANCE.GetModuleHandleA("kernel32.dll");
            if (hKernel32 == null) {
                return InjectionResult.failure("GetModuleHandle(kernel32.dll) failed", kernel32.GetLastError());
            }

            Pointer loadLibraryAddr = WindowsNative.Kernel32Ascii.INSTANCE.GetProcAddress(hKernel32, "LoadLibraryW");
            if (loadLibraryAddr == null) {
                return InjectionResult.failure("GetProcAddress(LoadLibraryW) failed", kernel32.GetLastError());
            }

            // Create remote thread to call LoadLibraryW
            IntByReference threadId = new IntByReference();
            HANDLE hThread = kernel32.CreateRemoteThread(
                hProcess,
                null,
                new SIZE_T(0),
                loadLibraryAddr,
                remoteMem,
                0,
                threadId
            );

            if (hThread == null) {
                int error = kernel32.GetLastError();
                return InjectionResult.failure("CreateRemoteThread failed: " + getErrorMessage(error), error);
            }

            try {
                // Wait for the thread to complete (10 second timeout)
                kernel32.WaitForSingleObject(hThread, 10000);
                return InjectionResult.success();
            } finally {
                kernel32.CloseHandle(hThread);
            }

        } finally {
            // Free the allocated memory
            kernel32.VirtualFreeEx(hProcess, remoteMem, new SIZE_T(0), WindowsNative.MEM_RELEASE);
        }
    }

    /**
     * Inject multiple DLLs into the target process.
     * 
     * @param processId Target process ID
     * @param dllPaths  List of DLL paths to inject
     * @return Number of DLLs successfully injected
     */
    public static int injectDlls(int processId, java.util.List<Path> dllPaths) {
        int successCount = 0;
        for (Path dllPath : dllPaths) {
            if (injectDll(processId, dllPath)) {
                successCount++;
            }
            // Small delay between injections
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        return successCount;
    }
}
