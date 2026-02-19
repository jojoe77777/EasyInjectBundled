package com.easyinject;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.*;
import com.sun.jna.platform.win32.BaseTSD.SIZE_T;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.win32.StdCallLibrary;
import com.sun.jna.win32.W32APIOptions;

import java.util.Arrays;
import java.util.List;

/**
 * JNA bindings for Windows native APIs required for DLL injection.
 */
public class WindowsNative {

    // Process access rights
    public static final int PROCESS_ALL_ACCESS = 0x1F0FFF;
    public static final int PROCESS_QUERY_INFORMATION = 0x0400;
    public static final int PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    public static final int PROCESS_VM_READ = 0x0010;
    public static final int PROCESS_VM_WRITE = 0x0020;
    public static final int PROCESS_VM_OPERATION = 0x0008;
    public static final int PROCESS_CREATE_THREAD = 0x0002;

    // Memory allocation constants
    public static final int MEM_COMMIT = 0x1000;
    public static final int MEM_RESERVE = 0x2000;
    public static final int MEM_RELEASE = 0x8000;
    public static final int PAGE_READWRITE = 0x04;

    // Snapshot flags
    public static final int TH32CS_SNAPPROCESS = 0x00000002;

    // Wait constants
    public static final int INFINITE = 0xFFFFFFFF;

    /**
     * Extended Kernel32 interface with additional functions for DLL injection.
     */
    public interface Kernel32Ex extends StdCallLibrary {
        Kernel32Ex INSTANCE = Native.load("kernel32", Kernel32Ex.class, W32APIOptions.DEFAULT_OPTIONS);

        HANDLE CreateToolhelp32Snapshot(int dwFlags, int th32ProcessID);
        boolean Process32First(HANDLE hSnapshot, PROCESSENTRY32.ByReference lppe);
        boolean Process32Next(HANDLE hSnapshot, PROCESSENTRY32.ByReference lppe);
        
        HANDLE OpenProcess(int dwDesiredAccess, boolean bInheritHandle, int dwProcessId);
        boolean CloseHandle(HANDLE hObject);

        // Returns a Win32 path (e.g. C:\\Program Files\\...) for the given process handle.
        // https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamew
        boolean QueryFullProcessImageNameW(HANDLE hProcess, int dwFlags, char[] lpExeName, IntByReference lpdwSize);
        
        Pointer VirtualAllocEx(HANDLE hProcess, Pointer lpAddress, SIZE_T dwSize, int flAllocationType, int flProtect);
        boolean VirtualFreeEx(HANDLE hProcess, Pointer lpAddress, SIZE_T dwSize, int dwFreeType);
        boolean WriteProcessMemory(HANDLE hProcess, Pointer lpBaseAddress, byte[] lpBuffer, int nSize, IntByReference lpNumberOfBytesWritten);
        boolean ReadProcessMemory(HANDLE hProcess, Pointer lpBaseAddress, Pointer lpBuffer, int nSize, IntByReference lpNumberOfBytesRead);
        
        HANDLE CreateRemoteThread(HANDLE hProcess, Pointer lpThreadAttributes, SIZE_T dwStackSize, 
                                   Pointer lpStartAddress, Pointer lpParameter, int dwCreationFlags, IntByReference lpThreadId);
        
        int WaitForSingleObject(HANDLE hHandle, int dwMilliseconds);
        
        HMODULE GetModuleHandleW(String lpModuleName);
        // Note: GetProcAddress needs ANSI encoding - use Kernel32Ascii interface
        
        int GetLastError();
    }

    /**
     * Kernel32 interface with ASCII options for functions that need ANSI strings (like GetProcAddress).
     */
    public interface Kernel32Ascii extends StdCallLibrary {
        Kernel32Ascii INSTANCE = Native.load("kernel32", Kernel32Ascii.class, W32APIOptions.ASCII_OPTIONS);
        
        // GetProcAddress expects ANSI string for lpProcName
        Pointer GetProcAddress(HMODULE hModule, String lpProcName);
        HMODULE GetModuleHandleA(String lpModuleName);
    }

    /**
     * User32 interface for window enumeration.
     */
    public interface User32Ex extends StdCallLibrary {
        User32Ex INSTANCE = Native.load("user32", User32Ex.class, W32APIOptions.DEFAULT_OPTIONS);

        interface WNDENUMPROC extends StdCallLibrary.StdCallCallback {
            boolean callback(HWND hwnd, Pointer lParam);
        }

        boolean EnumWindows(WNDENUMPROC lpEnumFunc, Pointer lParam);
        boolean IsWindowVisible(HWND hWnd);
        HWND GetParent(HWND hWnd);
        int GetWindowTextW(HWND hWnd, char[] lpString, int nMaxCount);
        int GetWindowThreadProcessId(HWND hWnd, IntByReference lpdwProcessId);
    }

    /**
     * PROCESSENTRY32 structure for process enumeration.
     */
    @Structure.FieldOrder({"dwSize", "cntUsage", "th32ProcessID", "th32DefaultHeapID", 
                           "th32ModuleID", "cntThreads", "th32ParentProcessID", "pcPriClassBase",
                           "dwFlags", "szExeFile"})
    public static class PROCESSENTRY32 extends Structure {
        public int dwSize;
        public int cntUsage;
        public int th32ProcessID;
        public Pointer th32DefaultHeapID;
        public int th32ModuleID;
        public int cntThreads;
        public int th32ParentProcessID;
        public int pcPriClassBase;
        public int dwFlags;
        public char[] szExeFile = new char[260]; // MAX_PATH

        public PROCESSENTRY32() {
            dwSize = size();
        }

        public String getExeFile() {
            return Native.toString(szExeFile);
        }

        public static class ByReference extends PROCESSENTRY32 implements Structure.ByReference {
            public ByReference() {
                super();
            }
        }
    }

    /**
     * NtDll interface for NtQueryInformationProcess.
     */
    public interface NtDll extends StdCallLibrary {
        NtDll INSTANCE = Native.load("ntdll", NtDll.class, W32APIOptions.DEFAULT_OPTIONS);
        
        int NtQueryInformationProcess(HANDLE ProcessHandle, int ProcessInformationClass,
                                       Pointer ProcessInformation, int ProcessInformationLength,
                                       IntByReference ReturnLength);
    }

    // ProcessInformationClass values
    public static final int ProcessBasicInformation = 0;

    /**
     * PROCESS_BASIC_INFORMATION structure (64-bit).
     */
    @Structure.FieldOrder({"Reserved1", "PebBaseAddress", "Reserved2", "UniqueProcessId", "Reserved3"})
    public static class PROCESS_BASIC_INFORMATION extends Structure {
        public Pointer Reserved1;
        public Pointer PebBaseAddress;
        public Pointer[] Reserved2 = new Pointer[2];
        public Pointer UniqueProcessId;
        public Pointer Reserved3;
        
        public static class ByReference extends PROCESS_BASIC_INFORMATION implements Structure.ByReference {}
    }

    /**
     * RTL_USER_PROCESS_PARAMETERS structure (partial, for environment access).
     * Offset to Environment is 0x80 on 64-bit Windows.
     */
    @Structure.FieldOrder({"Reserved1", "Reserved2", "ImagePathName", "CommandLine", 
                           "Environment"})
    public static class RTL_USER_PROCESS_PARAMETERS extends Structure {
        public byte[] Reserved1 = new byte[16];
        public byte[] Reserved2 = new byte[0x60 - 16]; // Padding to offset 0x60
        public UNICODE_STRING ImagePathName;
        public UNICODE_STRING CommandLine;
        public Pointer Environment; // At offset 0x80
        
        public static class ByReference extends RTL_USER_PROCESS_PARAMETERS implements Structure.ByReference {}
    }

    /**
     * UNICODE_STRING structure.
     */
    @Structure.FieldOrder({"Length", "MaximumLength", "Buffer"})
    public static class UNICODE_STRING extends Structure {
        public short Length;
        public short MaximumLength;
        public Pointer Buffer;
        
        public static class ByReference extends UNICODE_STRING implements Structure.ByReference {}
    }

    /**
     * PEB structure (partial, 64-bit).
     * ProcessParameters is at offset 0x20 on 64-bit Windows.
     */
    @Structure.FieldOrder({"Reserved1", "Mutant", "ImageBaseAddress", "Ldr", "ProcessParameters"})
    public static class PEB extends Structure {
        public byte[] Reserved1 = new byte[2];
        public byte BeingDebugged;
        public byte[] Reserved2 = new byte[1];
        public Pointer[] Reserved3 = new Pointer[2];
        public Pointer Ldr;
        public Pointer ProcessParameters; // Pointer to RTL_USER_PROCESS_PARAMETERS
        
        // Constructor to account for structure alignment
        public PEB() {
            super(ALIGN_DEFAULT);
        }
        
        public static class ByReference extends PEB implements Structure.ByReference {
            public ByReference() {
                super();
            }
        }
    }
}

