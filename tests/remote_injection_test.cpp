// Exercise the remote LoadLibraryW lookup the installer uses for a JVM of another architecture.
#define wmain installerEntryForTest
#define wWinMain installerWindowsEntryForTest
#if defined(TEST_LITE_INSTALLER)
#include "../exe-lite/src/main.cpp"
#else
#include "../exe/src/main.cpp"
#endif
#undef wmain
#undef wWinMain

static void require(bool value, const char *message) {
    if (!value)
        throw std::runtime_error(message);
}

int main() {
    wchar_t command[] = L"cmd.exe /c ping -n 30 127.0.0.1";
    STARTUPINFOW startup{sizeof(startup)};
    PROCESS_INFORMATION child{};
    if (!CreateProcessW(nullptr, command, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &child)) {
        std::cerr << "CreateProcessW failed: " << GetLastError() << "\n";
        return 1;
    }
    int status = 0;
    try {
        HANDLE process = child.hProcess;
        ULONG_PTR kernel32 = 0;
        for (int i = 0; i < 200 && !kernel32; ++i) {
            kernel32 = DllInjector::findRemoteModule(process, L"kernel32.dll");
            if (!kernel32)
                Sleep(25);
        }
        require(kernel32 == reinterpret_cast<ULONG_PTR>(GetModuleHandleW(L"kernel32.dll")),
                "the remote kernel32 base differs from ours");

        require(DllInjector::getProcessMachine(process) == DllInjector::currentProcessMachine(),
                "the child reports a different machine type");
        require(DllInjector::readRemoteImageMachine(process) == DllInjector::currentProcessMachine(),
                "the child's image header reports a different machine type");
        require(DllInjector::getPayloadArchitecture(child.dwProcessId) ==
                    (DllInjector::currentProcessMachine() == IMAGE_FILE_MACHINE_ARM64 ? "arm64" : "x64"),
                "the child maps to the wrong payload architecture");

        HMODULE localKernel32 = GetModuleHandleW(L"kernel32.dll");
        const ULONG_PTR loadLibrary = DllInjector::findRemoteLoadLibraryW(process);
        require(loadLibrary == reinterpret_cast<ULONG_PTR>(GetProcAddress(localKernel32, "LoadLibraryW")),
                "the remote LoadLibraryW differs from ours");
        // kernel32 forwards HeapAlloc to ntdll.
        require(DllInjector::findRemoteExport(process, kernel32, "HeapAlloc") ==
                    reinterpret_cast<ULONG_PTR>(GetProcAddress(localKernel32, "HeapAlloc")),
                "the forwarded HeapAlloc export differs from ours");
        require(DllInjector::findRemoteExport(process, kernel32, "NoSuchExportForToolscreen") == 0,
                "a missing export resolved");

        require(DllInjector::findRemoteModule(process, L"version.dll") == 0, "the child already has version.dll");
        const std::wstring library = L"version.dll";
        const SIZE_T bytes = (library.size() + 1) * sizeof(wchar_t);
        LPVOID remote = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        require(remote && WriteProcessMemory(process, remote, library.c_str(), bytes, nullptr),
                "could not write the library name");
        HANDLE thread = CreateRemoteThread(process, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibrary),
                                           remote, 0, nullptr);
        require(thread != nullptr, "CreateRemoteThread failed");
        WaitForSingleObject(thread, 10000);
        CloseHandle(thread);
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        require(DllInjector::findRemoteModule(process, L"version.dll") != 0,
                "the remote LoadLibraryW did not load version.dll");
        std::cout << "remote injection lookup passed\n";
    } catch (const std::exception &error) {
        std::cerr << error.what() << "\n";
        status = 1;
    }
    TerminateProcess(child.hProcess, 0);
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);
    return status;
}
