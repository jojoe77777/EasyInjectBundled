#pragma once
#include <windows.h>
#include <string>

namespace ProcessCapture {
struct Result { int exitCode = 1; std::string output; };
inline Result run(std::wstring command, DWORD timeoutMs = 60000) {
    Result result;
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE readPipe = nullptr, writePipe = nullptr;
    if (!CreatePipe(&readPipe, &writePipe, &sa, 0)) return result;
    SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);
    HANDLE input = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, nullptr);
    STARTUPINFOW si{}; si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = input; si.hStdOutput = writePipe; si.hStdError = writePipe;
    PROCESS_INFORMATION pi{};
    BOOL started = CreateProcessW(nullptr, command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(writePipe);
    if (input != INVALID_HANDLE_VALUE) CloseHandle(input);
    if (!started) { CloseHandle(readPipe); return result; }
    const ULONGLONG deadline = GetTickCount64() + timeoutMs;
    for (;;) {
        if (GetTickCount64() >= deadline) {
            TerminateProcess(pi.hProcess, 124);
            WaitForSingleObject(pi.hProcess, 1000);
            result.exitCode = 124;
            result.output += "\nProcess timed out";
            break;
        }
        DWORD available = 0;
        if (PeekNamedPipe(readPipe, nullptr, 0, nullptr, &available, nullptr) && available) {
            char buffer[4096]; DWORD count = 0;
            const DWORD request = available < sizeof(buffer) ? available : sizeof(buffer);
            if (ReadFile(readPipe, buffer, request, &count, nullptr) && count) {
                const size_t remaining = 1024 * 1024 - result.output.size();
                result.output.append(buffer, count < remaining ? count : remaining);
                continue;
            }
        }
        if (WaitForSingleObject(pi.hProcess, 10) == WAIT_OBJECT_0) {
            // Drain data already written, but never wait on a descendant that inherited the pipe.
            if (PeekNamedPipe(readPipe, nullptr, 0, nullptr, &available, nullptr) && available) continue;
            DWORD code = 1; GetExitCodeProcess(pi.hProcess, &code);
            result.exitCode = static_cast<int>(code);
            break;
        }
    }
    CloseHandle(readPipe); CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return result;
}
}
