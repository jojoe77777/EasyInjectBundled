/**
 * EasyInjectBundled — Native Win32 C++ Port
 *
 * Full port of the Java DLL injector to a standalone Windows EXE.
 * All functionality is preserved:
 *   - Launcher Mode (--prelaunch): spawn watcher, run forwarded pre-launch chains / prelaunch.txt, self-update
 *   - Watcher Mode (--watcher): poll for Minecraft Java process, wait for window, inject DLLs
 *   - Info Mode (--info): list bundled DLLs with SHA-512 hashes
 *   - Install Mode (double-click): detect instance.cfg / instance.json, install PreLaunchCommand,
 *     Windows Defender exclusion, Smart App Control detection
 *
 * DLLs are shipped in a dlls/ folder next to the EXE (not embedded in a JAR).
 * At runtime they are copied to %USERPROFILE%/.config/<brand>/dlls for injection.
 * The auto-updater downloads an .exe from GitHub releases.
 */

// ============================================================================
// Includes
// ============================================================================
#include <windows.h>
#include <winhttp.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlwapi.h>
#include <shellapi.h>
#include <shlobj.h>
#include <commctrl.h>
#include <winternl.h>     // PROCESS_BASIC_INFORMATION
#include <bcrypt.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <mutex>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;

// Link manifest for ComCtl32 v6 (visual styles / TaskDialog)
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' " \
    "version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// NtQueryInformationProcess prototype (ntdll)
extern "C" NTSTATUS NTAPI NtQueryInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

// ============================================================================
// Constants
// ============================================================================
static const wchar_t* WATCHER_ARG        = L"--watcher";
static const wchar_t* INFO_ARG           = L"--info";
static const wchar_t* PRELAUNCH_ARG      = L"--prelaunch";
static const wchar_t* FORWARDED_PRELAUNCH_CHAIN_ARG = L"--run-prelaunch-chain";
static const wchar_t* DEFENDER_ELEVATED_ENSURE_ARG   = L"--defender-elevated-ensure";
static const wchar_t* DEFENDER_ELEVATED_SELFEXE_ARG  = L"--defender-elevated-selfexe";
static const wchar_t* DEFENDER_ELEVATED_OUT_ARG      = L"--defender-elevated-out";
static const wchar_t* LOGGER_DLL_NAME   = L"liblogger_x64.dll";
static const wchar_t* LOG_FILE_NAME     = L"injector.log";
static const int POLL_INTERVAL_MS       = 500;
static const int TARGET_LEAF_RECHECK_MS = 2000;
static const int TIMEOUT_SECONDS        = 60;

// ============================================================================
// Branding globals
// ============================================================================
static std::string g_projectName = "EasyInjectBundled";
static std::string g_version     = "1.0";
static std::string g_updateApiUrl;
static std::string g_releasesUrl;
static std::string g_assetNameRegex;

// ============================================================================
// Logging
// ============================================================================
static std::ofstream g_logFile;
static std::mutex    g_logMutex;

static std::string currentTimestamp() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char buf[64];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d.%03d",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return buf;
}

static void logMsg(const std::string& msg) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    std::string line = "[" + currentTimestamp() + "] " + msg;
    std::cout << line << std::endl;
    if (g_logFile.is_open()) {
        g_logFile << line << std::endl;
        g_logFile.flush();
    }
}

static void initLogging(const fs::path& logFilePath, bool append = true) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    if (g_logFile.is_open()) g_logFile.close();
    auto mode = std::ios::out;
    if (append) mode |= std::ios::app;
    g_logFile.open(logFilePath, mode);
}

static void closeLogging() {
    std::lock_guard<std::mutex> lock(g_logMutex);
    if (g_logFile.is_open()) g_logFile.close();
}

static void resetLogFile(const fs::path& p) {
    try {
        if (p.has_parent_path()) fs::create_directories(p.parent_path());
        std::ofstream f(p, std::ios::out | std::ios::trunc);
    } catch (...) {}
}

// ============================================================================
// String utilities
// ============================================================================
static std::wstring toWide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (n <= 0) return {};
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), n);
    return w;
}

static std::string toUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), s.data(), n, nullptr, nullptr);
    return s;
}

static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)::tolower(c); });
    return s;
}

static std::wstring toLowerW(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) { return (wchar_t)::towlower(c); });
    return s;
}

static std::string trim(const std::string& s) {
    auto b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    auto e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

static std::wstring trimW(const std::wstring& s) {
    auto b = s.find_first_not_of(L" \t\r\n");
    if (b == std::wstring::npos) return {};
    auto e = s.find_last_not_of(L" \t\r\n");
    return s.substr(b, e - b + 1);
}

static bool startsWith(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

static bool startsWithW(const std::wstring& s, const std::wstring& prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

static bool endsWithW(const std::wstring& s, const std::wstring& suffix) {
    return s.size() >= suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

static bool iequals(const std::string& a, const std::string& b) {
    return toLower(a) == toLower(b);
}

static bool iequalsW(const std::wstring& a, const std::wstring& b) {
    return toLowerW(a) == toLowerW(b);
}

static std::string escapeHtml(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;";  break;
            case '>': out += "&gt;";  break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default: out += c;
        }
    }
    return out;
}

// ============================================================================
// Path utilities
// ============================================================================
static fs::path getExePath() {
    wchar_t buf[32768];
    DWORD n = GetModuleFileNameW(nullptr, buf, 32768);
    if (n == 0 || n >= 32768) return {};
    return fs::path(buf);
}

static fs::path getExeDir() {
    return getExePath().parent_path();
}

/**
 * Stable exe filename for launcher integration (e.g. Toolscreen.exe).
 */
static std::wstring getStableExeFileName() {
    std::string base = g_projectName;
    if (base.empty()) base = "Toolscreen";
    // Sanitize
    for (char& c : base) {
        if (c == '\\' || c == '/' || c == ':' || c == '*' || c == '"' || c == '<' || c == '>' || c == '|')
            c = '_';
    }
    return toWide(base) + L".exe";
}

static std::string getBrandedConfigFolderName() {
    std::string name = g_projectName;
    if (name.empty()) return "app";
    std::string out;
    for (char c : name) {
        if (c == '<' || c == '>' || c == ':' || c == '"' || c == '/' || c == '\\' || c == '|' || c == '?' || c == '*')
            out += '-';
        else
            out += c;
    }
    while (!out.empty() && (out.back() == '.' || out.back() == ' '))
        out.pop_back();
    return out.empty() ? "app" : out;
}

static fs::path getPreferredPersistentDllDir() {
    wchar_t profileDir[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_PROFILE, nullptr, 0, profileDir))) {
        fs::path p = fs::path(profileDir) / L".config" / toWide(getBrandedConfigFolderName()) / L"dlls";
        return p;
    }
    // Fallback
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    return fs::path(tmp) / toWide(g_projectName);
}

static std::wstring normalizePathForCompare(const std::wstring& path) {
    std::wstring p = trimW(path);
    if (p.empty()) return {};
    try {
        p = fs::absolute(p).lexically_normal().wstring();
    } catch (...) {}
    // Unify separators
    for (auto& c : p) if (c == L'\\') c = L'/';
    // Strip trailing slashes (but keep root like C:/)
    while (p.size() > 1 && p.back() == L'/') {
        if (p.size() == 3 && p[1] == L':' && p[2] == L'/') break;
        p.pop_back();
    }
    return p;
}

static std::wstring normalizeDefenderPath(const std::wstring& path) {
    std::wstring p = trimW(path);
    if (p.empty()) return {};
    // Strip BOM
    if (!p.empty() && p[0] == 0xFEFF) p = trimW(p.substr(1));
    // Strip wrapping quotes
    if (p.size() >= 2 && ((p.front() == L'"' && p.back() == L'"') || (p.front() == L'\'' && p.back() == L'\'')))
        p = trimW(p.substr(1, p.size() - 2));
    for (auto& c : p) if (c == L'/') c = L'\\';
    // Strip \\?\ prefix
    if (startsWithW(p, L"\\\\?\\UNC\\")) p = L"\\\\" + p.substr(8);
    else if (startsWithW(p, L"\\\\?\\")) p = p.substr(4);
    // Strip trailing wildcard
    if (endsWithW(p, L"\\*")) p = p.substr(0, p.size() - 2);
    // Canonicalize
    try { p = fs::canonical(p).wstring(); } catch (...) {
        try { p = fs::absolute(p).lexically_normal().wstring(); } catch (...) {}
    }
    // Strip trailing backslash (keep root)
    while (p.size() > 1 && p.back() == L'\\') {
        if (p.size() == 3 && p[1] == L':' && p[2] == L'\\') break;
        p.pop_back();
    }
    return p;
}

static bool isPathCoveredByExclusion(const std::wstring& exclusion, const std::wstring& wanted) {
    std::wstring ex = normalizeDefenderPath(exclusion);
    std::wstring wa = normalizeDefenderPath(wanted);
    if (ex.empty() || wa.empty()) return false;
    if (iequalsW(ex, wa)) return true;
    std::wstring exS = ex; if (exS.back() != L'\\') exS += L'\\';
    std::wstring waS = wa; if (waS.back() != L'\\') waS += L'\\';
    return _wcsnicmp(waS.c_str(), exS.c_str(), exS.size()) == 0;
}

// ============================================================================
// Branding properties loader
// ============================================================================
static void loadBranding() {
    fs::path propsFile = getExeDir() / L"branding.properties";
    std::ifstream f(propsFile);
    if (!f.is_open()) return;
    std::string line;
    while (std::getline(f, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = trim(line.substr(0, eq));
        std::string val = trim(line.substr(eq + 1));
        if (key == "brand.name" && !val.empty())                g_projectName = val;
        else if (key == "brand.version" && !val.empty())        g_version = val;
        else if (key == "update.latestReleaseApiUrl")           g_updateApiUrl = val;
        else if (key == "update.releasesUrl")                   g_releasesUrl = val;
        else if (key == "update.assetNameRegex")                g_assetNameRegex = val;
    }
}

// ============================================================================
// Command-line argument helpers
// ============================================================================
static bool hasArg(int argc, wchar_t* argv[], const wchar_t* arg) {
    for (int i = 1; i < argc; i++)
        if (_wcsicmp(argv[i], arg) == 0) return true;
    return false;
}

static std::wstring getArgValue(int argc, wchar_t* argv[], const wchar_t* arg) {
    for (int i = 1; i < argc - 1; i++)
        if (_wcsicmp(argv[i], arg) == 0) return argv[i + 1];
    return {};
}

// ============================================================================
// Shell / process execution helpers
// ============================================================================
struct ExecResult {
    int exitCode = 1;
    std::string output;
};

static ExecResult execCommandCapture(const std::wstring& cmdLine) {
    ExecResult result;
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE hReadPipe, hWritePipe;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) return result;
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.hStdOutput = hWritePipe;
    si.hStdError  = hWritePipe;
    si.dwFlags    = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};

    std::wstring cmd = cmdLine; // mutable copy
    if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return result;
    }
    CloseHandle(hWritePipe);

    std::string output;
    char buf[4096];
    DWORD bytesRead;
    while (ReadFile(hReadPipe, buf, sizeof(buf), &bytesRead, nullptr) && bytesRead > 0)
        output.append(buf, bytesRead);
    CloseHandle(hReadPipe);

    WaitForSingleObject(pi.hProcess, 60000);
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    result.exitCode = (int)exitCode;
    result.output = output;
    return result;
}

static ExecResult execElevatedAndWait(const std::wstring& file, const std::wstring& params, DWORD timeoutMs) {
    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"runas";
    sei.lpFile = file.c_str();
    sei.lpParameters = params.c_str();
    sei.nShow = SW_HIDE;

    if (!ShellExecuteExW(&sei)) {
        DWORD err = GetLastError();
        ExecResult r;
        r.exitCode = 1;
        r.output = (err == ERROR_CANCELLED) ? "UAC prompt was cancelled" : "ShellExecuteEx failed";
        return r;
    }

    if (!sei.hProcess) return {1, "Elevated process handle missing"};
    DWORD wait = WaitForSingleObject(sei.hProcess, timeoutMs > 0 ? timeoutMs : INFINITE);
    if (wait == WAIT_TIMEOUT) { CloseHandle(sei.hProcess); return {1, "Timed out"}; }

    DWORD exitCode = 1;
    GetExitCodeProcess(sei.hProcess, &exitCode);
    CloseHandle(sei.hProcess);
    return {(int)exitCode, ""};
}

static std::wstring getPowerShellExePath() {
    wchar_t root[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"SystemRoot", root, MAX_PATH);
    if (n > 0 && n < MAX_PATH) {
        std::wstring p = std::wstring(root) + L"\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
        if (GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES) return p;
    }
    return L"powershell.exe";
}

static std::wstring getRegExePath() {
    wchar_t root[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"SystemRoot", root, MAX_PATH);
    if (n > 0 && n < MAX_PATH) {
        std::wstring p = std::wstring(root) + L"\\System32\\reg.exe";
        if (GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES) return p;
    }
    return L"reg.exe";
}

static std::string readTextFile(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f.is_open()) return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static void writeTextFile(const fs::path& p, const std::string& text) {
    std::ofstream f(p, std::ios::binary);
    if (f.is_open()) f << text;
}

static std::vector<std::string> splitLines(const std::string& s) {
    std::vector<std::string> lines;
    std::istringstream iss(s);
    std::string line;
    while (std::getline(iss, line)) {
        // Strip \r
        if (!line.empty() && line.back() == '\r') line.pop_back();
        lines.push_back(line);
    }
    return lines;
}

// ============================================================================
// SHA-512 (BCrypt)
// ============================================================================
static std::string computeSha512(const std::vector<uint8_t>& data) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    BYTE hash[64]; // SHA-512 = 64 bytes
    std::string result;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA512_ALGORITHM, nullptr, 0) != 0) return "ERROR";
    if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) != 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return "ERROR"; }
    BCryptHashData(hHash, (PUCHAR)data.data(), (ULONG)data.size(), 0);
    BCryptFinishHash(hHash, hash, 64, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    char hex[129];
    for (int i = 0; i < 64; i++) sprintf(hex + i * 2, "%02x", hash[i]);
    hex[128] = '\0';
    return hex;
}

// ============================================================================
// Process Utilities
// ============================================================================
namespace ProcessUtils {

struct ProcessInfo {
    DWORD processId;
    std::wstring exeName;
};

static std::vector<ProcessInfo> findJavaLeafProcesses() {
    std::vector<ProcessInfo> javaProcs;
    std::set<DWORD> parents;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return {};

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ParentProcessID > 0) parents.insert(pe.th32ParentProcessID);
            std::wstring exe = pe.szExeFile;
            if (iequalsW(exe, L"java.exe") || iequalsW(exe, L"javaw.exe"))
                javaProcs.push_back({pe.th32ProcessID, exe});
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    std::vector<ProcessInfo> leaves;
    for (auto& p : javaProcs)
        if (parents.find(p.processId) == parents.end()) leaves.push_back(p);
    return leaves;
}

static bool isJavaLeafProcess(DWORD pid) {
    std::set<DWORD> parents;
    bool found = false, isJava = false;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ParentProcessID > 0) parents.insert(pe.th32ParentProcessID);
            if (pe.th32ProcessID == pid) {
                found = true;
                std::wstring exe = pe.szExeFile;
                isJava = iequalsW(exe, L"java.exe") || iequalsW(exe, L"javaw.exe");
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found && isJava && parents.find(pid) == parents.end();
}

static std::vector<ProcessInfo> findProcessesByImageNames(const std::vector<std::wstring>& names) {
    std::vector<ProcessInfo> matches;
    std::set<std::wstring> wanted;
    for (auto& n : names) wanted.insert(toLowerW(n));

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return {};

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (wanted.count(toLowerW(pe.szExeFile)))
                matches.push_back({pe.th32ProcessID, pe.szExeFile});
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return matches;
}

static DWORD getParentProcessId(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    DWORD ppid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) { ppid = pe.th32ParentProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return ppid;
}

static std::wstring getProcessExecutablePath(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!h) return {};
    wchar_t buf[32768];
    DWORD sz = 32768;
    BOOL ok = QueryFullProcessImageNameW(h, 0, buf, &sz);
    CloseHandle(h);
    if (!ok || sz == 0) return {};
    return std::wstring(buf, sz);
}

/**
 * Read a UNICODE_STRING from the target process at the given address (64-bit layout).
 */
static std::wstring readUnicodeString64(HANDLE hProc, ULONG_PTR addr) {
    // UNICODE_STRING64: USHORT Length, USHORT MaxLen, ULONG64 Buffer
    BYTE raw[16]{};
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProc, (LPCVOID)addr, raw, 16, &bytesRead) || bytesRead < 16) return {};
    USHORT length = *(USHORT*)&raw[0];
    ULONG_PTR bufAddr = *(ULONG_PTR*)&raw[8];
    if (length == 0 || bufAddr == 0) return {};
    std::vector<BYTE> data(length);
    if (!ReadProcessMemory(hProc, (LPCVOID)bufAddr, data.data(), length, &bytesRead) || bytesRead == 0) return {};
    std::wstring s((wchar_t*)data.data(), length / sizeof(wchar_t));
    while (!s.empty() && s.back() == L'\\') s.pop_back();
    return s;
}

static std::wstring readUnicodeString32(HANDLE hProc, ULONG_PTR addr) {
    BYTE raw[8]{};
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProc, (LPCVOID)addr, raw, 8, &bytesRead) || bytesRead < 8) return {};
    USHORT length = *(USHORT*)&raw[0];
    ULONG_PTR bufAddr = *(ULONG*)&raw[4];
    if (length == 0 || bufAddr == 0) return {};
    std::vector<BYTE> data(length);
    if (!ReadProcessMemory(hProc, (LPCVOID)bufAddr, data.data(), length, &bytesRead) || bytesRead == 0) return {};
    std::wstring s((wchar_t*)data.data(), length / sizeof(wchar_t));
    while (!s.empty() && s.back() == L'\\') s.pop_back();
    return s;
}

/**
 * Read the PEB of a remote process and get ProcessParameters pointer.
 * Returns {pebAddr, processParamsAddr, isWow64}.
 */
struct PebInfo {
    ULONG_PTR pebAddr = 0;
    bool isWow64 = false;
};

static PebInfo getPebInfo(HANDLE hProc) {
    PebInfo info;
    BOOL wow64 = FALSE;
    IsWow64Process(hProc, &wow64);
    info.isWow64 = (wow64 != FALSE);

    PROCESS_BASIC_INFORMATION pbi{};
    ULONG retLen = 0;
    NTSTATUS st = NtQueryInformationProcess(hProc, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
    if (st != 0 || pbi.PebBaseAddress == nullptr) return {};
    info.pebAddr = (ULONG_PTR)pbi.PebBaseAddress;
    return info;
}

static ULONG_PTR readProcessParamsAddr64(HANDLE hProc, ULONG_PTR pebAddr) {
    // PEB64.ProcessParameters at offset 0x20
    ULONG_PTR val = 0;
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProc, (LPCVOID)(pebAddr + 0x20), &val, 8, &bytesRead)) return 0;
    return val;
}

static ULONG_PTR readProcessParamsAddr32(HANDLE hProc, ULONG_PTR pebAddr) {
    ULONG val = 0;
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProc, (LPCVOID)(pebAddr + 0x10), &val, 4, &bytesRead)) return 0;
    return val;
}

static std::wstring getProcessWorkingDirectory(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) return {};
    auto info = getPebInfo(hProc);
    if (info.pebAddr == 0) { CloseHandle(hProc); return {}; }

    std::wstring result;
    if (info.isWow64) {
        ULONG_PTR pp = readProcessParamsAddr32(hProc, info.pebAddr);
        if (pp) result = readUnicodeString32(hProc, pp + 0x24); // CurrentDirectory.DosPath
        if (result.empty()) {
            pp = readProcessParamsAddr64(hProc, info.pebAddr);
            if (pp) result = readUnicodeString64(hProc, pp + 0x38);
        }
    } else {
        ULONG_PTR pp = readProcessParamsAddr64(hProc, info.pebAddr);
        if (pp) result = readUnicodeString64(hProc, pp + 0x38);
        if (result.empty()) {
            pp = readProcessParamsAddr32(hProc, info.pebAddr);
            if (pp) result = readUnicodeString32(hProc, pp + 0x24);
        }
    }
    CloseHandle(hProc);
    return result;
}

static std::wstring getProcessCommandLine(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) return {};
    auto info = getPebInfo(hProc);
    if (info.pebAddr == 0) { CloseHandle(hProc); return {}; }

    std::wstring result;
    if (info.isWow64) {
        ULONG_PTR pp = readProcessParamsAddr32(hProc, info.pebAddr);
        if (pp) result = readUnicodeString32(hProc, pp + 0x40); // CommandLine
        if (result.empty()) {
            pp = readProcessParamsAddr64(hProc, info.pebAddr);
            if (pp) result = readUnicodeString64(hProc, pp + 0x70);
        }
    } else {
        ULONG_PTR pp = readProcessParamsAddr64(hProc, info.pebAddr);
        if (pp) result = readUnicodeString64(hProc, pp + 0x70);
        if (result.empty()) {
            pp = readProcessParamsAddr32(hProc, info.pebAddr);
            if (pp) result = readUnicodeString32(hProc, pp + 0x40);
        }
    }
    CloseHandle(hProc);
    return result;
}

static std::wstring getProcessEnvVar(DWORD pid, const std::wstring& varName) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) return {};
    auto info = getPebInfo(hProc);
    if (info.pebAddr == 0) { CloseHandle(hProc); return {}; }

    ULONG_PTR pp = readProcessParamsAddr64(hProc, info.pebAddr);
    if (!pp) { CloseHandle(hProc); return {}; }

    // Environment pointer at offset 0x80 in RTL_USER_PROCESS_PARAMETERS (64-bit)
    ULONG_PTR envAddr = 0;
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProc, (LPCVOID)(pp + 0x80), &envAddr, 8, &bytesRead) || envAddr == 0) {
        CloseHandle(hProc);
        return {};
    }

    std::wstring target = toLowerW(varName) + L"=";
    size_t maxSize = 256 * 1024;
    std::vector<wchar_t> envBlock;
    size_t offset = 0;
    while (offset < maxSize) {
        wchar_t chunk[2048];
        if (!ReadProcessMemory(hProc, (LPCVOID)(envAddr + offset), chunk, sizeof(chunk), &bytesRead) || bytesRead == 0) break;
        size_t wchars = bytesRead / sizeof(wchar_t);
        envBlock.insert(envBlock.end(), chunk, chunk + wchars);
        // Check for double null terminator
        for (size_t i = 0; i + 1 < envBlock.size(); i++)
            if (envBlock[i] == L'\0' && envBlock[i + 1] == L'\0') goto done;
        offset += (size_t)bytesRead;
    }
done:
    CloseHandle(hProc);

    // Parse environment block
    std::wstring entry;
    for (wchar_t c : envBlock) {
        if (c == L'\0') {
            if (entry.size() >= target.size() && _wcsnicmp(entry.c_str(), target.c_str(), target.size()) == 0)
                return entry.substr(target.size());
            entry.clear();
        } else {
            entry += c;
        }
    }
    return {};
}

struct WindowSearchResult {
    HWND hwnd = nullptr;
    std::wstring title;
};

static std::wstring getWindowTitle(HWND hwnd) {
    wchar_t buf[2048];
    int len = GetWindowTextW(hwnd, buf, 2048);
    if (len <= 0) return {};
    return std::wstring(buf, len);
}

static bool processHasWindow(DWORD pid) {
    struct Data { DWORD pid; bool found; };
    Data data{pid, false};
    EnumWindows([](HWND hwnd, LPARAM lp) -> BOOL {
        auto* d = (Data*)lp;
        DWORD wpid = 0;
        GetWindowThreadProcessId(hwnd, &wpid);
        if (wpid == d->pid) { d->found = true; return FALSE; }
        return TRUE;
    }, (LPARAM)&data);
    return data.found;
}

static std::wstring getVisibleTopLevelWindowTitle(DWORD pid) {
    struct Data { DWORD pid; std::wstring title; };
    Data data{pid, {}};
    EnumWindows([](HWND hwnd, LPARAM lp) -> BOOL {
        auto* d = (Data*)lp;
        DWORD wpid = 0;
        GetWindowThreadProcessId(hwnd, &wpid);
        if (wpid == d->pid && IsWindowVisible(hwnd) && GetParent(hwnd) == nullptr) {
            wchar_t buf[2048];
            int len = GetWindowTextW(hwnd, buf, 2048);
            if (len > 0) {
                d->title = std::wstring(buf, len);
                return FALSE;
            }
        }
        return TRUE;
    }, (LPARAM)&data);
    return data.title;
}

} // namespace ProcessUtils

// ============================================================================
// DLL Injector
// ============================================================================
namespace DllInjector {

struct InjectionResult {
    bool success;
    std::string error;
    DWORD errorCode;
};

static std::string getErrorMessage(DWORD err) {
    switch (err) {
        case 5:   return "ERROR_ACCESS_DENIED - Need admin rights or process protection";
        case 6:   return "ERROR_INVALID_HANDLE";
        case 87:  return "ERROR_INVALID_PARAMETER";
        case 299: return "ERROR_PARTIAL_COPY - 32/64-bit mismatch?";
        default:  return "Error code " + std::to_string(err);
    }
}

static InjectionResult injectDll(DWORD processId, const fs::path& dllPath) {
    if (!fs::exists(dllPath))
        return {false, "DLL file does not exist: " + dllPath.string(), 0};

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess)
        return {false, "OpenProcess failed: " + getErrorMessage(GetLastError()), GetLastError()};

    // Convert DLL path to UTF-16LE with null terminator
    std::wstring pathW = dllPath.wstring();
    SIZE_T pathBytes = (pathW.size() + 1) * sizeof(wchar_t);

    // Allocate memory in target process
    LPVOID remoteMem = VirtualAllocEx(hProcess, nullptr, pathBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        DWORD err = GetLastError();
        CloseHandle(hProcess);
        return {false, "VirtualAllocEx failed: " + getErrorMessage(err), err};
    }

    InjectionResult result{false, "", 0};

    do {
        // Write DLL path
        SIZE_T written;
        if (!WriteProcessMemory(hProcess, remoteMem, pathW.c_str(), pathBytes, &written)) {
            DWORD err = GetLastError();
            result = {false, "WriteProcessMemory failed: " + getErrorMessage(err), err};
            break;
        }

        // Get LoadLibraryW address
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        if (!hKernel32) {
            result = {false, "GetModuleHandle(kernel32.dll) failed", GetLastError()};
            break;
        }
        FARPROC loadLibAddr = GetProcAddress(hKernel32, "LoadLibraryW");
        if (!loadLibAddr) {
            result = {false, "GetProcAddress(LoadLibraryW) failed", GetLastError()};
            break;
        }

        // Create remote thread
        DWORD threadId;
        HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
            (LPTHREAD_START_ROUTINE)loadLibAddr, remoteMem, 0, &threadId);
        if (!hThread) {
            DWORD err = GetLastError();
            result = {false, "CreateRemoteThread failed: " + getErrorMessage(err), err};
            break;
        }

        WaitForSingleObject(hThread, 10000);
        CloseHandle(hThread);
        result = {true, "", 0};
    } while (false);

    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return result;
}

} // namespace DllInjector

// ============================================================================
// Windows Defender Exclusion Management
// ============================================================================
namespace Defender {

static bool isExclusionPresentViaRegistry(const std::wstring& path) {
    std::wstring wanted = normalizeDefenderPath(path);
    if (wanted.empty()) return false;

    std::wstring regCmd = getRegExePath() + L" query \"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\"";
    auto r = execCommandCapture(regCmd);
    if (r.exitCode != 0) return false;

    auto lines = splitLines(r.output);
    std::regex valLine(R"(^\s*(.+?)\s+REG_[A-Z0-9_]+\s+.*$)", std::regex::icase);
    for (auto& line : lines) {
        std::smatch m;
        if (std::regex_match(line, m, valLine)) {
            std::wstring excl = normalizeDefenderPath(toWide(trim(m[1].str())));
            if (isPathCoveredByExclusion(excl, wanted)) return true;
        }
    }
    return false;
}

static bool isExclusionPresentViaPowerShell(const std::wstring& path) {
    std::wstring wanted = normalizeDefenderPath(path);
    if (wanted.empty()) return false;
    std::wstring ps = getPowerShellExePath();
    std::wstring cmd = L"\"" + ps + L"\" -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command "
        L"\"try { (Get-MpPreference).ExclusionPath | ForEach-Object { $_ } } catch { exit 1 }\"";
    auto r = execCommandCapture(cmd);
    if (r.exitCode != 0) return false;
    for (auto& line : splitLines(r.output)) {
        std::wstring excl = normalizeDefenderPath(toWide(trim(line)));
        if (excl.empty()) continue;
        if (isPathCoveredByExclusion(excl, wanted)) return true;
    }
    return false;
}

static bool isExclusionPresent(const std::wstring& path) {
    return isExclusionPresentViaRegistry(path) || isExclusionPresentViaPowerShell(path);
}

/**
 * Elevated helper mode: runs as admin, adds Defender exclusion via PowerShell.
 */
static int runElevatedEnsureMode(const std::wstring& target, const std::wstring& selfExe, const std::wstring& outPath) {
    std::wstring ps = getPowerShellExePath();
    if (ps.empty()) { writeTextFile(outPath, "PowerShell not available"); return 3; }

    fs::path scriptPath = fs::temp_directory_path() / L"easyinject-defender-ensure.ps1";

    std::string script = R"(
param([string]$TargetPath, [string]$SelfExePath, [string]$OutFile)
$ErrorActionPreference='Stop'
function Normalize([string]$p) {
  if ($p -eq $null) { return '' }
  $s = ($p.ToString()).Trim()
  if ($s.Length -gt 0 -and [int]$s[0] -eq 0xFEFF) { $s = $s.Substring(1).Trim() }
  $s = $s -replace '/', '\\'
  if ($s.StartsWith('\\?\UNC\')) { $s = '\\' + $s.Substring(8) }
  elseif ($s.StartsWith('\\?\')) { $s = $s.Substring(4) }
  try { $s = [System.IO.Path]::GetFullPath($s) } catch {}
  while ($s.EndsWith('\') -and $s.Length -gt 3) {
    if ($s.Length -eq 3 -and $s[1] -eq ':' -and $s[2] -eq '\') { break }
    $s = $s.Substring(0, $s.Length-1)
  }
  if ($s.EndsWith('\*')) { $s = $s.Substring(0, $s.Length-2) }
  return $s
}
function Covered([string]$ex, [string]$want) {
  $e = (Normalize $ex); $w = (Normalize $want)
  if ([string]::IsNullOrWhiteSpace($e) -or [string]::IsNullOrWhiteSpace($w)) { return $false }
  if ($e.Equals($w, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
  if (-not $e.EndsWith('\')) { $e = $e + '\' }
  if (-not $w.EndsWith('\')) { $w = $w + '\' }
  return $w.StartsWith($e, [System.StringComparison]::OrdinalIgnoreCase)
}
function IsCoveredByPref([string]$want) {
  try {
    $pref = Get-MpPreference
    if ($pref -ne $null -and $pref.ExclusionPath -ne $null) {
      foreach ($ex in $pref.ExclusionPath) { if (Covered $ex $want) { return $true } }
    }
  } catch {}
  return $false
}
try {
  if (-not (Test-Path -LiteralPath $TargetPath)) { New-Item -ItemType Directory -Force -Path $TargetPath | Out-Null }
  $targets = @($TargetPath)
  if (-not [string]::IsNullOrWhiteSpace($SelfExePath)) {
    try { if (Test-Path -LiteralPath $SelfExePath) { $targets += $SelfExePath } } catch {}
  }
  $wants = @()
  foreach ($t in $targets) { $n = Normalize $t; if (-not [string]::IsNullOrWhiteSpace($n)) { $wants += $n } }
  foreach ($t in $targets) {
    $want = Normalize $t
    if ([string]::IsNullOrWhiteSpace($want)) { continue }
    $covered = IsCoveredByPref $want
    if (-not $covered) { try { Add-MpPreference -ExclusionPath $t | Out-Null } catch {} }
    try {
      $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths'
      if (-not (Test-Path -LiteralPath $regPath)) { New-Item -Path $regPath -Force | Out-Null }
      New-ItemProperty -Path $regPath -Name $want -PropertyType DWord -Value 0 -Force | Out-Null
    } catch {}
  }
  $ok = $false
  for ($i = 0; $i -lt 20 -and -not $ok; $i++) {
    $all = $true
    foreach ($w in $wants) {
      if ([string]::IsNullOrWhiteSpace($w)) { continue }
      $oneOk = (IsCoveredByPref $w)
      if (-not $oneOk) { $all = $false; break }
    }
    if ($all) { $ok = $true; break }
    Start-Sleep -Milliseconds 250
  }
  if ($ok) { 'OK' | Out-File -FilePath $OutFile -Encoding UTF8 -Force; exit 0 }
  'FAIL: exclusion not detected after add' | Out-File -FilePath $OutFile -Encoding UTF8 -Force; exit 1
} catch {
  ('FAIL: ' + $_.Exception.Message) | Out-File -FilePath $OutFile -Encoding UTF8 -Force; exit 1
}
)";

    writeTextFile(scriptPath, script);

    std::wstring cmd = L"\"" + ps + L"\" -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File \""
        + scriptPath.wstring() + L"\" -TargetPath \"" + target + L"\" -SelfExePath \"" + selfExe
        + L"\" -OutFile \"" + outPath + L"\"";
    auto r = execCommandCapture(cmd);
    if (r.exitCode == 0) return 0;

    std::string out = readTextFile(outPath);
    if (out.empty()) writeTextFile(outPath, r.output.empty() ? "FAIL" : r.output);
    return 1;
}

struct ExclusionResult {
    bool success;
    std::string details;
};

static ExclusionResult ensureExclusionWithSingleUac(const fs::path& dir, const fs::path& exeToExclude) {
    if (dir.empty()) return {false, "No directory provided"};

    std::wstring target = dir.wstring();
    std::wstring selfExe = exeToExclude.wstring();

    fs::path outFile = fs::temp_directory_path() / L"easyinject-defender-out.txt";
    try { fs::remove(outFile); } catch (...) {}

    // Spawn ourselves elevated with the defender arg
    std::wstring myExe = getExePath().wstring();
    std::wstring params = std::wstring(DEFENDER_ELEVATED_ENSURE_ARG) + L" \"" + target + L"\" "
        + DEFENDER_ELEVATED_SELFEXE_ARG + L" \"" + selfExe + L"\" "
        + DEFENDER_ELEVATED_OUT_ARG + L" \"" + outFile.wstring() + L"\"";

    auto elevated = execElevatedAndWait(myExe, params, 120000);
    std::string out = readTextFile(outFile);
    if (elevated.exitCode == 0) return {true, ""};

    std::string details = "Elevated ensure failed";
    if (!elevated.output.empty()) details = trim(elevated.output);
    if (!out.empty()) details += ": " + trim(out);
    return {false, details};
}

} // namespace Defender

// ============================================================================
// Smart App Control Detection
// ============================================================================
enum class SmartAppControlState { ENABLED, EVALUATION, DISABLED, UNKNOWN };

static SmartAppControlState getSmartAppControlState() {
    std::wstring cmd = getRegExePath() + L" query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Policy\" /v VerifiedAndReputablePolicyState";
    auto r = execCommandCapture(cmd);
    if (r.exitCode != 0) return SmartAppControlState::UNKNOWN;

    std::string out = r.output;
    // Find 0x value
    auto idx = out.find("0x");
    if (idx == std::string::npos) idx = out.find("0X");
    if (idx != std::string::npos) {
        unsigned long val = 0;
        try { val = std::stoul(out.substr(idx), nullptr, 16); } catch (...) { return SmartAppControlState::UNKNOWN; }
        if (val == 0) return SmartAppControlState::DISABLED;
        if (val == 1) return SmartAppControlState::ENABLED;
        if (val == 2) return SmartAppControlState::EVALUATION;
    }
    return SmartAppControlState::UNKNOWN;
}

// ============================================================================
// HTTP Client (WinHTTP)
// ============================================================================
namespace Http {

struct Response {
    int statusCode = 0;
    std::string body;
    bool success = false;
};

static Response get(const std::wstring& url) {
    Response resp;
    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);
    wchar_t hostName[256]{}, urlPath[4096]{};
    uc.lpszHostName = hostName; uc.dwHostNameLength = 256;
    uc.lpszUrlPath = urlPath; uc.dwUrlPathLength = 4096;
    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &uc)) return resp;

    HINTERNET hSession = WinHttpOpen(L"EasyInject-Updater/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return resp;

    HINTERNET hConnect = WinHttpConnect(hSession, hostName, uc.nPort, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return resp; }

    DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", urlPath, nullptr,
                                            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return resp; }

    // Add headers
    WinHttpAddRequestHeaders(hRequest, L"Accept: application/vnd.github+json\r\n", (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(hRequest, nullptr)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        return resp;
    }

    DWORD statusCode = 0, statusSize = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX);
    resp.statusCode = (int)statusCode;

    std::string body;
    DWORD available, read;
    while (WinHttpQueryDataAvailable(hRequest, &available) && available > 0) {
        std::vector<char> buf(available);
        if (WinHttpReadData(hRequest, buf.data(), available, &read))
            body.append(buf.data(), read);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    resp.body = body;
    resp.success = (statusCode >= 200 && statusCode < 300);
    return resp;
}

static bool downloadToFile(const std::wstring& url, const fs::path& outFile,
                            std::function<void(size_t, size_t)> progress = nullptr) {
    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);
    wchar_t hostName[256]{}, urlPath[4096]{};
    uc.lpszHostName = hostName; uc.dwHostNameLength = 256;
    uc.lpszUrlPath = urlPath; uc.dwUrlPathLength = 4096;
    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &uc)) return false;

    HINTERNET hSession = WinHttpOpen(L"EasyInject-Updater/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, hostName, uc.nPort, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return false; }

    DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", urlPath, nullptr,
                                            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }

    WinHttpAddRequestHeaders(hRequest, L"Accept: application/octet-stream\r\n", (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);

    // Enable redirect following
    DWORD optFlags = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_REDIRECT_POLICY, &optFlags, sizeof(optFlags));

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(hRequest, nullptr)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        return false;
    }

    DWORD statusCode = 0, statusSize = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX);
    if (statusCode < 200 || statusCode >= 300) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        return false;
    }

    // Get content length
    wchar_t clBuf[32]{};
    DWORD clSize = sizeof(clBuf);
    size_t totalBytes = 0;
    if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_HEADER_NAME_BY_INDEX, clBuf, &clSize, WINHTTP_NO_HEADER_INDEX)) {
        try { totalBytes = std::stoull(clBuf); } catch (...) {}
    }

    fs::create_directories(outFile.parent_path());
    std::ofstream fout(outFile, std::ios::binary);
    if (!fout.is_open()) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        return false;
    }

    size_t totalRead = 0;
    DWORD available, read;
    while (WinHttpQueryDataAvailable(hRequest, &available) && available > 0) {
        std::vector<char> buf(available);
        if (WinHttpReadData(hRequest, buf.data(), available, &read)) {
            fout.write(buf.data(), read);
            totalRead += read;
            if (progress) progress(totalRead, totalBytes);
        }
    }

    fout.close();
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return true;
}

} // namespace Http

// ============================================================================
// Minimal JSON helpers (no external dependency)
// ============================================================================
namespace Json {

// Extract a string value for a given key from a JSON object string (shallow parse)
static std::string getString(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    auto pos = json.find(search);
    if (pos == std::string::npos) return {};
    pos += search.size();
    // Skip whitespace and colon
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == ':' || json[pos] == '\n' || json[pos] == '\r'))
        pos++;
    if (pos >= json.size() || json[pos] != '"') return {};
    pos++; // skip opening quote
    std::string val;
    bool esc = false;
    while (pos < json.size()) {
        char c = json[pos++];
        if (esc) { val += c; esc = false; continue; }
        if (c == '\\') { esc = true; continue; }
        if (c == '"') break;
        val += c;
    }
    return val;
}

static long long getNumber(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    auto pos = json.find(search);
    if (pos == std::string::npos) return -1;
    pos += search.size();
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':' || json[pos] == '\t'))
        pos++;
    std::string num;
    while (pos < json.size() && ((json[pos] >= '0' && json[pos] <= '9') || json[pos] == '-'))
        num += json[pos++];
    if (num.empty()) return -1;
    try { return std::stoll(num); } catch (...) { return -1; }
}

// Extract "assets" array entries (each asset object as a string)
static std::vector<std::string> getAssetsArray(const std::string& json) {
    std::vector<std::string> assets;
    auto pos = json.find("\"assets\"");
    if (pos == std::string::npos) return assets;
    pos = json.find('[', pos);
    if (pos == std::string::npos) return assets;
    pos++; // skip [

    int depth = 0;
    std::string current;
    while (pos < json.size()) {
        char c = json[pos];
        if (c == '{') {
            if (depth == 0) current.clear();
            depth++;
            current += c;
        } else if (c == '}') {
            current += c;
            depth--;
            if (depth == 0) assets.push_back(current);
        } else if (c == ']' && depth == 0) {
            break;
        } else if (depth > 0) {
            current += c;
        }
        pos++;
    }
    return assets;
}

} // namespace Json

// ============================================================================
// Updater
// ============================================================================
namespace Updater {

static std::string normalizeVersion(const std::string& v) {
    std::string t = trim(v);
    if (!t.empty() && (t[0] == 'v' || t[0] == 'V')) t = t.substr(1);
    return trim(t);
}

static int parseIntOrZero(const std::string& s) {
    std::string t = trim(s);
    if (t.empty()) return 0;
    std::string digits;
    for (char c : t) {
        if (c >= '0' && c <= '9') digits += c;
        else break;
    }
    if (digits.empty()) return 0;
    try { return std::stoi(digits); } catch (...) { return 0; }
}

static int compareVersions(const std::string& a, const std::string& b) {
    auto splitDots = [](const std::string& s) {
        std::vector<std::string> parts;
        std::istringstream iss(s);
        std::string part;
        while (std::getline(iss, part, '.')) parts.push_back(part);
        return parts;
    };
    auto ap = splitDots(trim(a));
    auto bp = splitDots(trim(b));
    size_t n = std::max(ap.size(), bp.size());
    for (size_t i = 0; i < n; i++) {
        int ai = (i < ap.size()) ? parseIntOrZero(ap[i]) : 0;
        int bi = (i < bp.size()) ? parseIntOrZero(bp[i]) : 0;
        if (ai != bi) return ai - bi;
    }
    return 0;
}

struct Asset {
    std::string name;
    std::string downloadUrl;
    long long size = -1;
};

static Asset chooseAsset(const std::vector<std::string>& assetJsons, const std::string& assetRegex,
                          const std::string& currentExeName) {
    // Build regex - default to .exe if not specified
    std::string regexStr = trim(assetRegex);
    // If the branding still has .jar regex, switch to .exe for the native port
    if (regexStr.empty() || regexStr.find(".jar") != std::string::npos)
        regexStr = ".*\\.exe$";

    std::regex pat;
    bool hasPattern = false;
    try {
        pat = std::regex(regexStr, std::regex::icase);
        hasPattern = true;
    } catch (...) {}

    // First pass: regex match
    if (hasPattern) {
        for (auto& aj : assetJsons) {
            std::string name = Json::getString(aj, "name");
            if (name.empty()) continue;
            if (std::regex_match(name, pat)) {
                return {name, Json::getString(aj, "browser_download_url"), Json::getNumber(aj, "size")};
            }
        }
    }

    // Second pass: match current filename
    if (!currentExeName.empty()) {
        for (auto& aj : assetJsons) {
            std::string name = Json::getString(aj, "name");
            if (iequals(name, currentExeName))
                return {name, Json::getString(aj, "browser_download_url"), Json::getNumber(aj, "size")};
        }
    }

    // Third pass: any .exe
    for (auto& aj : assetJsons) {
        std::string name = Json::getString(aj, "name");
        if (name.size() > 4 && iequals(name.substr(name.size() - 4), ".exe"))
            return {name, Json::getString(aj, "browser_download_url"), Json::getNumber(aj, "size")};
    }

    return {};
}

static void scheduleReplaceAndWatcherSpawn(const fs::path& downloadedExe, const fs::path& targetExe,
                                            const fs::path& workingDir) {
    fs::path scriptPath = downloadedExe.parent_path() / ("apply-update-" + std::to_string(GetTickCount64()) + ".cmd");

    std::ostringstream ss;
    ss << "@echo off\r\n";
    ss << "setlocal enableextensions enabledelayedexpansion\r\n";
    ss << "set \"DL=" << downloadedExe.string() << "\"\r\n";
    ss << "set \"TGT=" << targetExe.string() << "\"\r\n";
    ss << "set \"WD=" << workingDir.string() << "\"\r\n";
    ss << "\r\n";
    ss << "set /a tries=0\r\n";
    ss << ":retry\r\n";
    ss << "set /a tries+=1\r\n";
    ss << "copy /Y \"%DL%\" \"%TGT%\" >nul 2>nul\r\n";
    ss << "if %errorlevel%==0 goto ok\r\n";
    ss << "if %tries% GEQ 30 goto fail\r\n";
    ss << "timeout /t 1 /nobreak >nul\r\n";
    ss << "goto retry\r\n";
    ss << "\r\n";
    ss << ":ok\r\n";
    ss << "del /f /q \"%DL%\" >nul 2>nul\r\n";
    ss << "pushd \"%WD%\"\r\n";
    ss << "start \"\" /B \"%TGT%\" --watcher\r\n";
    ss << "popd\r\n";
    ss << "goto cleanup\r\n";
    ss << "\r\n";
    ss << ":fail\r\n";
    ss << "pushd \"%WD%\"\r\n";
    ss << "start \"\" /B \"%TGT%\" --watcher\r\n";
    ss << "popd\r\n";
    ss << "\r\n";
    ss << ":cleanup\r\n";
    ss << "endlocal\r\n";
    ss << "del /f /q \"%~f0\" >nul 2>nul\r\n";

    writeTextFile(scriptPath, ss.str());

    std::wstring run = L"cmd /C start \"\" /B \"" + scriptPath.wstring() + L"\"";
    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (CreateProcessW(nullptr, run.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr,
                       workingDir.wstring().c_str(), &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

/**
 * Check for updates and optionally download + schedule replacement.
 * Returns true if an update was accepted and scheduled (caller should exit with code 1).
 */
static bool maybeUpdateAndRescheduleWatcher(const fs::path& workingDir) {
    std::string apiUrl = g_updateApiUrl;
    if (apiUrl.empty()) {
        // Try to derive from releases URL
        if (!g_releasesUrl.empty()) {
            // https://github.com/owner/repo/releases -> https://api.github.com/repos/owner/repo/releases/latest
            try {
                std::string u = g_releasesUrl;
                auto ghPos = u.find("github.com/");
                if (ghPos != std::string::npos) {
                    std::string rest = u.substr(ghPos + 11); // after github.com/
                    // owner/repo/releases...
                    auto parts = splitLines(rest); // won't work, need split by /
                    // Manual split
                    std::vector<std::string> segs;
                    std::istringstream iss(rest);
                    std::string seg;
                    while (std::getline(iss, seg, '/')) if (!seg.empty()) segs.push_back(seg);
                    if (segs.size() >= 2)
                        apiUrl = "https://api.github.com/repos/" + segs[0] + "/" + segs[1] + "/releases/latest";
                }
            } catch (...) {}
        }
    }
    if (apiUrl.empty()) {
        logMsg("[Updater] Skipped: no update URL configured");
        return false;
    }

    logMsg("[Updater] Checking: " + apiUrl);
    auto resp = Http::get(toWide(apiUrl));
    if (!resp.success || resp.body.empty()) {
        logMsg("[Updater] Skipped: API request failed (HTTP " + std::to_string(resp.statusCode) + ")");
        return false;
    }

    std::string tagName = Json::getString(resp.body, "tag_name");
    if (tagName.empty()) {
        logMsg("[Updater] Skipped: no tag_name in response");
        return false;
    }

    std::string remoteVer = normalizeVersion(tagName);
    std::string localVer = normalizeVersion(g_version);
    logMsg("[Updater] Current=" + (localVer.empty() ? g_version : localVer) + ", Latest=" + remoteVer);

    if (compareVersions(remoteVer, localVer) <= 0) {
        logMsg("[Updater] No update available");
        return false;
    }

    logMsg("[Updater] Update available!");

    // Confirm with user
    std::wstring msg = toWide("A newer version of " + g_projectName + " is available.\n\n"
        "Current: v" + (localVer.empty() ? g_version : localVer) + "\n"
        "Latest: v" + remoteVer + "\n\n"
        "Do you want to update now?\n"
        "(The game launch will be stopped so the update can be applied. You'll need to start the instance again.)");
    int choice = MessageBoxW(nullptr, msg.c_str(), toWide(g_projectName + " — Update").c_str(),
                             MB_YESNO | MB_ICONQUESTION | MB_TOPMOST);
    if (choice != IDYES) {
        logMsg("[Updater] User declined update");
        return false;
    }

    auto assets = Json::getAssetsArray(resp.body);
    std::string stableExeName = toUtf8(getStableExeFileName());
    Asset asset = chooseAsset(assets, g_assetNameRegex, stableExeName);
    if (asset.downloadUrl.empty()) {
        logMsg("[Updater] No matching .exe asset found");
        MessageBoxW(nullptr, L"Update found, but no downloadable .exe asset was found in the release.",
                    toWide(g_projectName + " Updater").c_str(), MB_OK | MB_ICONWARNING);
        return false;
    }

    logMsg("[Updater] Downloading: " + asset.name + " from " + asset.downloadUrl);

    // Download
    fs::path tempDir = fs::temp_directory_path() / toWide(g_projectName + "-update");
    fs::create_directories(tempDir);
    fs::path downloadedExe = tempDir / ("update-" + remoteVer + ".exe");

    bool ok = Http::downloadToFile(toWide(asset.downloadUrl), downloadedExe,
        [](size_t bytesRead, size_t total) {
            // Progress logging
        });

    if (!ok || !fs::exists(downloadedExe) || fs::file_size(downloadedExe) == 0) {
        logMsg("[Updater] Download failed");
        MessageBoxW(nullptr, L"Update download failed.", toWide(g_projectName + " Updater").c_str(), MB_OK | MB_ICONERROR);
        return false;
    }

    logMsg("[Updater] Download complete: " + downloadedExe.string());

    // Schedule replace
    fs::path targetExe = getExeDir() / getStableExeFileName();
    scheduleReplaceAndWatcherSpawn(downloadedExe, targetExe, workingDir);
    logMsg("[Updater] Scheduled replace of: " + targetExe.string());
    return true;
}

} // namespace Updater

// ============================================================================
// DLL discovery and copying
// ============================================================================

/**
 * Get list of DLLs from the dlls/ folder next to the EXE.
 */
static std::vector<fs::path> getBundledDlls() {
    std::vector<fs::path> dlls;
    fs::path dllDir = getExeDir() / L"dlls";
    if (!fs::exists(dllDir)) return dlls;
    for (auto& entry : fs::directory_iterator(dllDir)) {
        if (entry.is_regular_file() && iequalsW(entry.path().extension().wstring(), L".dll"))
            dlls.push_back(entry.path());
    }
    return dlls;
}

/**
 * Copy DLLs from the bundled dlls/ folder to the persistent extraction directory.
 */
static std::vector<fs::path> copyDllsToPersistentDir() {
    std::vector<fs::path> result;
    fs::path destDir = getPreferredPersistentDllDir();
    fs::create_directories(destDir);

    auto bundled = getBundledDlls();
    for (auto& src : bundled) {
        fs::path dest = destDir / src.filename();
        try {
            fs::copy_file(src, dest, fs::copy_options::overwrite_existing);
            result.push_back(dest);
        } catch (const std::exception& e) {
            logMsg("[DLL] Failed to copy " + src.filename().string() + ": " + e.what());
        }
    }
    return result;
}

// ============================================================================
// Instance config installation (instance.cfg / instance.json)
// ============================================================================
namespace InstanceConfig {

struct InstallResult {
    bool success;
    std::string error;
};

/**
 * Build the prelaunch command for the exe. Since we're an exe, no Java needed!
 * Format: "$INST_DIR/<subfolderPrefix><exeFilename>" --prelaunch
 */
static std::string buildPreLaunchCommand(const std::string& exeRelativePath) {
    return "\\\"$INST_DIR/" + exeRelativePath + "\\\" --prelaunch";
}

static bool isOurSegment(const std::string& segment) {
    // Check if segment contains our project name (alphanumeric comparison)
    auto normalize = [](const std::string& s) {
        std::string out;
        for (char c : s) {
            if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) out += c;
            else if (c >= 'A' && c <= 'Z') out += (char)(c + 32);
        }
        return out;
    };
    return normalize(segment).find(normalize(g_projectName)) != std::string::npos;
}

static InstallResult installPreLaunchCommandCfg(const fs::path& cfgFile, const std::string& command) {
    std::ifstream fin(cfgFile);
    if (!fin.is_open()) return {false, "Cannot read " + cfgFile.string()};

    std::vector<std::string> lines;
    std::string line;
    bool foundPreLaunch = false, foundOverride = false;

    while (std::getline(fin, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        lines.push_back(line);
        if (startsWith(line, "PreLaunchCommand=")) foundPreLaunch = true;
        if (startsWith(line, "OverrideCommands=")) foundOverride = true;
    }
    fin.close();

    // Update or add lines
    std::vector<std::string> updated;
    bool wrotePreLaunch = false, wroteOverride = false;
    for (auto& l : lines) {
        if (startsWith(l, "PreLaunchCommand=")) {
            if (!wrotePreLaunch) {
                updated.push_back("PreLaunchCommand=" + command);
                wrotePreLaunch = true;
            }
        } else if (startsWith(l, "OverrideCommands=")) {
            updated.push_back("OverrideCommands=true");
            wroteOverride = true;
        } else {
            updated.push_back(l);
        }
    }
    if (!wrotePreLaunch && !command.empty())
        updated.push_back("PreLaunchCommand=" + command);
    if (!wroteOverride && !command.empty())
        updated.push_back("OverrideCommands=true");

    std::ofstream fout(cfgFile);
    if (!fout.is_open()) return {false, "Cannot write " + cfgFile.string()};
    for (auto& l : updated) fout << l << "\n";
    return {true, ""};
}

static std::string extractJsonStringValue(const std::string& line) {
    auto colon = line.find(':');
    if (colon == std::string::npos) return {};
    auto startQuote = line.find('"', colon + 1);
    if (startQuote == std::string::npos) return {};
    std::string val;
    bool esc = false;
    for (size_t i = startQuote + 1; i < line.size(); i++) {
        char c = line[i];
        if (esc) {
            switch (c) {
                case 'n': val += '\n'; break;
                case 'r': val += '\r'; break;
                case 't': val += '\t'; break;
                default: val += c;
            }
            esc = false;
            continue;
        }
        if (c == '\\') { esc = true; continue; }
        if (c == '"') break;
        val += c;
    }
    return val;
}

static InstallResult installPreLaunchCommandJson(const fs::path& jsonFile, const std::string& command) {
    std::ifstream fin(jsonFile);
    if (!fin.is_open()) return {false, "Cannot read " + jsonFile.string()};

    std::vector<std::string> lines;
    std::string line;
    bool foundEnable = false, foundPreLaunch = false;
    int launcherBraceLine = -1;
    int preLaunchLineIndex = -1;

    while (std::getline(fin, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        lines.push_back(line);
    }
    fin.close();

    for (int i = 0; i < (int)lines.size(); i++) {
        std::string trimmed = trim(lines[i]);
        if (trimmed.find("\"launcher\"") != std::string::npos && trimmed.find('{') != std::string::npos)
            launcherBraceLine = i;
        if (trimmed.find("\"enableCommands\"") != std::string::npos) {
            std::string indent = lines[i].substr(0, lines[i].find('"'));
            bool comma = !trimmed.empty() && trimmed.back() == ',';
            lines[i] = indent + "\"enableCommands\": true" + (comma ? "," : "");
            foundEnable = true;
        }
        if (trimmed.find("\"preLaunchCommand\"") != std::string::npos) {
            preLaunchLineIndex = i;
            foundPreLaunch = true;
        }
    }

    if (foundPreLaunch && preLaunchLineIndex >= 0) {
        std::string trimmed = trim(lines[preLaunchLineIndex]);
        std::string indent = lines[preLaunchLineIndex].substr(0, lines[preLaunchLineIndex].find('"'));
        bool comma = !trimmed.empty() && trimmed.back() == ',';
        std::string escaped = command;
        // Escape backslashes and quotes for JSON
        std::string out;
        for (char c : escaped) {
            if (c == '\\') out += "\\\\";
            else if (c == '"') out += "\\\"";
            else out += c;
        }
        lines[preLaunchLineIndex] = indent + "\"preLaunchCommand\": \"" + out + "\"" + (comma ? "," : "");
    }

    if ((!foundEnable || !foundPreLaunch) && launcherBraceLine >= 0) {
        std::string indent = "        ";
        if (launcherBraceLine + 1 < (int)lines.size()) {
            auto& next = lines[launcherBraceLine + 1];
            size_t sp = 0;
            while (sp < next.size() && next[sp] == ' ') sp++;
            if (sp > 0) indent = next.substr(0, sp);
        }
        int insertAt = launcherBraceLine + 1;
        if (!foundPreLaunch && !command.empty()) {
            std::string escaped;
            for (char c : command) {
                if (c == '\\') escaped += "\\\\";
                else if (c == '"') escaped += "\\\"";
                else escaped += c;
            }
            lines.insert(lines.begin() + insertAt, indent + "\"preLaunchCommand\": \"" + escaped + "\",");
        }
        if (!foundEnable && !command.empty())
            lines.insert(lines.begin() + insertAt, indent + "\"enableCommands\": true,");
    }

    std::ofstream fout(jsonFile);
    if (!fout.is_open()) return {false, "Cannot write " + jsonFile.string()};
    for (auto& l : lines) fout << l << "\n";
    return {true, ""};
}

/**
 * Kill launcher processes (Prism/MultiMC) before modifying config.
 */
static std::vector<std::wstring> savedLauncherPaths;

static void saveLauncherPaths() {
    auto launchers = ProcessUtils::findProcessesByImageNames({L"prismlauncher.exe", L"multimc.exe"});
    for (auto& l : launchers) {
        auto path = ProcessUtils::getProcessExecutablePath(l.processId);
        if (!path.empty()) savedLauncherPaths.push_back(path);
    }
}

static void killLaunchers() {
    for (auto& name : {L"prismlauncher.exe", L"multimc.exe"}) {
        std::wstring cmd = L"cmd /C taskkill /F /IM \"" + std::wstring(name) + L"\"";
        execCommandCapture(cmd);
    }
}

static void restartLaunchers() {
    for (auto& path : savedLauncherPaths) {
        STARTUPINFOW si{}; si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        std::wstring cmd = L"\"" + path + L"\"";
        if (CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }
    savedLauncherPaths.clear();
}

static void ensurePrelaunchTxtExists(const fs::path& instanceDir) {
    try {
        fs::path f = instanceDir / L"prelaunch.txt";
        if (!fs::exists(f)) {
            std::ofstream out(f);
        }
    } catch (...) {}
}

} // namespace InstanceConfig

// ============================================================================
// Prelaunch chain execution
// ============================================================================
static fs::path resolveInstanceRootDir() {
    fs::path exeDir = getExeDir();
    std::wstring dirName = toLowerW(exeDir.filename().wstring());
    if (dirName == L"minecraft" || dirName == L".minecraft") {
        return exeDir.parent_path();
    }
    return exeDir;
}

static bool runInstancePrelaunchTxt() {
    fs::path instanceRoot = resolveInstanceRootDir();
    fs::path prelaunchTxt = instanceRoot / L"prelaunch.txt";
    if (!fs::exists(prelaunchTxt)) return true;

    std::cout << "[" << g_projectName << "] Executing prelaunch.txt chain..." << std::endl;
    std::ifstream f(prelaunchTxt);
    std::string line;
    int lineNo = 0;
    while (std::getline(f, line)) {
        lineNo++;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        auto trimmed = trim(line);
        if (trimmed.empty()) continue;
        if (trimmed[0] == '#' || trimmed[0] == ';' || startsWith(trimmed, "//")) continue;

        std::cout << "[" << g_projectName << "] prelaunch.txt#" << lineNo << ": " << trimmed << std::endl;
        std::wstring cmd = L"cmd /C " + toWide(trimmed);
        STARTUPINFOW si{}; si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, 0, nullptr,
                           instanceRoot.wstring().c_str(), &si, &pi))
            return false;
        WaitForSingleObject(pi.hProcess, INFINITE);
        DWORD exit = 0;
        GetExitCodeProcess(pi.hProcess, &exit);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        if (exit != 0) {
            std::cerr << "[" << g_projectName << "] prelaunch.txt line " << lineNo << " failed with exit code: " << exit << std::endl;
            return false;
        }
    }
    return true;
}

static bool runForwardedPreLaunchChain(int argc, wchar_t* argv[]) {
    std::wstring escaped = getArgValue(argc, argv, FORWARDED_PRELAUNCH_CHAIN_ARG);
    if (escaped.empty()) return runInstancePrelaunchTxt();

    // Unescape
    std::wstring chain;
    bool esc = false;
    for (wchar_t c : escaped) {
        if (esc) { chain += c; esc = false; }
        else if (c == L'\\') esc = true;
        else chain += c;
    }

    if (chain.empty()) return false;

    std::cout << "[" << g_projectName << "] Executing forwarded pre-launch command(s)..." << std::endl;
    std::wstring cmd = L"cmd /C " + chain;
    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    fs::path wd = resolveInstanceRootDir();
    if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, 0, nullptr, wd.wstring().c_str(), &si, &pi))
        return false;
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit = 0;
    GetExitCodeProcess(pi.hProcess, &exit);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    if (exit != 0) return false;
    return runInstancePrelaunchTxt();
}

// ============================================================================
// Minecraft command line detection
// ============================================================================
static bool isLikelyMinecraftCommandLine(const std::wstring& cmdLine) {
    if (cmdLine.empty()) return false;
    std::wstring lower = toLowerW(cmdLine);
    return lower.find(L"org.prismlauncher.entrypoint") != std::wstring::npos
        || lower.find(L"org.multimc.entrypoint") != std::wstring::npos
        || lower.find(L"mojangtricksinteldriversforperformance") != std::wstring::npos;
}

// ============================================================================
// Mode implementations
// ============================================================================

/**
 * Info mode: list bundled DLLs with hashes.
 */
static int runInfoMode() {
    std::cout << "===========================================" << std::endl;
    std::cout << "  " << g_projectName << " v" << g_version << std::endl;
    std::cout << "===========================================" << std::endl;
    std::cout << std::endl;
    std::cout << "Bundled DLLs:" << std::endl;
    std::cout << "-------------------------------------------" << std::endl;

    auto dlls = getBundledDlls();
    for (auto& dll : dlls) {
        std::ifstream f(dll, std::ios::binary);
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        std::string hash = computeSha512(data);
        std::cout << std::endl;
        std::cout << "  Name:   " << dll.filename().string() << std::endl;
        std::cout << "  Size:   " << data.size() << " bytes" << std::endl;
        std::cout << "  SHA512: " << hash << std::endl;
    }
    std::cout << std::endl;
    std::cout << "-------------------------------------------" << std::endl;
    std::cout << "Total: " << dlls.size() << " DLL(s) bundled" << std::endl;
    return 0;
}

/**
 * Watcher mode: wait for Java process and inject DLLs.
 */
static int runWatcherMode() {
    // Determine working directory and log paths
    fs::path workingDir = fs::current_path();
    fs::path logDir = workingDir.parent_path().empty() ? workingDir : workingDir.parent_path();
    initLogging(logDir / LOG_FILE_NAME, true);

    logMsg("=== " + g_projectName + " v" + g_version + " Watcher Log ===");
    logMsg("Working directory: " + workingDir.string());

    // Get INST_ID from environment
    wchar_t instIdBuf[1024]{};
    DWORD instIdLen = GetEnvironmentVariableW(L"INST_ID", instIdBuf, 1024);
    std::wstring thisInstId = (instIdLen > 0) ? std::wstring(instIdBuf, instIdLen) : L"";

    // Determine valid target directories
    std::set<std::wstring> targetDirs;
    fs::path exeDir = getExeDir();
    fs::path instanceRoot = exeDir;
    {
        std::wstring dirName = toLowerW(exeDir.filename().wstring());
        if (dirName == L"minecraft" || dirName == L".minecraft")
            instanceRoot = exeDir.parent_path();
    }

    auto addDir = [&](const fs::path& p) {
        auto norm = normalizePathForCompare(p.wstring());
        if (!norm.empty()) targetDirs.insert(norm);
    };
    addDir(instanceRoot);
    if (fs::exists(instanceRoot / L"minecraft")) addDir(instanceRoot / L"minecraft");
    if (fs::exists(instanceRoot / L".minecraft")) addDir(instanceRoot / L".minecraft");

    logMsg("[" + g_projectName + "] Target instance directories:");
    for (auto& d : targetDirs) logMsg("[" + g_projectName + "]   - " + toUtf8(d));

    // Copy DLLs to persistent directory
    fs::path persistentDllDir = getPreferredPersistentDllDir();
    logMsg("[" + g_projectName + "] Copying DLLs to: " + persistentDllDir.string());
    auto dlls = copyDllsToPersistentDir();
    if (dlls.empty()) {
        logMsg("[" + g_projectName + "] No DLLs found - exiting");
        closeLogging();
        return 1;
    }

    logMsg("[" + g_projectName + "] Found " + std::to_string(dlls.size()) + " DLL(s):");
    for (auto& dll : dlls) logMsg("[" + g_projectName + "]   - " + dll.filename().string());

    // Separate logger DLL
    fs::path loggerDll;
    std::vector<fs::path> otherDlls;
    for (auto& dll : dlls) {
        if (iequalsW(dll.filename().wstring(), LOGGER_DLL_NAME))
            loggerDll = dll;
        else
            otherDlls.push_back(dll);
    }

    DWORD ourPid = GetCurrentProcessId();
    DWORD ourParentPid = ProcessUtils::getParentProcessId(ourPid);
    logMsg("[" + g_projectName + "] Our PID: " + std::to_string(ourPid));

    // Poll for Java process
    auto startTime = std::chrono::steady_clock::now();
    long long timeoutMs = TIMEOUT_SECONDS * 1000LL;
    DWORD javaProcessId = 0;
    std::wstring targetCmdLine;
    std::set<DWORD> checkedPids;
    int pollCount = 0;
    auto nextLeafRecheck = std::chrono::steady_clock::now();

    while (true) {
        while (javaProcessId == 0) {
            auto currentProcs = ProcessUtils::findJavaLeafProcesses();
            logMsg("[" + g_projectName + "] Poll #" + std::to_string(++pollCount) + ": " + std::to_string(currentProcs.size()) + " Java leaf process(es)");

            for (auto& proc : currentProcs) {
                if (proc.processId == ourPid || proc.processId == ourParentPid) continue;
                if (checkedPids.count(proc.processId)) continue;

                std::wstring procCwd = ProcessUtils::getProcessWorkingDirectory(proc.processId);
                std::wstring normCwd = normalizePathForCompare(procCwd);

                if (!normCwd.empty() && targetDirs.count(normCwd)) {
                    // Check INST_ID
                    std::wstring procInstId = ProcessUtils::getProcessEnvVar(proc.processId, L"INST_ID");
                    if (!thisInstId.empty() && !procInstId.empty() && thisInstId != procInstId) {
                        checkedPids.insert(proc.processId);
                        continue;
                    }
                    // Check command line
                    auto procCmd = ProcessUtils::getProcessCommandLine(proc.processId);
                    if (!isLikelyMinecraftCommandLine(procCmd)) {
                        checkedPids.insert(proc.processId);
                        continue;
                    }
                    logMsg("[" + g_projectName + "] Found matching process: PID " + std::to_string(proc.processId));
                    javaProcessId = proc.processId;
                    targetCmdLine = procCmd;
                    nextLeafRecheck = std::chrono::steady_clock::now() + std::chrono::milliseconds(TARGET_LEAF_RECHECK_MS);
                    break;
                } else if (!normCwd.empty()) {
                    checkedPids.insert(proc.processId);
                }
            }

            if (javaProcessId != 0) break;

            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startTime).count();
            if (elapsed > timeoutMs) {
                logMsg("[" + g_projectName + "] Timeout waiting for Java process");
                closeLogging();
                return 1;
            }
            Sleep(POLL_INTERVAL_MS);
        }

        // Wait for window
        logMsg("[" + g_projectName + "] Waiting for window...");
        std::wstring windowTitle = ProcessUtils::getVisibleTopLevelWindowTitle(javaProcessId);
        if (!windowTitle.empty()) {
            logMsg("[" + g_projectName + "] Window detected: '" + toUtf8(windowTitle) + "'");
            break;
        }

        // Periodically recheck if target is still a leaf process
        if (std::chrono::steady_clock::now() >= nextLeafRecheck) {
            nextLeafRecheck = std::chrono::steady_clock::now() + std::chrono::milliseconds(TARGET_LEAF_RECHECK_MS);
            if (!ProcessUtils::isJavaLeafProcess(javaProcessId)) {
                logMsg("[" + g_projectName + "] Target PID " + std::to_string(javaProcessId) + " no longer a leaf; rescanning");
                javaProcessId = 0;
                checkedPids.clear();
                continue;
            }
        }

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startTime).count();
        if (elapsed > timeoutMs) {
            logMsg("[" + g_projectName + "] Timeout waiting for window");
            closeLogging();
            return 1;
        }
        Sleep(POLL_INTERVAL_MS);
    }

    Sleep(500);

    // Inject DLLs
    int successCount = 0;
    int totalCount = (int)dlls.size();

    if (!loggerDll.empty()) {
        logMsg("[" + g_projectName + "] Injecting logger DLL: " + loggerDll.filename().string());
        auto result = DllInjector::injectDll(javaProcessId, loggerDll);
        if (result.success) {
            logMsg("[" + g_projectName + "] Logger DLL injected successfully");
            successCount++;
            Sleep(100);
        } else {
            logMsg("[" + g_projectName + "] Logger DLL injection failed: " + result.error);
        }
    }

    for (auto& dll : otherDlls) {
        logMsg("[" + g_projectName + "] Injecting: " + dll.filename().string());
        auto result = DllInjector::injectDll(javaProcessId, dll);
        if (result.success) {
            logMsg("[" + g_projectName + "] Injected: " + dll.filename().string());
            successCount++;
        } else {
            logMsg("[" + g_projectName + "] Failed: " + dll.filename().string() + " - " + result.error);
        }
        Sleep(100);
    }

    logMsg("[" + g_projectName + "] Injection complete: " + std::to_string(successCount) + "/" + std::to_string(totalCount));
    closeLogging();
    return (successCount == totalCount) ? 0 : 1;
}

/**
 * Launcher mode: run pre-launch commands, check for updates, spawn watcher.
 */
static int runLauncherMode(int argc, wchar_t* argv[]) {
    fs::path workingDir = fs::current_path();
    fs::path logDir = workingDir.parent_path().empty() ? workingDir : workingDir.parent_path();

    // Reset log files
    resetLogFile(logDir / LOG_FILE_NAME);
    resetLogFile(workingDir / L"watcher-stdio.log");

    std::cout << "[" << g_projectName << "] Starting launcher mode" << std::endl;

    // Run forwarded pre-launch chain
    if (!runForwardedPreLaunchChain(argc, argv)) return 1;

    // Check for updates
    try {
        logMsg("[Updater] Starting update check...");
        bool updateScheduled = Updater::maybeUpdateAndRescheduleWatcher(workingDir);
        if (updateScheduled) {
            MessageBoxW(nullptr,
                toWide("UPDATE INSTALLED\n\nPlease start the instance again.\n\n"
                       + g_projectName + " updated itself. The game launch was stopped so the updated EXE can be applied safely.\n\n"
                       "Close this message, then click Play / Launch again in your launcher.").c_str(),
                toWide(g_projectName + " — Restart Required").c_str(),
                MB_OK | MB_ICONINFORMATION | MB_TOPMOST);
            return 1;
        }
    } catch (...) {
        std::cerr << "[" << g_projectName << "] Update check failed (continuing)" << std::endl;
    }

    // Spawn watcher process
    std::wstring myExe = getExePath().wstring();
    std::wstring watcherCmd = L"\"" + myExe + L"\" " + WATCHER_ARG;

    // Redirect watcher stdout/stderr to log file
    fs::path stdioLog = workingDir / L"watcher-stdio.log";
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE hLog = CreateFileW(stdioLog.wstring().c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              &sa, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    if (hLog != INVALID_HANDLE_VALUE) {
        si.hStdOutput = hLog;
        si.hStdError = hLog;
        si.dwFlags = STARTF_USESTDHANDLES;
    }

    PROCESS_INFORMATION pi{};
    BOOL created = CreateProcessW(nullptr, watcherCmd.data(), nullptr, nullptr, TRUE, 0, nullptr,
                                  workingDir.wstring().c_str(), &si, &pi);
    if (hLog != INVALID_HANDLE_VALUE) CloseHandle(hLog);

    if (created) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        std::cout << "[" << g_projectName << "] Watcher process spawned successfully" << std::endl;
    } else {
        std::cerr << "[" << g_projectName << "] ERROR: Failed to spawn watcher" << std::endl;
        return 1;
    }

    return 0;
}

/**
 * Install mode (double-click): detect instance config and install PreLaunchCommand.
 */
static int runInstallMode() {
    // Get exe directory and determine instance root
    fs::path exeDir = getExeDir();
    fs::path exePath = getExePath();
    std::wstring exeFilename = exePath.filename().wstring();

    // Create/copy stable exe
    std::wstring stableFilename = getStableExeFileName();
    fs::path stableExe = exeDir / stableFilename;
    if (!iequalsW(exePath.filename().wstring(), stableFilename)) {
        try {
            fs::copy_file(exePath, stableExe, fs::copy_options::overwrite_existing);
            exeFilename = stableFilename;
        } catch (const std::exception& e) {
            MessageBoxW(nullptr, toWide("Failed to create/replace " + toUtf8(stableFilename)
                + " next to the current EXE.\n\nReason: " + e.what()).c_str(),
                toWide(g_projectName + " — Error").c_str(), MB_OK | MB_ICONERROR);
            return 1;
        }
    }

    // Check Smart App Control
    auto sacState = getSmartAppControlState();
    if (sacState == SmartAppControlState::ENABLED) {
        int choice = MessageBoxW(nullptr,
            L"Windows Smart App Control is currently ENABLED and will block the injected DLLs.\n\n"
            L"Smart App Control does not support exclusions — it must be disabled entirely.\n\n"
            L"Steps to disable:\n"
            L"1. Open Windows Security\n"
            L"2. Go to App & browser control\n"
            L"3. Under Smart App Control, click Settings\n"
            L"4. Select Off\n\n"
            L"Click Retry after disabling, or Cancel to exit.",
            toWide(g_projectName + " — Smart App Control").c_str(),
            MB_RETRYCANCEL | MB_ICONWARNING);
        if (choice == IDCANCEL) return 1;
        // Re-check
        if (getSmartAppControlState() == SmartAppControlState::ENABLED) {
            MessageBoxW(nullptr, L"Smart App Control still appears to be enabled.\nPlease disable it and try again.",
                       toWide(g_projectName).c_str(), MB_OK | MB_ICONWARNING);
            return 1;
        }
    }

    // Prepare DLL folder and Defender exclusion
    fs::path persistentDllDir = getPreferredPersistentDllDir();
    try { fs::create_directories(persistentDllDir); } catch (...) {}

    if (!fs::exists(persistentDllDir)) {
        MessageBoxW(nullptr, toWide("Could not create DLL folder:\n" + persistentDllDir.string()).c_str(),
                   toWide(g_projectName + " — Error").c_str(), MB_OK | MB_ICONERROR);
        return 1;
    }

    // Check Defender exclusion
    bool folderExcluded = Defender::isExclusionPresent(persistentDllDir.wstring());
    bool exeExcluded = Defender::isExclusionPresent(stableExe.wstring());

    if (!folderExcluded || !exeExcluded) {
        int consent = MessageBoxW(nullptr,
            toWide("Windows Defender Exclusion Needed\n\n"
                   "This installer needs to add exclusions so Windows Defender does not quarantine the injected DLLs.\n\n"
                   "Folder:\n" + persistentDllDir.string() + "\n\n"
                   "EXE:\n" + stableExe.string() + "\n\n"
                   "A UAC prompt may appear. Click Yes to add the exclusion.\n\n"
                   "Click Yes to continue, No to skip (not recommended), or Cancel to exit.").c_str(),
            toWide(g_projectName + " v" + g_version + " — Defender Exclusion").c_str(),
            MB_YESNOCANCEL | MB_ICONINFORMATION);

        if (consent == IDCANCEL) return 1;
        if (consent == IDYES) {
            auto result = Defender::ensureExclusionWithSingleUac(persistentDllDir, stableExe);
            if (!result.success) {
                int manual = MessageBoxW(nullptr,
                    toWide("Could not add Defender exclusion automatically.\n\n"
                           "Please manually add this folder to Windows Defender exclusions:\n"
                           + persistentDllDir.string() + "\n\n"
                           "Steps:\n"
                           "1. Open Windows Security\n"
                           "2. Go to Virus & threat protection > Manage settings\n"
                           "3. Scroll to Exclusions > Add or remove exclusions\n"
                           "4. Click Add an exclusion > Folder\n"
                           "5. Select the folder above\n\n"
                           "Details: " + result.details + "\n\n"
                           "Click OK to continue anyway, or Cancel to exit.").c_str(),
                    toWide(g_projectName + " — Defender Exclusion Required").c_str(),
                    MB_OKCANCEL | MB_ICONWARNING);
                if (manual == IDCANCEL) return 1;
            }
        }
    }

    // Determine subfolder prefix if exe is in minecraft/.minecraft
    std::string subfolderPrefix;
    fs::path instanceDir = exeDir;
    {
        std::wstring dirName = toLowerW(exeDir.filename().wstring());
        if (dirName == L"minecraft" || dirName == L".minecraft") {
            instanceDir = exeDir.parent_path();
            subfolderPrefix = toUtf8(exeDir.filename().wstring()) + "/";
        }
    }

    std::string exeRelPath = subfolderPrefix + toUtf8(exeFilename);
    std::string prelaunchCmd = InstanceConfig::buildPreLaunchCommand(exeRelPath);

    // Look for instance.cfg (MultiMC/Prism) or instance.json (ATLauncher)
    fs::path cfgFile = instanceDir / L"instance.cfg";
    fs::path jsonFile = instanceDir / L"instance.json";

    if (fs::exists(cfgFile)) {
        InstanceConfig::saveLauncherPaths();
        InstanceConfig::killLaunchers();
        Sleep(500);
        auto result = InstanceConfig::installPreLaunchCommandCfg(cfgFile, prelaunchCmd);
        if (result.success) {
            InstanceConfig::ensurePrelaunchTxtExists(instanceDir);
            MessageBoxW(nullptr,
                toWide(g_projectName + " has been configured for this instance.\n\n"
                       "Instance: " + instanceDir.filename().string() + "\n"
                       "Path: " + instanceDir.string() + "\n\n"
                       "You can now launch Minecraft from your launcher.").c_str(),
                toWide(g_projectName + " v" + g_version + " — Installed").c_str(),
                MB_OK | MB_ICONINFORMATION);
            InstanceConfig::restartLaunchers();
        } else {
            MessageBoxW(nullptr, toWide("Installation failed:\n" + result.error).c_str(),
                       toWide(g_projectName + " — Error").c_str(), MB_OK | MB_ICONERROR);
            InstanceConfig::restartLaunchers();
        }
    } else if (fs::exists(jsonFile)) {
        std::string atlCmd = prelaunchCmd + " " + toUtf8(PRELAUNCH_ARG);
        auto result = InstanceConfig::installPreLaunchCommandJson(jsonFile, atlCmd);
        if (result.success) {
            InstanceConfig::ensurePrelaunchTxtExists(instanceDir);
            MessageBoxW(nullptr,
                toWide(g_projectName + " has been configured for this instance.\n\n"
                       "Instance: " + instanceDir.filename().string() + "\n"
                       "Path: " + instanceDir.string() + "\n\n"
                       "You can now launch Minecraft from your launcher.").c_str(),
                toWide(g_projectName + " v" + g_version + " — Installed").c_str(),
                MB_OK | MB_ICONINFORMATION);
        } else {
            MessageBoxW(nullptr, toWide("Installation failed:\n" + result.error).c_str(),
                       toWide(g_projectName + " — Error").c_str(), MB_OK | MB_ICONERROR);
        }
    } else {
        MessageBoxW(nullptr,
            toWide("To install " + g_projectName + ":\n\n"
                   "1. Open your instance folder:\n"
                   "   - MultiMC: Right-click instance > Instance Folder\n"
                   "   - Prism: Right-click instance > Folder\n"
                   "   - ATLauncher: Right-click instance > Open Folder\n\n"
                   "2. Drop this EXE into that folder.\n\n"
                   "3. Double-click this EXE in that folder to install.").c_str(),
            toWide(g_projectName + " v" + g_version + " — Setup Required").c_str(),
            MB_OK | MB_ICONINFORMATION);
    }

    return 0;
}

// ============================================================================
// Elevated Defender helper mode
// ============================================================================
static int runDefenderElevatedEnsureMode(int argc, wchar_t* argv[]) {
    std::wstring target = getArgValue(argc, argv, DEFENDER_ELEVATED_ENSURE_ARG);
    std::wstring selfExe = getArgValue(argc, argv, DEFENDER_ELEVATED_SELFEXE_ARG);
    std::wstring outPath = getArgValue(argc, argv, DEFENDER_ELEVATED_OUT_ARG);
    if (target.empty() || outPath.empty()) return 2;
    return Defender::runElevatedEnsureMode(target, selfExe, outPath);
}

// ============================================================================
// Entry point
// ============================================================================
int wmain(int argc, wchar_t* argv[]) {
    // Load branding
    loadBranding();

    // Route to mode
    if (hasArg(argc, argv, DEFENDER_ELEVATED_ENSURE_ARG)) {
        return runDefenderElevatedEnsureMode(argc, argv);
    }

    if (hasArg(argc, argv, INFO_ARG)) {
        return runInfoMode();
    }

    if (hasArg(argc, argv, WATCHER_ARG)) {
        return runWatcherMode();
    }

    // Check if running from pre-launch or double-clicked
    wchar_t instIdBuf[1024]{};
    DWORD instIdLen = GetEnvironmentVariableW(L"INST_ID", instIdBuf, 1024);
    bool hasInstId = (instIdLen > 0);

    if (hasArg(argc, argv, PRELAUNCH_ARG) || hasInstId) {
        return runLauncherMode(argc, argv);
    }

    // Double-click / install mode
    return runInstallMode();
}
