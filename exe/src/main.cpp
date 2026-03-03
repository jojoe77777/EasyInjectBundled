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
 * DLLs and branding.properties are embedded directly in the EXE as Win32 resources.
 * At runtime, embedded DLLs are extracted to %USERPROFILE%/.config/<brand>/dlls for injection.
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
static const int BRANDING_RESOURCE_ID = 101;
static const int DLL_INDEX_RESOURCE_ID = 102;
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

struct EmbeddedDllEntry {
    int resourceId;
    std::string fileName;
};

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

static std::wstring normalizeCrLf(const std::wstring& s) {
    if (s.empty()) return {};
    std::wstring out;
    out.reserve(s.size() + 16);
    for (size_t i = 0; i < s.size(); ++i) {
        wchar_t c = s[i];
        if (c == L'\r') {
            out.push_back(L'\r');
            if (i + 1 < s.size() && s[i + 1] == L'\n') {
                out.push_back(L'\n');
                ++i;
            } else {
                out.push_back(L'\n');
            }
        } else if (c == L'\n') {
            out.push_back(L'\r');
            out.push_back(L'\n');
        } else {
            out.push_back(c);
        }
    }
    return out;
}

static void enableHighDpiAwareness() {
    HMODULE user32 = GetModuleHandleW(L"user32.dll");
    if (user32) {
        using SetProcessDpiAwarenessContextFn = BOOL(WINAPI*)(HANDLE);
        auto setContext = reinterpret_cast<SetProcessDpiAwarenessContextFn>(
            GetProcAddress(user32, "SetProcessDpiAwarenessContext")
        );
        if (setContext) {
            const HANDLE perMonitorV2 = reinterpret_cast<HANDLE>(static_cast<INT_PTR>(-4));
            const HANDLE perMonitor = reinterpret_cast<HANDLE>(static_cast<INT_PTR>(-3));
            const HANDLE systemAware = reinterpret_cast<HANDLE>(static_cast<INT_PTR>(-2));
            if (setContext(perMonitorV2) || setContext(perMonitor) || setContext(systemAware)) {
                return;
            }
        }
    }

    HMODULE shcore = LoadLibraryW(L"shcore.dll");
    if (shcore) {
        using SetProcessDpiAwarenessFn = HRESULT(WINAPI*)(int);
        auto setAwareness = reinterpret_cast<SetProcessDpiAwarenessFn>(
            GetProcAddress(shcore, "SetProcessDpiAwareness")
        );
        if (setAwareness) {
            const int PROCESS_PER_MONITOR_DPI_AWARE = 2;
            const int PROCESS_SYSTEM_DPI_AWARE = 1;
            if (SUCCEEDED(setAwareness(PROCESS_PER_MONITOR_DPI_AWARE)) ||
                SUCCEEDED(setAwareness(PROCESS_SYSTEM_DPI_AWARE))) {
                FreeLibrary(shcore);
                return;
            }
        }
        FreeLibrary(shcore);
    }

    SetProcessDPIAware();
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
// Custom dark popup UI
// ============================================================================
namespace Ui {

enum class DialogTone {
    Info,
    Warning,
    Error,
    Question,
    Success,
};

struct DialogButton {
    int id;
    std::wstring label;
    bool isDefault = false;
};

struct DialogOptions {
    std::wstring title;
    std::wstring heading;
    std::wstring message;
    DialogTone tone = DialogTone::Info;
    std::vector<DialogButton> buttons;
    int cancelResult = IDCANCEL;
    bool topMost = false;
    int width = 700;
};

static const wchar_t* DARK_DIALOG_CLASS = L"EasyInject.DarkDialog";

struct DarkDialogState {
    DialogOptions options;
    int result = IDCANCEL;
    int defaultButtonId = IDOK;

    HWND hwndTitle = nullptr;
    std::vector<HWND> buttonHwnds;
    RECT bodyRect{};

    HFONT titleFont = nullptr;
    HFONT bodyFont = nullptr;
    HFONT buttonFont = nullptr;

    HBRUSH bgBrush = nullptr;
    HBRUSH bodyBrush = nullptr;
};

static constexpr COLORREF COLOR_BG = RGB(43, 43, 43);
static constexpr COLORREF COLOR_TEXT = RGB(224, 224, 224);
static constexpr COLORREF COLOR_MUTED_TEXT = RGB(199, 206, 214);
static constexpr COLORREF COLOR_BODY_BG = RGB(39, 39, 39);
static constexpr COLORREF COLOR_BODY_BORDER = RGB(52, 52, 52);
static constexpr COLORREF COLOR_BUTTON_BG = RGB(60, 60, 60);
static constexpr COLORREF COLOR_BUTTON_BG_HOT = RGB(69, 69, 69);
static constexpr COLORREF COLOR_BUTTON_BG_ACTIVE = RGB(74, 74, 74);
static constexpr COLORREF COLOR_BUTTON_BORDER = RGB(90, 90, 90);
static constexpr int BASE_PAD = 16;
static constexpr int BASE_TITLE_HEIGHT = 24;
static constexpr int BASE_TITLE_SPACING = 8;
static constexpr int BASE_BODY_MIN_HEIGHT = 110;
static constexpr int BASE_BUTTON_TOP_GAP = 12;
static constexpr int BASE_BUTTON_HEIGHT = 34;
static constexpr int BASE_BUTTON_GAP = 10;

static COLORREF accentForTone(DialogTone tone) {
    switch (tone) {
        case DialogTone::Warning: return RGB(255, 179, 0);
        case DialogTone::Error: return RGB(239, 83, 80);
        case DialogTone::Question: return RGB(129, 212, 250);
        case DialogTone::Success: return RGB(102, 187, 106);
        case DialogTone::Info:
        default: return RGB(129, 212, 250);
    }
}

static std::wstring defaultHeadingForTone(DialogTone tone) {
    switch (tone) {
        case DialogTone::Warning: return L"Warning";
        case DialogTone::Error: return L"Error";
        case DialogTone::Question: return L"Action Required";
        case DialogTone::Success: return L"Success";
        case DialogTone::Info:
        default: return L"Information";
    }
}

static HFONT createUiFont(int pointSize, int weight = FW_NORMAL) {
    HDC hdc = GetDC(nullptr);
    int dpi = hdc ? GetDeviceCaps(hdc, LOGPIXELSY) : 96;
    if (hdc) ReleaseDC(nullptr, hdc);
    int height = -MulDiv(pointSize, dpi, 72);
    return CreateFontW(height, 0, 0, 0, weight, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
}

static UINT queryWindowDpi(HWND hwnd) {
    if (!hwnd) return 96;
    HMODULE user32 = GetModuleHandleW(L"user32.dll");
    if (user32) {
        using GetDpiForWindowFn = UINT(WINAPI*)(HWND);
        auto fn = reinterpret_cast<GetDpiForWindowFn>(GetProcAddress(user32, "GetDpiForWindow"));
        if (fn) {
            UINT dpi = fn(hwnd);
            if (dpi != 0) return dpi;
        }
    }
    HDC hdc = GetDC(hwnd);
    UINT dpi = hdc ? static_cast<UINT>(GetDeviceCaps(hdc, LOGPIXELSY)) : 96;
    if (hdc) ReleaseDC(hwnd, hdc);
    return dpi == 0 ? 96 : dpi;
}

static UINT querySystemDpi() {
    HMODULE user32 = GetModuleHandleW(L"user32.dll");
    if (user32) {
        using GetDpiForSystemFn = UINT(WINAPI*)();
        auto fn = reinterpret_cast<GetDpiForSystemFn>(GetProcAddress(user32, "GetDpiForSystem"));
        if (fn) {
            UINT dpi = fn();
            if (dpi != 0) return dpi;
        }
    }
    HDC hdc = GetDC(nullptr);
    UINT dpi = hdc ? static_cast<UINT>(GetDeviceCaps(hdc, LOGPIXELSY)) : 96;
    if (hdc) ReleaseDC(nullptr, hdc);
    return dpi == 0 ? 96 : dpi;
}

static int scaleByDpi(int value96, UINT dpi) {
    return MulDiv(value96, static_cast<int>(dpi), 96);
}

static void applyDarkTitleBar(HWND hwnd) {
    HMODULE hDwm = LoadLibraryW(L"dwmapi.dll");
    if (!hDwm) return;

    using DwmSetWindowAttributeFn = HRESULT(WINAPI*)(HWND, DWORD, LPCVOID, DWORD);
    auto fn = reinterpret_cast<DwmSetWindowAttributeFn>(GetProcAddress(hDwm, "DwmSetWindowAttribute"));
    if (fn) {
        constexpr DWORD DWMWA_USE_IMMERSIVE_DARK_MODE_OLD = 19;
        constexpr DWORD DWMWA_USE_IMMERSIVE_DARK_MODE = 20;

        BOOL enabled = TRUE;
        fn(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &enabled, sizeof(enabled));
        fn(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE_OLD, &enabled, sizeof(enabled));
    }
    FreeLibrary(hDwm);
}

static bool ensureDialogClassRegistered() {
    static std::atomic<bool> registered{false};
    if (registered.load()) return true;

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = [](HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) -> LRESULT {
        auto* state = reinterpret_cast<DarkDialogState*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));

        auto layout = [&](DarkDialogState* s) {
            if (!s) return;
            RECT rc{};
            GetClientRect(hwnd, &rc);

            UINT dpi = queryWindowDpi(hwnd);

            const int pad = scaleByDpi(BASE_PAD, dpi);
            const int titleSpacing = scaleByDpi(BASE_TITLE_SPACING, dpi);
            const int buttonTopGap = scaleByDpi(BASE_BUTTON_TOP_GAP, dpi);
            const int buttonHeight = scaleByDpi(BASE_BUTTON_HEIGHT, dpi);
            const int buttonGap = scaleByDpi(BASE_BUTTON_GAP, dpi);
            const int bodyInset = scaleByDpi(2, dpi);

            int titleHeight = scaleByDpi(BASE_TITLE_HEIGHT, dpi);
            if (s->hwndTitle && s->titleFont) {
                HDC hdc = GetDC(hwnd);
                if (hdc) {
                    HFONT old = (HFONT)SelectObject(hdc, s->titleFont);
                    TEXTMETRICW tm{};
                    if (GetTextMetricsW(hdc, &tm)) {
                        titleHeight = std::max(titleHeight, static_cast<int>(tm.tmHeight) + scaleByDpi(6, dpi));
                    }
                    SelectObject(hdc, old);
                    ReleaseDC(hwnd, hdc);
                }
            }

            int buttonsTop = rc.bottom - pad - buttonHeight;
            int bodyTop = pad + titleHeight + titleSpacing;
            int bodyHeight = std::max(scaleByDpi(BASE_BODY_MIN_HEIGHT, dpi), buttonsTop - buttonTopGap - bodyTop);

            if (s->hwndTitle) MoveWindow(s->hwndTitle, pad, pad, rc.right - pad * 2, titleHeight, TRUE);
            int bodyX = pad + bodyInset;
            int bodyW = std::max(scaleByDpi(220, dpi), static_cast<int>(rc.right - bodyX * 2));
            s->bodyRect.left = bodyX;
            s->bodyRect.top = bodyTop;
            s->bodyRect.right = bodyX + bodyW;
            s->bodyRect.bottom = bodyTop + bodyHeight;

            if (!s->buttonHwnds.empty()) {
                HDC hdc = GetDC(hwnd);
                HFONT old = nullptr;
                if (hdc && s->buttonFont) old = (HFONT)SelectObject(hdc, s->buttonFont);

                std::vector<int> widths;
                widths.reserve(s->buttonHwnds.size());
                int totalWidth = 0;

                for (HWND button : s->buttonHwnds) {
                    wchar_t text[256]{};
                    GetWindowTextW(button, text, 255);
                    SIZE size{};
                    if (hdc) GetTextExtentPoint32W(hdc, text, (int)wcslen(text), &size);
                    int width = std::max(scaleByDpi(120, dpi), (int)size.cx + scaleByDpi(36, dpi));
                    widths.push_back(width);
                    totalWidth += width;
                }

                if (hdc) {
                    if (old) SelectObject(hdc, old);
                    ReleaseDC(hwnd, hdc);
                }

                totalWidth += (int)(s->buttonHwnds.size() - 1) * buttonGap;
                int x = rc.right - pad - totalWidth;
                int buttonRadius = scaleByDpi(10, dpi);

                for (size_t i = 0; i < s->buttonHwnds.size(); i++) {
                    MoveWindow(s->buttonHwnds[i], x, buttonsTop, widths[i], buttonHeight, TRUE);

                    HRGN rgn = CreateRoundRectRgn(0, 0, widths[i], buttonHeight, buttonRadius * 2, buttonRadius * 2);
                    SetWindowRgn(s->buttonHwnds[i], rgn, TRUE);

                    x += widths[i] + buttonGap;
                }
            }

            InvalidateRect(hwnd, nullptr, FALSE);
        };

        auto buttonExists = [&](DarkDialogState* s, int id) -> bool {
            if (!s) return false;
            for (HWND button : s->buttonHwnds) {
                if ((int)GetDlgCtrlID(button) == id) return true;
            }
            return false;
        };

        switch (msg) {
            case WM_NCCREATE: {
                auto* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
                auto* st = reinterpret_cast<DarkDialogState*>(cs->lpCreateParams);
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(st));
                return TRUE;
            }

            case WM_CREATE: {
                if (!state) return -1;

                state->titleFont = createUiFont(15, FW_SEMIBOLD);
                state->bodyFont = createUiFont(11, FW_NORMAL);
                state->buttonFont = createUiFont(11, FW_NORMAL);

                state->bgBrush = CreateSolidBrush(COLOR_BG);
                state->bodyBrush = CreateSolidBrush(COLOR_BODY_BG);

                std::wstring heading = state->options.heading.empty()
                    ? defaultHeadingForTone(state->options.tone)
                    : state->options.heading;

                state->hwndTitle = CreateWindowExW(
                    0, L"STATIC", heading.c_str(),
                    WS_CHILD | WS_VISIBLE | SS_LEFT,
                    0, 0, 0, 0,
                    hwnd, (HMENU)1001, GetModuleHandleW(nullptr), nullptr
                );

                if (state->hwndTitle && state->titleFont) {
                    SendMessageW(state->hwndTitle, WM_SETFONT, (WPARAM)state->titleFont, TRUE);
                }

                if (state->hwndTitle) {
                    SetWindowPos(state->hwndTitle, HWND_TOP, 0, 0, 0, 0,
                        SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
                }

                for (auto& button : state->options.buttons) {
                    DWORD style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW;

                    HWND hwndButton = CreateWindowExW(
                        0, L"BUTTON", button.label.c_str(), style,
                        0, 0, 0, 0,
                        hwnd, (HMENU)(INT_PTR)button.id, GetModuleHandleW(nullptr), nullptr
                    );

                    if (hwndButton && state->buttonFont) {
                        SendMessageW(hwndButton, WM_SETFONT, (WPARAM)state->buttonFont, TRUE);
                    }
                    if (hwndButton) state->buttonHwnds.push_back(hwndButton);
                    if (button.isDefault) state->defaultButtonId = button.id;
                }

                if (!buttonExists(state, state->defaultButtonId) && !state->buttonHwnds.empty()) {
                    state->defaultButtonId = (int)GetDlgCtrlID(state->buttonHwnds[0]);
                }

                applyDarkTitleBar(hwnd);
                layout(state);
                return 0;
            }

            case WM_PAINT: {
                PAINTSTRUCT ps{};
                HDC hdc = BeginPaint(hwnd, &ps);
                if (!hdc) return 0;

                RECT client{};
                GetClientRect(hwnd, &client);
                FillRect(hdc, &client, state && state->bgBrush ? state->bgBrush : (HBRUSH)(COLOR_WINDOW + 1));

                if (state) {
                    UINT dpi = queryWindowDpi(hwnd);
                    int bodyRadius = scaleByDpi(10, dpi);
                    int bodyInnerPadX = scaleByDpi(10, dpi);
                    int bodyInnerPadY = scaleByDpi(8, dpi);

                    HBRUSH panelBrush = state->bodyBrush ? state->bodyBrush : CreateSolidBrush(COLOR_BODY_BG);
                    HPEN panelPen = CreatePen(PS_SOLID, 1, COLOR_BODY_BORDER);
                    HGDIOBJ oldBrush = SelectObject(hdc, panelBrush);
                    HGDIOBJ oldPen = SelectObject(hdc, panelPen);

                    RoundRect(hdc,
                              state->bodyRect.left,
                              state->bodyRect.top,
                              state->bodyRect.right,
                              state->bodyRect.bottom,
                              bodyRadius,
                              bodyRadius);

                    SelectObject(hdc, oldBrush);
                    SelectObject(hdc, oldPen);
                    DeleteObject(panelPen);

                    RECT textRect = state->bodyRect;
                    InflateRect(&textRect, -bodyInnerPadX, -bodyInnerPadY);

                    HFONT oldFont = nullptr;
                    if (state->bodyFont) {
                        oldFont = (HFONT)SelectObject(hdc, state->bodyFont);
                    }
                    SetBkMode(hdc, TRANSPARENT);
                    SetTextColor(hdc, COLOR_MUTED_TEXT);
                    DrawTextW(hdc,
                              state->options.message.c_str(),
                              -1,
                              &textRect,
                              DT_LEFT | DT_TOP | DT_WORDBREAK | DT_EDITCONTROL | DT_NOPREFIX | DT_EXPANDTABS);

                    if (oldFont) SelectObject(hdc, oldFont);

                    if (!state->bodyBrush) {
                        DeleteObject(panelBrush);
                    }
                }

                EndPaint(hwnd, &ps);
                return 0;
            }

            case WM_SHOWWINDOW: {
                if (wParam && state) {
                    for (HWND button : state->buttonHwnds) {
                        if ((int)GetDlgCtrlID(button) == state->defaultButtonId) {
                            SetFocus(button);
                            break;
                        }
                    }
                }
                break;
            }

            case WM_SIZE:
                layout(state);
                return 0;

            case WM_COMMAND: {
                if (HIWORD(wParam) == BN_CLICKED && state) {
                    int id = LOWORD(wParam);
                    if (buttonExists(state, id)) {
                        state->result = id;
                        DestroyWindow(hwnd);
                        return 0;
                    }
                }
                break;
            }

            case WM_CLOSE:
                if (state) state->result = state->options.cancelResult;
                DestroyWindow(hwnd);
                return 0;

            case WM_ERASEBKGND: {
                RECT rc{};
                GetClientRect(hwnd, &rc);
                FillRect((HDC)wParam, &rc, state && state->bgBrush ? state->bgBrush : (HBRUSH)(COLOR_WINDOW + 1));
                return 1;
            }

            case WM_CTLCOLORSTATIC: {
                HDC hdc = (HDC)wParam;
                HWND ctl = (HWND)lParam;
                SetBkMode(hdc, TRANSPARENT);
                SetBkColor(hdc, COLOR_BG);
                COLORREF accent = state ? accentForTone(state->options.tone) : COLOR_TEXT;
                SetTextColor(hdc, (state && ctl == state->hwndTitle) ? accent : COLOR_TEXT);
                return (LRESULT)(state && state->bgBrush ? state->bgBrush : GetStockObject(DC_BRUSH));
            }

            case WM_CTLCOLOREDIT: {
                HDC hdc = (HDC)wParam;
                SetBkMode(hdc, OPAQUE);
                SetBkColor(hdc, COLOR_BODY_BG);
                SetTextColor(hdc, COLOR_MUTED_TEXT);
                return (LRESULT)(state && state->bodyBrush ? state->bodyBrush : GetStockObject(WHITE_BRUSH));
            }

            case WM_DRAWITEM: {
                auto* dis = reinterpret_cast<DRAWITEMSTRUCT*>(lParam);
                if (!dis || dis->CtlType != ODT_BUTTON) break;

                bool disabled = (dis->itemState & ODS_DISABLED) != 0;
                bool pressed = (dis->itemState & ODS_SELECTED) != 0;
                bool hot = (dis->itemState & ODS_HOTLIGHT) != 0;
                bool isDefault = state && ((int)GetDlgCtrlID(dis->hwndItem) == state->defaultButtonId);
                UINT dpi = queryWindowDpi(hwnd);
                int radius = scaleByDpi(10, dpi);

                COLORREF borderColor = isDefault
                    ? accentForTone(state ? state->options.tone : DialogTone::Info)
                    : COLOR_BUTTON_BORDER;

                COLORREF bg = pressed ? COLOR_BUTTON_BG_ACTIVE : (hot ? COLOR_BUTTON_BG_HOT : COLOR_BUTTON_BG);
                RECT rcItem = dis->rcItem;
                int width = rcItem.right - rcItem.left;
                int height = rcItem.bottom - rcItem.top;

                HDC memDc = CreateCompatibleDC(dis->hDC);
                HBITMAP memBmp = CreateCompatibleBitmap(dis->hDC, width, height);
                HGDIOBJ oldBmp = SelectObject(memDc, memBmp);

                HBRUSH parentBg = CreateSolidBrush(COLOR_BG);
                RECT memRect{0, 0, width, height};
                FillRect(memDc, &memRect, parentBg);
                DeleteObject(parentBg);

                HBRUSH bgBrush = CreateSolidBrush(bg);
                HPEN borderPen = CreatePen(PS_SOLID, 1, borderColor);
                HGDIOBJ oldBrush = SelectObject(memDc, bgBrush);
                HGDIOBJ oldPen = SelectObject(memDc, borderPen);
                RoundRect(memDc, 0, 0, width, height, radius, radius);
                SelectObject(memDc, oldBrush);
                SelectObject(memDc, oldPen);
                DeleteObject(bgBrush);
                DeleteObject(borderPen);

                wchar_t text[256]{};
                GetWindowTextW(dis->hwndItem, text, 255);
                HFONT oldFont = nullptr;
                if (state && state->buttonFont) {
                    oldFont = (HFONT)SelectObject(memDc, state->buttonFont);
                }
                SetBkMode(memDc, TRANSPARENT);
                SetTextColor(memDc, disabled ? RGB(140, 140, 140) : COLOR_TEXT);

                RECT textRc{0, 0, width, height};
                DrawTextW(memDc, text, -1, &textRc, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
                if (oldFont) SelectObject(memDc, oldFont);

                BitBlt(dis->hDC,
                       rcItem.left,
                       rcItem.top,
                       width,
                       height,
                       memDc,
                       0,
                       0,
                       SRCCOPY);

                SelectObject(memDc, oldBmp);
                DeleteObject(memBmp);
                DeleteDC(memDc);
                return TRUE;
            }

            case WM_NCDESTROY: {
                if (state) {
                    if (state->titleFont) DeleteObject(state->titleFont);
                    if (state->bodyFont) DeleteObject(state->bodyFont);
                    if (state->buttonFont) DeleteObject(state->buttonFont);
                    if (state->bgBrush) DeleteObject(state->bgBrush);
                    if (state->bodyBrush) DeleteObject(state->bodyBrush);
                }
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                break;
            }
        }
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    };
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = nullptr;
    wc.lpszClassName = DARK_DIALOG_CLASS;

    if (!RegisterClassExW(&wc)) {
        DWORD err = GetLastError();
        if (err != ERROR_CLASS_ALREADY_EXISTS) {
            return false;
        }
    }

    registered.store(true);
    return true;
}

static int estimateClientHeight(const std::wstring& message, int width96) {
    UINT dpi = querySystemDpi();

    int widthPx = scaleByDpi(width96, dpi);
    int pad = scaleByDpi(BASE_PAD, dpi);
    int bodyInset = scaleByDpi(4, dpi);
    int textWidthPx = std::max(scaleByDpi(280, dpi), widthPx - (pad + bodyInset) * 2);

    int measuredTextHeight = scaleByDpi(120, dpi);
    HDC hdc = GetDC(nullptr);
    HFONT font = createUiFont(12, FW_NORMAL);
    if (hdc && font) {
        HFONT old = (HFONT)SelectObject(hdc, font);
        RECT rc{0, 0, textWidthPx, 0};
        DrawTextW(hdc,
              message.c_str(),
              -1,
              &rc,
              DT_WORDBREAK | DT_CALCRECT | DT_NOPREFIX | DT_EXPANDTABS);
        measuredTextHeight = std::max(scaleByDpi(72, dpi), static_cast<int>(rc.bottom - rc.top));
        SelectObject(hdc, old);
    }
    if (font) DeleteObject(font);
    if (hdc) ReleaseDC(nullptr, hdc);

    int bodyHeight = std::clamp(measuredTextHeight + scaleByDpi(12, dpi),
                                scaleByDpi(130, dpi),
                                scaleByDpi(430, dpi));

    return scaleByDpi(BASE_PAD + BASE_TITLE_HEIGHT + BASE_TITLE_SPACING, dpi)
        + bodyHeight
        + scaleByDpi(BASE_BUTTON_TOP_GAP + BASE_BUTTON_HEIGHT + BASE_PAD, dpi);
}

static std::wstring removeDuplicateHeading(const std::wstring& heading, const std::wstring& message) {
    std::wstring normalizedHeading = trimW(heading);
    if (normalizedHeading.empty() || message.empty()) return message;

    size_t lineEnd = message.find_first_of(L"\r\n");
    std::wstring firstLine = trimW(lineEnd == std::wstring::npos ? message : message.substr(0, lineEnd));
    if (!iequalsW(firstLine, normalizedHeading)) return message;

    if (lineEnd == std::wstring::npos) return L"";

    size_t pos = lineEnd;
    if (pos < message.size() && message[pos] == L'\r') ++pos;
    if (pos < message.size() && message[pos] == L'\n') ++pos;

    while (pos < message.size()) {
        size_t nextEnd = message.find_first_of(L"\r\n", pos);
        std::wstring line = trimW(nextEnd == std::wstring::npos ? message.substr(pos)
                                                                 : message.substr(pos, nextEnd - pos));
        if (!line.empty()) break;
        if (nextEnd == std::wstring::npos) return L"";
        pos = nextEnd;
        if (pos < message.size() && message[pos] == L'\r') ++pos;
        if (pos < message.size() && message[pos] == L'\n') ++pos;
    }

    return message.substr(pos);
}

static DWORD fallbackIconFlag(DialogTone tone) {
    switch (tone) {
        case DialogTone::Warning: return MB_ICONWARNING;
        case DialogTone::Error: return MB_ICONERROR;
        case DialogTone::Question: return MB_ICONQUESTION;
        case DialogTone::Success:
        case DialogTone::Info:
        default: return MB_ICONINFORMATION;
    }
}

static int fallbackMessageBox(const DialogOptions& options) {
    DWORD flags = fallbackIconFlag(options.tone);
    if (options.topMost) flags |= MB_TOPMOST;

    if (options.buttons.size() == 2) {
        int a = options.buttons[0].id;
        int b = options.buttons[1].id;
        if ((a == IDYES && b == IDNO) || (a == IDNO && b == IDYES)) flags |= MB_YESNO;
        else if ((a == IDOK && b == IDCANCEL) || (a == IDCANCEL && b == IDOK)) flags |= MB_OKCANCEL;
        else if ((a == IDRETRY && b == IDCANCEL) || (a == IDCANCEL && b == IDRETRY)) flags |= MB_RETRYCANCEL;
        else flags |= MB_OK;
    } else if (options.buttons.size() == 3) {
        bool hasYes = false, hasNo = false, hasCancel = false;
        for (const auto& b : options.buttons) {
            hasYes |= b.id == IDYES;
            hasNo |= b.id == IDNO;
            hasCancel |= b.id == IDCANCEL;
        }
        flags |= (hasYes && hasNo && hasCancel) ? MB_YESNOCANCEL : MB_OK;
    } else {
        flags |= MB_OK;
    }

    return MessageBoxW(nullptr, options.message.c_str(), options.title.c_str(), flags);
}

static int showDialog(const DialogOptions& inOptions) {
    DialogOptions options = inOptions;

    if (options.heading.empty()) {
        options.heading = defaultHeadingForTone(options.tone);
    }
    if (options.title.empty()) {
        options.title = options.heading;
    }

    options.message = removeDuplicateHeading(options.heading, options.message);
    options.message = normalizeCrLf(options.message);
    if (options.buttons.empty()) {
        options.buttons.push_back({IDOK, L"OK", true});
        options.cancelResult = IDOK;
    }

    bool hasDefault = false;
    for (const auto& b : options.buttons) {
        if (b.isDefault) {
            hasDefault = true;
            break;
        }
    }
    if (!hasDefault && !options.buttons.empty()) {
        options.buttons[0].isDefault = true;
    }

    if (!ensureDialogClassRegistered()) {
        return fallbackMessageBox(options);
    }

    UINT dpi = querySystemDpi();
    int width96 = std::clamp(options.width <= 0 ? 700 : options.width, 520, 1040);
    int width = std::clamp(scaleByDpi(width96, dpi), scaleByDpi(520, dpi), scaleByDpi(1400, dpi));
    int clientHeight = estimateClientHeight(options.message, width96);

    DWORD style = WS_CAPTION | WS_SYSMENU | WS_POPUP;
    DWORD exStyle = WS_EX_DLGMODALFRAME | (options.topMost ? WS_EX_TOPMOST : 0);

    RECT wr{0, 0, width, clientHeight};
    AdjustWindowRectEx(&wr, style, FALSE, exStyle);
    int winW = wr.right - wr.left;
    int winH = wr.bottom - wr.top;

    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);
    int x = std::max(0, (screenW - winW) / 2);
    int y = std::max(0, (screenH - winH) / 2);

    DarkDialogState state;
    state.options = std::move(options);
    state.result = state.options.cancelResult;

    HWND hwnd = CreateWindowExW(
        exStyle,
        DARK_DIALOG_CLASS,
        state.options.title.c_str(),
        style,
        x, y, winW, winH,
        nullptr,
        nullptr,
        GetModuleHandleW(nullptr),
        &state
    );

    if (!hwnd) {
        return fallbackMessageBox(state.options);
    }

    SetWindowTextW(hwnd, state.options.title.c_str());

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    MSG msg{};
    while (IsWindow(hwnd) && GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if ((msg.message == WM_KEYDOWN || msg.message == WM_SYSKEYDOWN) &&
            (msg.hwnd == hwnd || IsChild(hwnd, msg.hwnd))) {
            if (msg.wParam == VK_ESCAPE) {
                state.result = state.options.cancelResult;
                DestroyWindow(hwnd);
                continue;
            }
            if (msg.wParam == VK_RETURN) {
                SendMessageW(hwnd, WM_COMMAND, MAKEWPARAM(state.defaultButtonId, BN_CLICKED), 0);
                continue;
            }
        }

        if (!IsDialogMessageW(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    return state.result;
}

static int showDialog(const std::wstring& title,
                      const std::wstring& message,
                      DialogTone tone,
                      std::vector<DialogButton> buttons,
                      int cancelResult,
                      bool topMost = false,
                      const std::wstring& heading = L"",
                      int width = 700) {
    DialogOptions options;
    options.title = title;
    options.heading = heading;
    options.message = message;
    options.tone = tone;
    options.buttons = std::move(buttons);
    options.cancelResult = cancelResult;
    options.topMost = topMost;
    options.width = width;
    return showDialog(options);
}

} // namespace Ui

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
// Embedded resource loading
// ============================================================================
static bool loadEmbeddedResourceBytes(int resourceId, std::vector<uint8_t>& outData) {
    outData.clear();
    HMODULE module = GetModuleHandleW(nullptr);
    if (!module) return false;

    HRSRC hResInfo = FindResourceW(module, MAKEINTRESOURCEW(resourceId), RT_RCDATA);
    if (!hResInfo) return false;

    DWORD size = SizeofResource(module, hResInfo);
    if (size == 0) return false;

    HGLOBAL hResData = LoadResource(module, hResInfo);
    if (!hResData) return false;

    void* ptr = LockResource(hResData);
    if (!ptr) return false;

    const uint8_t* begin = static_cast<const uint8_t*>(ptr);
    outData.assign(begin, begin + size);
    return true;
}

static bool loadEmbeddedResourceText(int resourceId, std::string& outText) {
    std::vector<uint8_t> data;
    if (!loadEmbeddedResourceBytes(resourceId, data)) return false;

    outText.assign(reinterpret_cast<const char*>(data.data()), data.size());
    if (outText.size() >= 3 &&
        static_cast<unsigned char>(outText[0]) == 0xEF &&
        static_cast<unsigned char>(outText[1]) == 0xBB &&
        static_cast<unsigned char>(outText[2]) == 0xBF) {
        outText.erase(0, 3);
    }
    return true;
}

static std::vector<EmbeddedDllEntry> getEmbeddedDllEntries() {
    std::vector<EmbeddedDllEntry> entries;
    std::string manifest;
    if (!loadEmbeddedResourceText(DLL_INDEX_RESOURCE_ID, manifest)) return entries;

    std::set<std::string> seenNames;
    std::istringstream in(manifest);
    std::string line;
    while (std::getline(in, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        auto sep = line.find('|');
        if (sep == std::string::npos) continue;

        std::string resourceIdText = trim(line.substr(0, sep));
        std::string fileName = trim(line.substr(sep + 1));
        if (resourceIdText.empty() || fileName.empty()) continue;

        int resourceId = 0;
        try {
            resourceId = std::stoi(resourceIdText);
        } catch (...) {
            continue;
        }
        if (resourceId <= 0) continue;

        std::string fileNameLower = toLower(fileName);
        if (!seenNames.insert(fileNameLower).second) continue;

        entries.push_back({resourceId, fileName});
    }

    return entries;
}

// ============================================================================
// Branding properties loader
// ============================================================================
static void applyBrandingProperties(const std::string& propertiesContent) {
    std::istringstream in(propertiesContent);
    std::string line;
    while (std::getline(in, line)) {
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

static void loadBranding() {
    std::string embeddedProps;
    if (!loadEmbeddedResourceText(BRANDING_RESOURCE_ID, embeddedProps)) return;
    applyBrandingProperties(embeddedProps);
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
    int choice = Ui::showDialog(
        toWide(g_projectName + " — Update"),
        msg,
        Ui::DialogTone::Question,
        {
            {IDYES, L"Update now", true},
            {IDNO, L"Not now"}
        },
        IDNO,
        true,
        L"Update Available",
        700
    );
    if (choice != IDYES) {
        logMsg("[Updater] User declined update");
        return false;
    }

    auto assets = Json::getAssetsArray(resp.body);
    std::string stableExeName = toUtf8(getStableExeFileName());
    Asset asset = chooseAsset(assets, g_assetNameRegex, stableExeName);
    if (asset.downloadUrl.empty()) {
        logMsg("[Updater] No matching .exe asset found");
        Ui::showDialog(
            toWide(g_projectName + " Updater"),
            L"Update found, but no downloadable .exe asset was found in the release.",
            Ui::DialogTone::Warning,
            {{IDOK, L"OK", true}},
            IDOK,
            true,
            L"No Downloadable Asset",
            680
        );
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
        Ui::showDialog(
            toWide(g_projectName + " Updater"),
            L"Update download failed.",
            Ui::DialogTone::Error,
            {{IDOK, L"OK", true}},
            IDOK,
            true,
            L"Download Failed",
            640
        );
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
 * Copy embedded DLL resources to the persistent extraction directory.
 */
static std::vector<fs::path> copyDllsToPersistentDir() {
    std::vector<fs::path> result;
    fs::path destDir = getPreferredPersistentDllDir();
    fs::create_directories(destDir);

    auto bundled = getEmbeddedDllEntries();
    for (auto& entry : bundled) {
        std::vector<uint8_t> data;
        if (!loadEmbeddedResourceBytes(entry.resourceId, data)) {
            logMsg("[DLL] Missing embedded resource for " + entry.fileName);
            continue;
        }

        fs::path dest = destDir / toWide(entry.fileName);
        try {
            std::ofstream out(dest, std::ios::binary | std::ios::trunc);
            if (!out.is_open()) throw std::runtime_error("Unable to open destination file");
            if (!data.empty()) {
                out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
            }
            if (!out.good()) throw std::runtime_error("Failed while writing destination file");
            result.push_back(dest);
        } catch (const std::exception& e) {
            logMsg("[DLL] Failed to extract " + entry.fileName + ": " + e.what());
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
 * Default format: \"$INST_DIR/<subfolderPrefix><exeFilename>\" --prelaunch
 * ATLauncher format: "$INST_DIR/<subfolderPrefix><exeFilename>" --prelaunch
 */
static std::string buildPreLaunchCommand(const std::string& exeRelativePath, bool quoteExecutablePath = true) {
    std::string exePath = "$INST_DIR/" + exeRelativePath;
    if (quoteExecutablePath) {
        return "\\\"" + exePath + "\\\" --prelaunch";
    }
    return "\"" + exePath + "\" --prelaunch";
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

    auto dlls = getEmbeddedDllEntries();
    for (auto& dll : dlls) {
        std::vector<uint8_t> data;
        if (!loadEmbeddedResourceBytes(dll.resourceId, data)) {
            std::cout << std::endl;
            std::cout << "  Name:   " << dll.fileName << std::endl;
            std::cout << "  Error:  missing embedded resource" << std::endl;
            continue;
        }
        std::string hash = computeSha512(data);
        std::cout << std::endl;
        std::cout << "  Name:   " << dll.fileName << std::endl;
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
            Ui::showDialog(
                toWide(g_projectName + " — Restart Required"),
                toWide("UPDATE INSTALLED\n\nPlease start the instance again.\n\n"
                       + g_projectName + " updated itself. The game launch was stopped so the updated EXE can be applied safely.\n\n"
                       "Close this message, then click Play / Launch again in your launcher."),
                Ui::DialogTone::Success,
                {{IDOK, L"OK", true}},
                IDOK,
                true,
                L"Update Installed",
                760
            );
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
static void showInstallSuccessDialogWithUninstall(const fs::path& instanceCfg, const fs::path& instanceDir) {
    while (true) {
        int action = Ui::showDialog(
            toWide(g_projectName + " v" + g_version + " — Installed"),
            toWide(g_projectName + " has been configured for this instance.\n\n"
                   "Instance: " + instanceDir.filename().string() + "\n"
                   "Path: " + instanceDir.string() + "\n\n"
                   "You can now launch Minecraft from your launcher."),
            Ui::DialogTone::Success,
            {
                {IDOK, L"Done", true},
                {IDNO, L"Uninstall"}
            },
            IDOK,
            true,
            L"Installation Complete",
            760
        );

        if (action != IDNO) {
            return;
        }

        int confirm = Ui::showDialog(
            toWide(g_projectName + " — Confirm Uninstall"),
            L"Are you sure you want to undo the installation?\n"
            L"This will remove the launcher integration.",
            Ui::DialogTone::Warning,
            {
                {IDYES, L"Uninstall", true},
                {IDNO, L"Cancel"}
            },
            IDNO,
            true,
            L"Confirm Uninstall",
            700
        );

        if (confirm != IDYES) {
            continue;
        }

        InstanceConfig::InstallResult uninstallResult;
        if (iequals(toLower(instanceCfg.extension().string()), ".json")) {
            uninstallResult = InstanceConfig::installPreLaunchCommandJson(instanceCfg, "");
        } else {
            uninstallResult = InstanceConfig::installPreLaunchCommandCfg(instanceCfg, "");
        }

        if (uninstallResult.success) {
            Ui::showDialog(
                toWide(g_projectName + " v" + g_version + " — Uninstalled"),
                toWide("Launcher integration was removed for this instance.\n\n"
                       "Instance: " + instanceDir.filename().string() + "\n"
                       "Path: " + instanceDir.string()),
                Ui::DialogTone::Info,
                {{IDOK, L"Done", true}},
                IDOK,
                true,
                L"Uninstalled",
                760
            );
            return;
        }

        Ui::showDialog(
            toWide(g_projectName + " — Error"),
            toWide("Failed to uninstall:\n" + uninstallResult.error),
            Ui::DialogTone::Error,
            {{IDOK, L"OK", true}},
            IDOK,
            true,
            L"Uninstall Failed",
            760
        );
    }
}

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
            Ui::showDialog(
                toWide(g_projectName + " — Error"),
                toWide("Failed to create/replace " + toUtf8(stableFilename)
                    + " next to the current EXE.\n\nReason: " + e.what()),
                Ui::DialogTone::Error,
                {{IDOK, L"Exit", true}},
                IDOK,
                true,
                L"Setup Failed",
                760
            );
            return 1;
        }
    }

    // Check Smart App Control
    auto sacState = getSmartAppControlState();
    if (sacState == SmartAppControlState::ENABLED) {
        int choice = Ui::showDialog(
            toWide(g_projectName + " — Smart App Control"),
            L"Windows Smart App Control is currently ENABLED and will block the injected DLLs.\n\n"
            L"Smart App Control does not support exclusions — it must be disabled entirely.\n\n"
            L"Steps to disable:\n"
            L"1. Open Windows Security\n"
            L"2. Go to App & browser control\n"
            L"3. Under Smart App Control, click Settings\n"
            L"4. Select Off\n\n"
            L"Click I've disabled it after turning it off, or Exit to cancel setup.",
            Ui::DialogTone::Warning,
            {
                {IDRETRY, L"I've disabled it", true},
                {IDCANCEL, L"Exit"}
            },
            IDCANCEL,
            true,
            L"Smart App Control Is Enabled",
            760
        );
        if (choice == IDCANCEL) return 1;
        // Re-check
        if (getSmartAppControlState() == SmartAppControlState::ENABLED) {
            Ui::showDialog(
                toWide(g_projectName),
                L"Smart App Control still appears to be enabled.\nPlease disable it and try again.",
                Ui::DialogTone::Warning,
                {{IDOK, L"Exit", true}},
                IDOK,
                true,
                L"Still Enabled",
                640
            );
            return 1;
        }
    }

    // Prepare DLL folder and Defender exclusion
    fs::path persistentDllDir = getPreferredPersistentDllDir();
    try { fs::create_directories(persistentDllDir); } catch (...) {}

    if (!fs::exists(persistentDllDir)) {
        Ui::showDialog(
            toWide(g_projectName + " — Error"),
            toWide("Could not create DLL folder:\n" + persistentDllDir.string()),
            Ui::DialogTone::Error,
            {{IDOK, L"Exit", true}},
            IDOK,
            true,
            L"Setup Failed",
            760
        );
        return 1;
    }

    // Check Defender exclusion
    bool folderExcluded = Defender::isExclusionPresent(persistentDllDir.wstring());
    bool exeExcluded = Defender::isExclusionPresent(stableExe.wstring());

    if (!folderExcluded || !exeExcluded) {
        int consent = Ui::showDialog(
            toWide(g_projectName + " v" + g_version + " — Defender Exclusion"),
            toWide("Windows Defender Exclusion Needed\n\n"
                   "This installer needs to add exclusions so Windows Defender does not quarantine the injected DLLs.\n\n"
                   "Folder:\n" + persistentDllDir.string() + "\n\n"
                   "EXE:\n" + stableExe.string() + "\n\n"
                   "A UAC prompt may appear. Click Yes to add the exclusion.\n\n"
                   "Choose Continue to add exclusions, Skip to continue without them, or Exit."),
            Ui::DialogTone::Question,
            {
                {IDYES, L"Continue", true},
                {IDNO, L"Skip (not recommended)"},
                {IDCANCEL, L"Exit"}
            },
            IDCANCEL,
            true,
            L"Windows Defender Exclusion Needed",
            820
        );

        if (consent == IDCANCEL) return 1;
        if (consent == IDYES) {
            auto result = Defender::ensureExclusionWithSingleUac(persistentDllDir, stableExe);
            if (!result.success) {
                int manual = Ui::showDialog(
                    toWide(g_projectName + " — Defender Exclusion Required"),
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
                           "Click Continue anyway to proceed, or Exit to cancel setup."),
                    Ui::DialogTone::Warning,
                    {
                        {IDOK, L"Continue anyway", true},
                        {IDCANCEL, L"Exit"}
                    },
                    IDCANCEL,
                    true,
                    L"Manual Action Required",
                    860
                );
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
    std::string prelaunchCmdAtLauncher = InstanceConfig::buildPreLaunchCommand(exeRelPath, false);

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
            showInstallSuccessDialogWithUninstall(cfgFile, instanceDir);
            InstanceConfig::restartLaunchers();
        } else {
            Ui::showDialog(
                toWide(g_projectName + " — Error"),
                toWide("Installation failed:\n" + result.error),
                Ui::DialogTone::Error,
                {{IDOK, L"Exit", true}},
                IDOK,
                true,
                L"Installation Failed",
                760
            );
            InstanceConfig::restartLaunchers();
        }
    } else if (fs::exists(jsonFile)) {
        std::string atlCmd = prelaunchCmdAtLauncher + " " + toUtf8(PRELAUNCH_ARG);
        auto result = InstanceConfig::installPreLaunchCommandJson(jsonFile, atlCmd);
        if (result.success) {
            InstanceConfig::ensurePrelaunchTxtExists(instanceDir);
            showInstallSuccessDialogWithUninstall(jsonFile, instanceDir);
        } else {
            Ui::showDialog(
                toWide(g_projectName + " — Error"),
                toWide("Installation failed:\n" + result.error),
                Ui::DialogTone::Error,
                {{IDOK, L"Exit", true}},
                IDOK,
                true,
                L"Installation Failed",
                760
            );
        }
    } else {
        Ui::showDialog(
            toWide(g_projectName + " v" + g_version + " — Setup Required"),
            toWide("To install " + g_projectName + ":\n\n"
                   "1. Open your instance folder:\n"
                   "   - MultiMC: Right-click instance > Instance Folder\n"
                   "   - Prism: Right-click instance > Folder\n"
                   "   - ATLauncher: Right-click instance > Open Folder\n\n"
                   "2. Drop this EXE into that folder.\n\n"
                   "3. Double-click this EXE in that folder to install."),
            Ui::DialogTone::Info,
            {{IDOK, L"OK", true}},
            IDOK,
            true,
            L"Setup Required",
            760
        );
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
static int runAppMain(int argc, wchar_t* argv[]) {
    enableHighDpiAwareness();

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

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);

    if (!argv || argc <= 0) {
        wchar_t fallbackArg0[] = L"EasyInjectExe";
        wchar_t* fallbackArgv[] = { fallbackArg0 };
        if (argv) LocalFree(argv);
        return runAppMain(1, fallbackArgv);
    }

    int code = runAppMain(argc, argv);
    LocalFree(argv);
    return code;
}

int wmain(int argc, wchar_t* argv[]) {
    return runAppMain(argc, argv);
}
