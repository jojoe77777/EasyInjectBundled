// Exercise the actual installer dialog code, without packaged DLL resources.
#define wmain installerEntryForTest
#define wWinMain installerWindowsEntryForTest
#if defined(TEST_LITE_INSTALLER)
#include "../exe-lite/src/main.cpp"
#else
#include "../exe/src/main.cpp"
#endif
#undef wmain
#undef wWinMain

int main() {
    // A separate desktop keeps these automated dialogs off the user's screen.
    HDESK original = GetThreadDesktop(GetCurrentThreadId());
    std::wstring name = L"EasyInject-dialog-test-" + std::to_wstring(GetCurrentProcessId());
    HDESK desktop = CreateDesktopW(name.c_str(), nullptr, nullptr, 0, GENERIC_ALL, nullptr);
    if (!desktop || !SetThreadDesktop(desktop)) return 1;
    HANDLE finished = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    std::thread watchdog([finished] {
        if (WaitForSingleObject(finished, 90000) == WAIT_TIMEOUT) {
            std::cerr << "FAIL: dialog message loop did not return after cross-thread close\n";
            TerminateProcess(GetCurrentProcess(), 2);
        }
    });
    bool passed = true;
    for (int i = 0; i < 2; ++i) {
        std::wstring title = L"EasyInject dialog regression " + std::to_wstring(i);
        bool clicked = false;
        std::thread automation([&] {
            if (!SetThreadDesktop(desktop)) {
                std::cerr << "FAIL: automation desktop switch: " << GetLastError() << '\n';
                return;
            }
            for (int attempt = 0; attempt < 1200; ++attempt) {
                HWND window = FindWindowW(nullptr, title.c_str());
                HWND button = window ? FindWindowExW(window, nullptr, L"Button", L"Done") : nullptr;
                if (attempt == 100) std::cerr << "Waiting for dialog " << i << ": window=" << window << " button=" << button << '\n';
                // IsWindowVisible also considers ancestors on the SSH service's
                // hidden window station. Wait for ShowWindow's own style instead.
                if (button && (GetWindowLongPtrW(window, GWL_STYLE) & WS_VISIBLE)) {
                    std::cerr << "Found dialog " << i << "; sending BM_CLICK\n";
                    DWORD_PTR result;
                    clicked = SendMessageTimeoutW(button, BM_CLICK, 0, 0, SMTO_ABORTIFHUNG, 5000, &result) != 0;
                    return;
                }
                Sleep(50);
            }
            std::cerr << "FAIL: automation could not find the dialog button\n";
        });
        std::cerr << "Opening dialog " << i << '\n';
        const int result = Ui::showDialog(title, L"Cross-thread close regression", Ui::DialogTone::Info,
            {{IDOK, L"Done", true}}, IDCANCEL, false, L"Test", 520);
        automation.join();
        std::cerr << "Dialog " << i << " returned " << result << "; click=" << clicked << '\n';
        passed = passed && clicked && result == IDOK;
    }
    SetEvent(finished); watchdog.join(); CloseHandle(finished);
    SetThreadDesktop(original); CloseDesktop(desktop);
    std::cout << (passed ? "PASS: two sequential installer dialogs closed by cross-thread BM_CLICK\n" : "FAIL: dialog result\n");
    return passed ? 0 : 1;
}
