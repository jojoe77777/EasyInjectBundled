#include <windows.h>
#include <commctrl.h>
#include <winhttp.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

#include "generated_config.h"

namespace fs = std::filesystem;

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "winhttp.lib")

static const wchar_t* kWindowClassName = L"ToolscreenDownloaderWindow";
static const wchar_t* kInstallerTitle = L"Toolscreen Downloader";
static const wchar_t* kTargetFileName = L"Toolscreen.exe";
static const wchar_t* kFallbackApiUrl = L"https://api.github.com/repos/jojoe77777/Toolscreen/releases/latest";
static const wchar_t* kFallbackReleasesUrl = L"https://github.com/jojoe77777/Toolscreen/releases";
static const char* kDefaultExeRegex = ".*\\.exe$";

static const UINT WM_APP_SET_STATUS = WM_APP + 1;
static const UINT WM_APP_SET_FILE_INFO = WM_APP + 2;
static const UINT WM_APP_SET_PROGRESS = WM_APP + 3;
static const UINT WM_APP_COMPLETE = WM_APP + 4;

struct StringMessage {
    std::wstring text;
};

struct FileInfoMessage {
    std::wstring assetName;
    std::wstring releaseTag;
    std::wstring targetPath;
};

struct ProgressMessage {
    unsigned long long bytesRead = 0;
    unsigned long long totalBytes = 0;
    int percent = -1;
};

struct CompletionMessage {
    bool success = false;
    std::wstring text;
};

struct WindowState {
    HWND hwnd = nullptr;
    HWND assetLabel = nullptr;
    HWND targetLabel = nullptr;
    HWND statusLabel = nullptr;
    HWND bytesLabel = nullptr;
    HWND progressBar = nullptr;
    HFONT headingFont = nullptr;
    bool finished = false;
    bool success = false;
    std::wstring finalMessage;
};

struct WorkerContext {
    HWND hwnd = nullptr;
};

struct HttpResponse {
    int statusCode = 0;
    std::string body;
    std::wstring errorMessage;
    bool success = false;
};

struct Asset {
    std::string name;
    std::string downloadUrl;
};

static std::wstring toWide(const std::string& value) {
    if (value.empty()) {
        return {};
    }
    int length = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0);
    if (length <= 0) {
        return {};
    }
    std::wstring result(length, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), &result[0], length);
    return result;
}

static std::string toUtf8(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }
    int length = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (length <= 0) {
        return {};
    }
    std::string result(length, '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), &result[0], length, nullptr, nullptr);
    return result;
}

static std::string trim(const std::string& value) {
    size_t start = value.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) {
        return {};
    }
    size_t end = value.find_last_not_of(" \t\r\n");
    return value.substr(start, end - start + 1);
}

static std::wstring trimWide(const std::wstring& value) {
    size_t start = value.find_first_not_of(L" \t\r\n");
    if (start == std::wstring::npos) {
        return {};
    }
    size_t end = value.find_last_not_of(L" \t\r\n");
    return value.substr(start, end - start + 1);
}

static bool endsWithInsensitive(const std::string& value, const std::string& suffix) {
    if (value.size() < suffix.size()) {
        return false;
    }
    for (size_t i = 0; i < suffix.size(); ++i) {
        char a = static_cast<char>(tolower(static_cast<unsigned char>(value[value.size() - suffix.size() + i])));
        char b = static_cast<char>(tolower(static_cast<unsigned char>(suffix[i])));
        if (a != b) {
            return false;
        }
    }
    return true;
}

static fs::path getExePath() {
    wchar_t buffer[32768];
    DWORD length = GetModuleFileNameW(nullptr, buffer, 32768);
    if (length == 0 || length >= 32768) {
        return {};
    }
    return fs::path(buffer);
}

static fs::path getExeDir() {
    fs::path exePath = getExePath();
    return exePath.empty() ? fs::current_path() : exePath.parent_path();
}

static std::wstring formatBytes(unsigned long long value) {
    wchar_t buffer[64];
    if (value < 1024ULL) {
        swprintf_s(buffer, L"%llu B", value);
        return buffer;
    }
    if (value < 1024ULL * 1024ULL) {
        swprintf_s(buffer, L"%.1f KB", static_cast<double>(value) / 1024.0);
        return buffer;
    }
    if (value < 1024ULL * 1024ULL * 1024ULL) {
        swprintf_s(buffer, L"%.1f MB", static_cast<double>(value) / (1024.0 * 1024.0));
        return buffer;
    }
    swprintf_s(buffer, L"%.2f GB", static_cast<double>(value) / (1024.0 * 1024.0 * 1024.0));
    return buffer;
}

static std::wstring deriveLatestReleaseApiUrl(const std::wstring& releasesUrl) {
    std::wstring trimmed = trimWide(releasesUrl);
    if (trimmed.empty()) {
        return {};
    }

    std::string url = toUtf8(trimmed);
    size_t hostPos = url.find("github.com/");
    if (hostPos == std::string::npos) {
        return {};
    }

    std::string path = url.substr(hostPos + 11);
    std::vector<std::string> segments;
    std::istringstream input(path);
    std::string segment;
    while (std::getline(input, segment, '/')) {
        if (!segment.empty()) {
            segments.push_back(segment);
        }
    }
    if (segments.size() < 2) {
        return {};
    }

    return toWide("https://api.github.com/repos/" + segments[0] + "/" + segments[1] + "/releases/latest");
}

namespace Json {

static std::string getString(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) {
        return {};
    }
    pos += search.size();
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == ':' || json[pos] == '\n' || json[pos] == '\r')) {
        ++pos;
    }
    if (pos >= json.size() || json[pos] != '"') {
        return {};
    }

    ++pos;
    std::string result;
    bool escaped = false;
    while (pos < json.size()) {
        char c = json[pos++];
        if (escaped) {
            result.push_back(c);
            escaped = false;
            continue;
        }
        if (c == '\\') {
            escaped = true;
            continue;
        }
        if (c == '"') {
            break;
        }
        result.push_back(c);
    }
    return result;
}

static std::vector<std::string> getAssetsArray(const std::string& json) {
    std::vector<std::string> assets;
    size_t pos = json.find("\"assets\"");
    if (pos == std::string::npos) {
        return assets;
    }
    pos = json.find('[', pos);
    if (pos == std::string::npos) {
        return assets;
    }
    ++pos;

    int depth = 0;
    bool inString = false;
    bool escaped = false;
    std::string current;
    while (pos < json.size()) {
        char c = json[pos++];
        if (inString) {
            current.push_back(c);
            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                inString = false;
            }
            continue;
        }

        if (c == '"') {
            inString = true;
            if (depth > 0) {
                current.push_back(c);
            }
            continue;
        }
        if (c == '{') {
            if (depth == 0) {
                current.clear();
            }
            ++depth;
            current.push_back(c);
            continue;
        }
        if (c == '}') {
            if (depth > 0) {
                current.push_back(c);
                --depth;
                if (depth == 0) {
                    assets.push_back(current);
                    current.clear();
                }
            }
            continue;
        }
        if (c == ']' && depth == 0) {
            break;
        }
        if (depth > 0) {
            current.push_back(c);
        }
    }
    return assets;
}

} // namespace Json

namespace Http {

static HttpResponse get(const std::wstring& url) {
    HttpResponse response;
    URL_COMPONENTS parts{};
    parts.dwStructSize = sizeof(parts);
    wchar_t hostName[256]{};
    wchar_t urlPath[4096]{};
    parts.lpszHostName = hostName;
    parts.dwHostNameLength = 256;
    parts.lpszUrlPath = urlPath;
    parts.dwUrlPathLength = 4096;

    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &parts)) {
        response.errorMessage = L"Failed to parse the GitHub API URL.";
        return response;
    }

    HINTERNET session = WinHttpOpen(L"Toolscreen-Downloader/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) {
        response.errorMessage = L"Failed to initialize WinHTTP.";
        return response;
    }

    HINTERNET connection = WinHttpConnect(session, hostName, parts.nPort, 0);
    if (!connection) {
        response.errorMessage = L"Failed to connect to GitHub.";
        WinHttpCloseHandle(session);
        return response;
    }

    DWORD flags = (parts.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(connection, L"GET", urlPath, nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!request) {
        response.errorMessage = L"Failed to create the GitHub request.";
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return response;
    }

    WinHttpAddRequestHeaders(request, L"Accept: application/vnd.github+json\r\n", static_cast<DWORD>(-1), WINHTTP_ADDREQ_FLAG_ADD);

    bool sent = WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) != FALSE;
    bool received = sent && WinHttpReceiveResponse(request, nullptr) != FALSE;
    if (!received) {
        response.errorMessage = L"GitHub did not return a valid release response.";
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return response;
    }

    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX);
    response.statusCode = static_cast<int>(statusCode);

    DWORD available = 0;
    DWORD read = 0;
    std::string body;
    while (WinHttpQueryDataAvailable(request, &available) && available > 0) {
        std::vector<char> buffer(available);
        if (!WinHttpReadData(request, buffer.data(), available, &read)) {
            break;
        }
        body.append(buffer.data(), read);
    }

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);

    response.body = body;
    response.success = (statusCode >= 200 && statusCode < 300);
    if (!response.success && response.errorMessage.empty()) {
        std::wstringstream ss;
        ss << L"GitHub API returned HTTP " << statusCode << L".";
        response.errorMessage = ss.str();
    }
    return response;
}

static bool downloadToFile(
    const std::wstring& url,
    const fs::path& outFile,
    const std::function<void(unsigned long long, unsigned long long)>& progress,
    const std::function<void(const std::wstring&)>& status,
    std::wstring& errorMessage
) {
    URL_COMPONENTS parts{};
    parts.dwStructSize = sizeof(parts);
    wchar_t hostName[256]{};
    wchar_t urlPath[4096]{};
    parts.lpszHostName = hostName;
    parts.dwHostNameLength = 256;
    parts.lpszUrlPath = urlPath;
    parts.dwUrlPathLength = 4096;

    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &parts)) {
        errorMessage = L"Failed to parse the download URL.";
        return false;
    }

    if (status) {
        status(L"Connecting to GitHub...");
    }

    HINTERNET session = WinHttpOpen(L"Toolscreen-Downloader/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) {
        errorMessage = L"Failed to initialize WinHTTP.";
        return false;
    }

    HINTERNET connection = WinHttpConnect(session, hostName, parts.nPort, 0);
    if (!connection) {
        errorMessage = L"Failed to connect to the release asset.";
        WinHttpCloseHandle(session);
        return false;
    }

    DWORD flags = (parts.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(connection, L"GET", urlPath, nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!request) {
        errorMessage = L"Failed to create the download request.";
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return false;
    }

    WinHttpAddRequestHeaders(request, L"Accept: application/octet-stream\r\n", static_cast<DWORD>(-1), WINHTTP_ADDREQ_FLAG_ADD);
    DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
    WinHttpSetOption(request, WINHTTP_OPTION_REDIRECT_POLICY, &redirectPolicy, sizeof(redirectPolicy));

    bool sent = WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) != FALSE;
    bool received = sent && WinHttpReceiveResponse(request, nullptr) != FALSE;
    if (!received) {
        errorMessage = L"GitHub did not return the release asset.";
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return false;
    }

    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX);
    if (statusCode < 200 || statusCode >= 300) {
        std::wstringstream ss;
        ss << L"GitHub asset download returned HTTP " << statusCode << L".";
        errorMessage = ss.str();
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return false;
    }

    wchar_t contentLengthBuffer[64]{};
    DWORD contentLengthSize = sizeof(contentLengthBuffer);
    unsigned long long totalBytes = 0;
    if (WinHttpQueryHeaders(request, WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_HEADER_NAME_BY_INDEX,
        contentLengthBuffer, &contentLengthSize, WINHTTP_NO_HEADER_INDEX)) {
        try {
            totalBytes = std::stoull(contentLengthBuffer);
        } catch (...) {
            totalBytes = 0;
        }
    }

    fs::create_directories(outFile.parent_path());
    std::ofstream output(outFile, std::ios::binary | std::ios::trunc);
    if (!output.is_open()) {
        errorMessage = L"Could not create the output file next to the downloader.";
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return false;
    }

    if (status) {
        status(L"Downloading Toolscreen.exe...");
    }

    unsigned long long totalRead = 0;
    DWORD available = 0;
    DWORD read = 0;
    while (WinHttpQueryDataAvailable(request, &available) && available > 0) {
        std::vector<char> buffer(available);
        if (!WinHttpReadData(request, buffer.data(), available, &read)) {
            errorMessage = L"Reading the release asset failed partway through the download.";
            output.close();
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connection);
            WinHttpCloseHandle(session);
            return false;
        }

        output.write(buffer.data(), read);
        if (!output.good()) {
            errorMessage = L"Writing to Toolscreen.exe failed.";
            output.close();
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connection);
            WinHttpCloseHandle(session);
            return false;
        }

        totalRead += read;
        if (progress) {
            progress(totalRead, totalBytes);
        }
    }

    output.close();
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    return true;
}

} // namespace Http

static Asset chooseAsset(const std::vector<std::string>& assets, const std::string& targetName) {
    std::regex exeRegex(kDefaultExeRegex, std::regex::icase);

    for (const std::string& assetJson : assets) {
        std::string name = Json::getString(assetJson, "name");
        if (!name.empty() && std::regex_match(name, exeRegex)) {
            return {name, Json::getString(assetJson, "browser_download_url")};
        }
    }

    for (const std::string& assetJson : assets) {
        std::string name = Json::getString(assetJson, "name");
        if (!name.empty() && _stricmp(name.c_str(), targetName.c_str()) == 0) {
            return {name, Json::getString(assetJson, "browser_download_url")};
        }
    }

    for (const std::string& assetJson : assets) {
        std::string name = Json::getString(assetJson, "name");
        if (endsWithInsensitive(name, ".exe")) {
            return {name, Json::getString(assetJson, "browser_download_url")};
        }
    }

    return {};
}

static void postStatus(HWND hwnd, const std::wstring& text) {
    PostMessageW(hwnd, WM_APP_SET_STATUS, 0, reinterpret_cast<LPARAM>(new StringMessage{text}));
}

static void postFileInfo(HWND hwnd, const std::wstring& assetName, const std::wstring& releaseTag, const std::wstring& targetPath) {
    PostMessageW(hwnd, WM_APP_SET_FILE_INFO, 0, reinterpret_cast<LPARAM>(new FileInfoMessage{assetName, releaseTag, targetPath}));
}

static void postProgress(HWND hwnd, unsigned long long bytesRead, unsigned long long totalBytes) {
    int percent = -1;
    if (totalBytes > 0) {
        percent = static_cast<int>(std::min<unsigned long long>(100ULL, (bytesRead * 100ULL) / totalBytes));
    }
    PostMessageW(hwnd, WM_APP_SET_PROGRESS, 0, reinterpret_cast<LPARAM>(new ProgressMessage{bytesRead, totalBytes, percent}));
}

static void postCompletion(HWND hwnd, bool success, const std::wstring& text) {
    PostMessageW(hwnd, WM_APP_COMPLETE, 0, reinterpret_cast<LPARAM>(new CompletionMessage{success, text}));
}

static bool moveIntoPlace(const fs::path& sourceFile, const fs::path& targetFile, std::wstring& errorMessage) {
    if (MoveFileExW(sourceFile.c_str(), targetFile.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        return true;
    }
    if (CopyFileW(sourceFile.c_str(), targetFile.c_str(), FALSE)) {
        DeleteFileW(sourceFile.c_str());
        return true;
    }
    errorMessage = L"The download completed, but Toolscreen.exe could not be written in the downloader folder.";
    return false;
}

static DWORD WINAPI downloadWorkerProc(LPVOID parameter) {
    WorkerContext* context = reinterpret_cast<WorkerContext*>(parameter);
    if (context == nullptr || context->hwnd == nullptr) {
        return 1;
    }

    std::wstring apiUrl = toWide(TOOLSCREEN_INSTALLER_API_URL);
    if (trimWide(apiUrl).empty()) {
        apiUrl = deriveLatestReleaseApiUrl(toWide(TOOLSCREEN_INSTALLER_RELEASES_URL));
    }
    if (trimWide(apiUrl).empty()) {
        apiUrl = kFallbackApiUrl;
    }

    std::wstring releasesUrl = toWide(TOOLSCREEN_INSTALLER_RELEASES_URL);
    if (trimWide(releasesUrl).empty()) {
        releasesUrl = kFallbackReleasesUrl;
    }

    postStatus(context->hwnd, L"Checking GitHub releases...");
    HttpResponse response = Http::get(apiUrl);
    if (!response.success || response.body.empty()) {
        std::wstring message = response.errorMessage.empty() ? L"Could not fetch the latest Toolscreen release." : response.errorMessage;
        postCompletion(context->hwnd, false, message);
        return 1;
    }

    std::string tagName = Json::getString(response.body, "tag_name");
    std::vector<std::string> assets = Json::getAssetsArray(response.body);
    Asset asset = chooseAsset(assets, "Toolscreen.exe");
    if (asset.name.empty() || asset.downloadUrl.empty()) {
        postCompletion(context->hwnd, false, L"The latest GitHub release did not contain a downloadable Toolscreen EXE asset.");
        return 1;
    }

    fs::path installDir = getExeDir();
    fs::path targetFile = installDir / kTargetFileName;
    fs::path tempFile = installDir / L"Toolscreen.exe.download";

    postFileInfo(context->hwnd, toWide(asset.name), toWide(tagName), targetFile.wstring());

    std::wstring downloadError;
    bool downloadOk = Http::downloadToFile(
        toWide(asset.downloadUrl),
        tempFile,
        [context](unsigned long long bytesRead, unsigned long long totalBytes) {
            postProgress(context->hwnd, bytesRead, totalBytes);
        },
        [context](const std::wstring& status) {
            postStatus(context->hwnd, status);
        },
        downloadError
    );

    if (!downloadOk || !fs::exists(tempFile) || fs::file_size(tempFile) == 0) {
        if (fs::exists(tempFile)) {
            std::error_code ignored;
            fs::remove(tempFile, ignored);
        }
        std::wstring message = downloadError.empty() ? L"The Toolscreen download failed." : downloadError;
        postCompletion(context->hwnd, false, message);
        return 1;
    }

    postStatus(context->hwnd, L"Finalizing Toolscreen.exe...");

    std::wstring moveError;
    if (!moveIntoPlace(tempFile, targetFile, moveError)) {
        if (fs::exists(tempFile)) {
            std::error_code ignored;
            fs::remove(tempFile, ignored);
        }
        postCompletion(context->hwnd, false, moveError);
        return 1;
    }

    std::wstring successMessage =
        L"Toolscreen has been downloaded.\n\nSaved to:\n" + targetFile.wstring() +
        L"\n\nYou must run that file to install Toolscreen.\nThis EXE was only the downloader.";
    postCompletion(context->hwnd, true, successMessage);
    return 0;
}

static void applyControlFont(HWND control, HFONT font) {
    SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
}

static LRESULT CALLBACK windowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    WindowState* state = reinterpret_cast<WindowState*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));

    switch (message) {
    case WM_NCCREATE: {
        CREATESTRUCTW* create = reinterpret_cast<CREATESTRUCTW*>(lParam);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(create->lpCreateParams));
        return TRUE;
    }
    case WM_CREATE: {
        state = reinterpret_cast<WindowState*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        if (state == nullptr) {
            return -1;
        }

        HINSTANCE instance = reinterpret_cast<HINSTANCE>(GetWindowLongPtrW(hwnd, GWLP_HINSTANCE));
        HFONT defaultFont = reinterpret_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
        LOGFONTW headingLogFont{};
        GetObjectW(defaultFont, sizeof(headingLogFont), &headingLogFont);
        headingLogFont.lfHeight = -20;
        headingLogFont.lfWeight = FW_BOLD;
        wcscpy_s(headingLogFont.lfFaceName, L"Segoe UI");
        state->headingFont = CreateFontIndirectW(&headingLogFont);

        HWND heading = CreateWindowExW(0, L"STATIC", L"Downloading the latest Toolscreen release",
            WS_CHILD | WS_VISIBLE, 20, 18, 520, 24, hwnd, nullptr, instance, nullptr);
        applyControlFont(heading, state->headingFont);

        state->assetLabel = CreateWindowExW(0, L"STATIC", L"GitHub asset: resolving...",
            WS_CHILD | WS_VISIBLE, 20, 52, 520, 20, hwnd, nullptr, instance, nullptr);
        applyControlFont(state->assetLabel, defaultFont);

        state->targetLabel = CreateWindowExW(0, L"STATIC", L"Saving as: Toolscreen.exe",
            WS_CHILD | WS_VISIBLE, 20, 74, 520, 20, hwnd, nullptr, instance, nullptr);
        applyControlFont(state->targetLabel, defaultFont);

        state->statusLabel = CreateWindowExW(0, L"STATIC", L"Preparing download...",
            WS_CHILD | WS_VISIBLE, 20, 104, 520, 20, hwnd, nullptr, instance, nullptr);
        applyControlFont(state->statusLabel, defaultFont);

        state->progressBar = CreateWindowExW(0, PROGRESS_CLASSW, nullptr,
            WS_CHILD | WS_VISIBLE | PBS_SMOOTH, 20, 132, 520, 22, hwnd, nullptr, instance, nullptr);
        SendMessageW(state->progressBar, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
        SendMessageW(state->progressBar, PBM_SETPOS, 0, 0);

        state->bytesLabel = CreateWindowExW(0, L"STATIC", L"Waiting for response...",
            WS_CHILD | WS_VISIBLE, 20, 160, 520, 20, hwnd, nullptr, instance, nullptr);
        applyControlFont(state->bytesLabel, defaultFont);
        return 0;
    }
    case WM_APP_SET_STATUS: {
        StringMessage* payload = reinterpret_cast<StringMessage*>(lParam);
        if (state != nullptr && payload != nullptr && state->statusLabel != nullptr) {
            SetWindowTextW(state->statusLabel, payload->text.c_str());
        }
        delete payload;
        return 0;
    }
    case WM_APP_SET_FILE_INFO: {
        FileInfoMessage* payload = reinterpret_cast<FileInfoMessage*>(lParam);
        if (state != nullptr && payload != nullptr) {
            std::wstring assetText = L"GitHub asset: " + payload->assetName;
            if (!payload->releaseTag.empty()) {
                assetText += L" (" + payload->releaseTag + L")";
            }
            SetWindowTextW(state->assetLabel, assetText.c_str());
            SetWindowTextW(state->targetLabel, (L"Saving as: " + payload->targetPath).c_str());
        }
        delete payload;
        return 0;
    }
    case WM_APP_SET_PROGRESS: {
        ProgressMessage* payload = reinterpret_cast<ProgressMessage*>(lParam);
        if (state != nullptr && payload != nullptr && state->progressBar != nullptr && state->bytesLabel != nullptr) {
            int percent = payload->percent < 0 ? 0 : payload->percent;
            SendMessageW(state->progressBar, PBM_SETPOS, percent, 0);
            if (payload->totalBytes > 0) {
                std::wstring text = formatBytes(payload->bytesRead) + L" / " + formatBytes(payload->totalBytes);
                SetWindowTextW(state->bytesLabel, text.c_str());
            } else {
                SetWindowTextW(state->bytesLabel, formatBytes(payload->bytesRead).c_str());
            }
        }
        delete payload;
        return 0;
    }
    case WM_APP_COMPLETE: {
        CompletionMessage* payload = reinterpret_cast<CompletionMessage*>(lParam);
        if (state != nullptr && payload != nullptr) {
            state->finished = true;
            state->success = payload->success;
            state->finalMessage = payload->text;
        }
        delete payload;
        DestroyWindow(hwnd);
        return 0;
    }
    case WM_CLOSE:
        if (state != nullptr && !state->finished) {
            return 0;
        }
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    case WM_NCDESTROY:
        if (state != nullptr && state->headingFont != nullptr) {
            DeleteObject(state->headingFont);
            state->headingFont = nullptr;
        }
        return 0;
    default:
        return DefWindowProcW(hwnd, message, wParam, lParam);
    }
}

static bool registerWindowClass(HINSTANCE instance) {
    WNDCLASSEXW windowClass{};
    windowClass.cbSize = sizeof(windowClass);
    windowClass.lpfnWndProc = windowProc;
    windowClass.hInstance = instance;
    windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(1));
    windowClass.hIconSm = LoadIconW(instance, MAKEINTRESOURCEW(1));
    windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    windowClass.lpszClassName = kWindowClassName;
    return RegisterClassExW(&windowClass) != 0 || GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
}

static HWND createMainWindow(HINSTANCE instance, WindowState* state) {
    int width = 580;
    int height = 235;
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    int x = std::max(0, (screenWidth - width) / 2);
    int y = std::max(0, (screenHeight - height) / 2);

    return CreateWindowExW(
        WS_EX_DLGMODALFRAME | WS_EX_TOPMOST,
        kWindowClassName,
        kInstallerTitle,
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        x,
        y,
        width,
        height,
        nullptr,
        nullptr,
        instance,
        state
    );
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int) {
    INITCOMMONCONTROLSEX controls{};
    controls.dwSize = sizeof(controls);
    controls.dwICC = ICC_PROGRESS_CLASS;
    InitCommonControlsEx(&controls);

    if (!registerWindowClass(instance)) {
        MessageBoxW(nullptr, L"The downloader window could not be created.", kInstallerTitle, MB_OK | MB_ICONERROR | MB_TOPMOST);
        return 1;
    }

    WindowState state;
    HWND hwnd = createMainWindow(instance, &state);
    if (hwnd == nullptr) {
        MessageBoxW(nullptr, L"The downloader window could not be created.", kInstallerTitle, MB_OK | MB_ICONERROR | MB_TOPMOST);
        return 1;
    }
    state.hwnd = hwnd;

    WorkerContext workerContext;
    workerContext.hwnd = hwnd;

    HANDLE workerThread = CreateThread(nullptr, 0, downloadWorkerProc, &workerContext, 0, nullptr);
    if (workerThread == nullptr) {
        DestroyWindow(hwnd);
        MessageBoxW(nullptr, L"The downloader worker could not be started.", kInstallerTitle, MB_OK | MB_ICONERROR | MB_TOPMOST);
        return 1;
    }

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }

    WaitForSingleObject(workerThread, INFINITE);
    CloseHandle(workerThread);

    UINT flags = MB_OK | MB_TOPMOST | (state.success ? MB_ICONINFORMATION : MB_ICONERROR);
    std::wstring finalMessage = state.finalMessage.empty()
        ? (state.success ? L"Toolscreen has been downloaded." : L"Toolscreen download failed.")
        : state.finalMessage;
    MessageBoxW(nullptr, finalMessage.c_str(), kInstallerTitle, flags);
    return state.success ? 0 : 1;
}