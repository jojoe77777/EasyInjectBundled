#pragma once
#include <algorithm>
#include <cctype>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

namespace Prelaunch {
inline std::string trim(const std::string &s) {
    auto first = s.find_first_not_of(" \r\n\t");
    return first == s.npos ? "" : s.substr(first, s.find_last_not_of(" \r\n\t") - first + 1);
}
inline std::string lower(std::string s) {
    for (auto &c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}
inline std::string decodeIni(std::string s) {
    s = trim(s);
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"')
        s = s.substr(1, s.size() - 2);
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            char c = s[++i];
            if (c == 'n')
                out += '\n';
            else if (c == 'r')
                out += '\r';
            else if (c == 't')
                out += '\t';
            else if (c == '\\' || c == '"')
                out += c;
            else {
                out += '\\';
                out += c;
            }
        } else
            out += s[i];
    }
    return out;
}
inline std::string encodeIni(const std::string &s) {
    std::string out;
    for (char c : s) {
        if (c == '\\' || c == '"') {
            out += '\\';
            out += c;
        } else if (c == '\n')
            out += "\\n";
        else if (c == '\r')
            out += "\\r";
        else
            out += c;
    }
    return out;
}
inline std::string hex(const std::string &s) {
    std::string out;
    for (unsigned char c : s) {
        out += "0123456789abcdef"[c >> 4];
        out += "0123456789abcdef"[c & 15];
    }
    return out;
}
inline std::string unhex(const std::string &s) {
    if (s.empty() || s.size() % 2)
        throw std::runtime_error("Invalid prelaunch chain encoding");
    auto digit = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        throw std::runtime_error("Invalid prelaunch chain encoding");
    };
    std::string out;
    for (size_t i = 0; i < s.size(); i += 2)
        out += static_cast<char>((digit(s[i]) << 4) | digit(s[i + 1]));
    if (out.find('\0') != out.npos)
        throw std::runtime_error("Invalid prelaunch chain NUL");
    return out;
}
inline std::string unwrap(std::string s) {
    s = trim(s);
    auto l = lower(s);
    size_t n = l.rfind("cmd.exe /c ", 0) == 0 ? 11 : l.rfind("cmd /c ", 0) == 0 ? 7 : 0;
    if (n) {
        s = trim(s.substr(n));
        if (s.size() > 1 && s.front() == '"' && s.back() == '"')
            s = s.substr(1, s.size() - 2);
    }
    return s;
}
inline std::vector<std::string> split(const std::string &value) {
    auto s = unwrap(value);
    std::vector<std::string> parts;
    bool quoted = false;
    size_t start = 0, slashes = 0;
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == '"' && slashes % 2 == 0)
            quoted = !quoted;
        if (!quoted && (c == ';' || (c == '&' && i + 1 < s.size() && s[i + 1] == '&'))) {
            auto part = trim(s.substr(start, i - start));
            if (!part.empty())
                parts.push_back(part);
            if (c == '&')
                ++i;
            start = i + 1;
        }
        slashes = c == '\\' ? slashes + 1 : 0;
    }
    auto part = trim(s.substr(start));
    if (!part.empty())
        parts.push_back(part);
    return parts;
}
// Tokenize the quoting used by Windows process arguments without treating
// backslashes in filesystem paths as generic escape characters.
inline std::vector<std::string> arguments(const std::string &command) {
    std::vector<std::string> out;
    size_t i = 0;
    while (i < command.size()) {
        while (i < command.size() && (command[i] == ' ' || command[i] == '\t'))
            ++i;
        if (i == command.size())
            break;
        std::string arg;
        bool quoted = false;
        while (i < command.size()) {
            if (!quoted && (command[i] == ' ' || command[i] == '\t'))
                break;
            size_t slashes = 0;
            while (i < command.size() && command[i] == '\\') {
                ++slashes;
                ++i;
            }
            if (i < command.size() && command[i] == '"') {
                arg.append(slashes / 2, '\\');
                if (slashes % 2)
                    arg += '"';
                else
                    quoted = !quoted;
                ++i;
            } else {
                arg.append(slashes, '\\');
                if (i < command.size())
                    arg += command[i++];
            }
        }
        out.push_back(arg);
    }
    return out;
}
inline bool isOurs(const std::string &command, const std::string &brand) {
    auto args = arguments(unwrap(command));
    if (args.empty() || std::find(args.begin(), args.end(), "--prelaunch") == args.end())
        return false;
    auto basename = [](std::string s) {
        s = lower(s);
        return s.substr(s.find_last_of("/\\") == s.npos ? 0 : s.find_last_of("/\\") + 1);
    };
    std::string executable = basename(args[0]), payload = executable;
    if (executable == "java" || executable == "java.exe" || executable == "javaw" || executable == "javaw.exe" ||
        executable == "$inst_java") {
        auto jar = std::find(args.begin(), args.end(), "-jar");
        if (jar == args.end() || ++jar == args.end())
            return false;
        payload = basename(*jar);
    }
    auto b = lower(brand);
    if (payload == b + ".exe" || payload == b + ".jar")
        return true;
    return payload.rfind(b + "-", 0) == 0 && payload.size() > 4 &&
           (payload.substr(payload.size() - 4) == ".exe" || payload.substr(payload.size() - 4) == ".jar");
}
inline std::string forwarded(const std::string &command) {
    const std::string hexFlag = "--run-prelaunch-chain-hex ";
    auto p = command.find(hexFlag);
    if (p != command.npos) {
        auto value = trim(command.substr(p + hexFlag.size()));
        return unhex(value.substr(0, value.find_first_of(" \t")));
    }
    const std::string oldFlag = "--run-prelaunch-chain";
    p = command.find(oldFlag);
    if (p == command.npos)
        return "";
    auto rest = trim(command.substr(p + oldFlag.size()));
    // Legacy JAR transport escapes both quotes and backslashes. Remove only
    // its argument envelope; keep all path backslashes during the one decode.
    if (rest.size() >= 4 && rest.rfind("\\\"", 0) == 0 && rest.substr(rest.size() - 2) == "\\\"")
        rest = rest.substr(2, rest.size() - 4);
    else if (rest.size() >= 2 && rest.front() == '"' && rest.back() == '"')
        rest = rest.substr(1, rest.size() - 2);
    std::string out;
    for (size_t i = 0; i < rest.size(); ++i) {
        if (rest[i] == '\\' && i + 1 < rest.size() && (rest[i + 1] == '\\' || rest[i + 1] == '"'))
            ++i;
        out += rest[i];
    }
    return out;
}
struct Merge {
    std::string keep;
    std::string replace;
    bool needsChoice = false;
};
inline const std::vector<std::pair<std::string, std::string>> &launcherTokens() {
    static const std::vector<std::pair<std::string, std::string>> tokens = {
        {"INST_JAVA_ARGS", "--chain-java-args"}, {"INST_MC_DIR", "--chain-mc-dir"}, {"INST_JAVA", "--chain-java"},
        {"INST_NAME", "--chain-name"},           {"INST_DIR", "--chain-dir"},       {"INST_ID", "--chain-id"}};
    return tokens;
}
inline std::string tokenArguments(const std::string &chain) {
    std::string result;
    // Keep referenced launcher placeholders outside the encoded payload so the
    // launcher can expand them. ATLauncher does not export them as environment variables.
    for (const auto &token : launcherTokens()) {
        const auto placeholder = "$" + token.first;
        if (chain.find(placeholder) != chain.npos)
            result += " " + token.second + " \"" + placeholder + "\"";
    }
    return result;
}
inline std::string expandTokens(const std::string &chain,
                                const std::function<std::string(const std::string &, const std::string &)> &value) {
    std::string out;
    for (size_t i = 0; i < chain.size();) {
        bool matched = false;
        for (const auto &token : launcherTokens()) {
            auto placeholder = "$" + token.first;
            auto end = i + placeholder.size();
            if (chain.compare(i, placeholder.size(), placeholder) == 0 &&
                (end == chain.size() || !(std::isalnum(static_cast<unsigned char>(chain[end])) || chain[end] == '_'))) {
                out += value(token.first, token.second);
                i = end;
                matched = true;
                break;
            }
        }
        if (!matched)
            out += chain[i++];
    }
    return out;
}
inline Merge merge(const std::string &existing, const std::string &command, const std::string &brand) {
    Merge result{unwrap(command), unwrap(command), false};
    if (result.replace.empty())
        return result;
    std::vector<std::string> chain;
    for (const auto &part : split(existing)) {
        if (isOurs(part, brand)) {
            auto old = forwarded(part);
            if (!old.empty())
                chain.push_back(old);
        } else {
            chain.push_back(part);
            result.needsChoice = true;
        }
    }
    std::string joined;
    for (const auto &part : chain) {
        if (!joined.empty())
            joined += " && ";
        joined += part;
    }
    if (!joined.empty())
        result.keep += " --run-prelaunch-chain-hex " + hex(joined) + tokenArguments(joined);
    return result;
}
} // namespace Prelaunch
