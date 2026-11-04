#pragma once
// Waymark keeps each instance's settings in instance.toml, with the game in a
// "game" folder beside it and a waymark.lock next to both. It runs the top-level
// preLaunch command from the game folder through cmd, with the same INST_*
// environment variables as Prism, so only that one key is ever touched here.

#include <cwctype>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace InstanceToml {

// The instance.toml for a Waymark game folder, or empty for anything else.
inline std::filesystem::path waymarkFile(const std::filesystem::path &gameDir) {
    std::error_code error;
    auto name = gameDir.filename().wstring();
    for (auto &c : name)
        c = static_cast<wchar_t>(towlower(c));
    if (name != L"game")
        return {};
    const auto root = gameDir.parent_path();
    if (std::filesystem::is_regular_file(root / L"instance.toml", error) &&
        std::filesystem::is_regular_file(root / L"waymark.lock", error))
        return root / L"instance.toml";
    return {};
}

inline std::string trim(const std::string &s) {
    auto first = s.find_first_not_of(" \t\r\n");
    return first == s.npos ? "" : s.substr(first, s.find_last_not_of(" \t\r\n") - first + 1);
}

struct Layout {
    std::optional<size_t> preLaunch; // line of the top-level preLaunch key
    size_t firstTable;               // line of the first [table] header, or the line count
};

// Finds where the top-level keys end. Arrays can span lines, and a line inside one
// may start with "[", so brackets and strings are followed rather than guessed.
inline Layout layout(const std::vector<std::string> &lines) {
    Layout found{std::nullopt, lines.size()};
    int depth = 0;
    enum { Plain, MultiBasic, MultiLiteral } state = Plain;
    for (size_t index = 0; index < lines.size(); ++index) {
        std::string line = lines[index];
        if (index == 0 && line.compare(0, 3, "\xEF\xBB\xBF") == 0)
            line.erase(0, 3);
        const auto text = trim(line);
        if (state == Plain && depth == 0) {
            if (!text.empty() && text.front() == '[') {
                found.firstTable = index;
                return found;
            }
            auto equals = text.find('=');
            if (equals != text.npos && trim(text.substr(0, equals)) == "preLaunch" && !found.preLaunch)
                found.preLaunch = index;
        }
        for (size_t i = 0; i < line.size(); ++i) {
            const char c = line[i];
            if (state == MultiBasic) {
                if (c == '\\')
                    ++i;
                else if (line.compare(i, 3, "\"\"\"") == 0) {
                    state = Plain;
                    i += 2;
                }
            } else if (state == MultiLiteral) {
                if (line.compare(i, 3, "'''") == 0) {
                    state = Plain;
                    i += 2;
                }
            } else if (c == '#') {
                break;
            } else if (line.compare(i, 3, "\"\"\"") == 0) {
                state = MultiBasic;
                i += 2;
            } else if (line.compare(i, 3, "'''") == 0) {
                state = MultiLiteral;
                i += 2;
            } else if (c == '"') {
                for (++i; i < line.size() && line[i] != '"'; ++i)
                    if (line[i] == '\\')
                        ++i;
            } else if (c == '\'') {
                i = line.find('\'', i + 1);
                if (i == line.npos)
                    break;
            } else if (c == '[' || c == '{') {
                ++depth;
            } else if ((c == ']' || c == '}') && depth > 0) {
                --depth;
            }
        }
    }
    return found;
}

inline void appendUtf8(std::string &out, unsigned long code) {
    if (code < 0x80) {
        out += static_cast<char>(code);
    } else if (code < 0x800) {
        out += static_cast<char>(0xC0 | (code >> 6));
        out += static_cast<char>(0x80 | (code & 0x3F));
    } else if (code < 0x10000) {
        out += static_cast<char>(0xE0 | (code >> 12));
        out += static_cast<char>(0x80 | ((code >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (code & 0x3F));
    } else {
        out += static_cast<char>(0xF0 | (code >> 18));
        out += static_cast<char>(0x80 | ((code >> 12) & 0x3F));
        out += static_cast<char>(0x80 | ((code >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (code & 0x3F));
    }
}

// The value of a one-line TOML string, with any comment after it ignored.
inline std::string decode(const std::string &raw) {
    const auto value = trim(raw);
    if (value.compare(0, 3, "\"\"\"") == 0 || value.compare(0, 3, "'''") == 0)
        throw std::runtime_error("This instance's pre-launch command spans several lines. Change it in Waymark first.");
    if (value.size() >= 2 && value.front() == '\'') {
        auto end = value.find('\'', 1);
        if (end == value.npos)
            throw std::runtime_error("Unclosed preLaunch string in instance.toml");
        return value.substr(1, end - 1);
    }
    if (value.empty() || value.front() != '"')
        throw std::runtime_error("preLaunch in instance.toml is not a string");
    std::string out;
    for (size_t i = 1; i < value.size(); ++i) {
        const char c = value[i];
        if (c == '"')
            return out;
        if (c != '\\') {
            out += c;
            continue;
        }
        if (++i == value.size())
            break;
        switch (value[i]) {
        case 'b': out += '\b'; break;
        case 't': out += '\t'; break;
        case 'n': out += '\n'; break;
        case 'f': out += '\f'; break;
        case 'r': out += '\r'; break;
        case '"': out += '"'; break;
        case '\\': out += '\\'; break;
        case 'u':
        case 'U': {
            const size_t digits = value[i] == 'u' ? 4 : 8;
            if (i + digits >= value.size())
                throw std::runtime_error("Invalid escape in preLaunch");
            appendUtf8(out, std::stoul(value.substr(i + 1, digits), nullptr, 16));
            i += digits;
            break;
        }
        default:
            throw std::runtime_error("Invalid escape in preLaunch");
        }
    }
    throw std::runtime_error("Unclosed preLaunch string in instance.toml");
}

inline std::string encode(const std::string &command) {
    std::string out = "\"";
    for (unsigned char c : command) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\t': out += "\\t"; break;
        case '\n': out += "\\n"; break;
        case '\f': out += "\\f"; break;
        case '\r': out += "\\r"; break;
        default:
            if (c < 0x20 || c == 0x7F) {
                static const char *hex = "0123456789ABCDEF";
                out += "\\u00";
                out += hex[c >> 4];
                out += hex[c & 15];
            } else {
                out += static_cast<char>(c);
            }
        }
    }
    return out + "\"";
}

inline std::string preLaunchCommand(const std::vector<std::string> &lines) {
    const auto found = layout(lines);
    if (!found.preLaunch)
        return {};
    const auto &line = lines[*found.preLaunch];
    return decode(line.substr(line.find('=') + 1));
}

// Sets the top-level preLaunch, or removes it when the command is empty.
// Everything else in the file is left exactly as it was.
inline std::vector<std::string> update(const std::vector<std::string> &lines, const std::string &command) {
    const auto found = layout(lines);
    std::vector<std::string> updated = lines;
    const bool installing = !trim(command).empty();
    const auto entry = "preLaunch = " + encode(command);
    const std::string bom = "\xEF\xBB\xBF";
    // A byte order mark has to stay at the very start of the file.
    const bool marked = !updated.empty() && updated.front().compare(0, 3, bom) == 0;
    if (marked)
        updated.front().erase(0, 3);
    if (found.preLaunch) {
        if (installing)
            updated[*found.preLaunch] = entry;
        else
            updated.erase(updated.begin() + static_cast<std::ptrdiff_t>(*found.preLaunch));
    } else if (installing) {
        // Waymark leaves a blank line before its first table, so the key goes above it.
        size_t at = found.firstTable;
        while (at > 0 && trim(updated[at - 1]).empty())
            --at;
        updated.insert(updated.begin() + static_cast<std::ptrdiff_t>(at), entry);
    }
    if (marked) {
        if (updated.empty())
            updated.push_back("");
        updated.front().insert(0, bom);
    }
    return updated;
}

} // namespace InstanceToml
