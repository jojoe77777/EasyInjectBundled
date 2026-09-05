#pragma once
#include "../third_party/nlohmann/json.hpp"
#include "../third_party/sqlite/sqlite3.h"
#include <filesystem>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace Modrinth {
using Json = nlohmann::ordered_json;
namespace fs = std::filesystem;
struct Profile {
    fs::path database;
    std::string path;
};

class Database {
    sqlite3 *db_ = nullptr;

  public:
    explicit Database(const fs::path &path, bool writable = false) {
        // Never create an empty database in a guessed location.
        int rc = sqlite3_open_v2(path.u8string().c_str(), &db_, writable ? SQLITE_OPEN_READWRITE : SQLITE_OPEN_READONLY,
                                 nullptr);
        if (rc != SQLITE_OK) {
            std::string error = db_ ? sqlite3_errmsg(db_) : "Cannot open database";
            if (db_)
                sqlite3_close(db_);
            throw std::runtime_error(error);
        }
        sqlite3_busy_timeout(db_, 5000);
    }
    ~Database() { sqlite3_close(db_); }
    Database(const Database &) = delete;
    Database &operator=(const Database &) = delete;
    sqlite3 *get() const { return db_; }
    void exec(const char *sql) {
        if (sqlite3_exec(db_, sql, nullptr, nullptr, nullptr) != SQLITE_OK)
            throw std::runtime_error(sqlite3_errmsg(db_));
    }
};

class Statement {
    sqlite3_stmt *stmt_ = nullptr;
    sqlite3 *db_;

  public:
    Statement(Database &db, const char *sql) : db_(db.get()) {
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt_, nullptr) != SQLITE_OK)
            throw std::runtime_error(sqlite3_errmsg(db_));
    }
    ~Statement() { sqlite3_finalize(stmt_); }
    Statement(const Statement &) = delete;
    Statement &operator=(const Statement &) = delete;
    void bind(int index, const std::string &text) {
        if (sqlite3_bind_text(stmt_, index, text.data(), static_cast<int>(text.size()), SQLITE_TRANSIENT) != SQLITE_OK)
            throw std::runtime_error(sqlite3_errmsg(db_));
    }
    void null(int index) { sqlite3_bind_null(stmt_, index); }
    bool row() {
        int rc = sqlite3_step(stmt_);
        if (rc != SQLITE_ROW && rc != SQLITE_DONE)
            throw std::runtime_error(sqlite3_errmsg(db_));
        return rc == SQLITE_ROW;
    }
    std::string text(int column) {
        const auto *value = sqlite3_column_text(stmt_, column);
        return value ? reinterpret_cast<const char *>(value) : "";
    }
};

inline bool currentSchema(Database &db) {
    Statement query(db, "SELECT 1 FROM sqlite_master WHERE type='table' AND name='instance_launch_overrides'");
    return query.row();
}
inline bool contains(Database &db, const std::string &path) {
    Statement query(db,
                    currentSchema(db) ? "SELECT 1 FROM instances WHERE path=?" : "SELECT 1 FROM profiles WHERE path=?");
    query.bind(1, path);
    return query.row();
}
inline std::optional<Profile> detect(const fs::path &directory, const std::vector<fs::path> &extraDatabases = {}) {
    auto dir = fs::weakly_canonical(directory);
    if (dir.filename() == L"minecraft" || dir.filename() == L".minecraft")
        dir = dir.parent_path();
    if (dir.parent_path().filename() != L"profiles")
        return {};
    auto candidates = extraDatabases;
    candidates.insert(candidates.begin(), dir.parent_path().parent_path() / L"app.db");
    std::string error;
    for (const auto &database : candidates) {
        if (!fs::is_regular_file(database))
            continue;
        try {
            Database db(database);
            if (contains(db, dir.filename().u8string()))
                return Profile{database, dir.filename().u8string()};
        } catch (const std::exception &e) {
            error = "Cannot read Modrinth database " + database.u8string() + ": " + e.what();
        }
    }
    if (!error.empty())
        throw std::runtime_error(error);
    return {};
}

// Read-modify-write under one writer transaction so another app cannot lose
// unrelated launch overrides between our SELECT and UPDATE. WAL remains intact.
inline void update(const Profile &profile, const std::optional<std::string> &command,
                   const std::function<bool(const std::string &)> &isOurs) {
    Database db(profile.database, true);
    db.exec("BEGIN IMMEDIATE");
    try {
        bool current = currentSchema(db);
        std::string id, existing;
        Json overrides = Json::object();
        {
            Statement query(db, current ? "SELECT i.id, json(o.overrides) FROM instances i LEFT JOIN "
                                          "instance_launch_overrides o ON o.instance_id=i.id WHERE i.path=?"
                                        : "SELECT path, override_hook_pre_launch FROM profiles WHERE path=?");
            query.bind(1, profile.path);
            if (!query.row())
                throw std::runtime_error("Modrinth instance was not found in its database");
            id = query.text(0);
            if (current) {
                auto text = query.text(1);
                if (!text.empty() && text != "null")
                    overrides = Json::parse(text);
                if (!overrides.is_object())
                    throw std::runtime_error("Invalid Modrinth launch overrides");
                if (overrides.contains("hooks")) {
                    const auto &hooks = overrides["hooks"];
                    if (!hooks.is_object())
                        throw std::runtime_error("Invalid Modrinth hooks");
                    if (hooks.contains("pre_launch") && !hooks["pre_launch"].is_null())
                        existing = hooks["pre_launch"].get<std::string>();
                }
            } else
                existing = query.text(1);
        }
        if (!existing.empty() && !isOurs(existing))
            throw std::runtime_error("This Modrinth instance has another pre-launch hook. Remove it in the instance "
                                     "options before changing this integration.");
        if (current) {
            if (command) {
                if (!overrides.contains("hooks"))
                    overrides["hooks"] = Json::object();
                overrides["hooks"]["pre_launch"] = *command;
            } else if (overrides.contains("hooks")) {
                overrides["hooks"].erase("pre_launch");
                if (overrides["hooks"].empty())
                    overrides.erase("hooks");
            }
            Statement write(db, "INSERT INTO instance_launch_overrides(instance_id,overrides) VALUES(?,jsonb(?)) ON "
                                "CONFLICT(instance_id) DO UPDATE SET overrides=excluded.overrides");
            write.bind(1, id);
            write.bind(2, overrides.dump());
            write.row();
        } else {
            Statement write(db, "UPDATE profiles SET override_hook_pre_launch=? WHERE path=?");
            if (command)
                write.bind(1, *command);
            else
                write.null(1);
            write.bind(2, profile.path);
            write.row();
        }
        db.exec("COMMIT");
    } catch (...) {
        try {
            db.exec("ROLLBACK");
        } catch (...) {
        }
        throw;
    }
}
} // namespace Modrinth
