#include "../common/launcher_support.h"
#include "../common/modrinth.h"
#include "../common/prelaunch.h"
#include <iostream>
#include <windows.h>

static void require(bool value, const char *message) {
    if (!value)
        throw std::runtime_error(message);
}
template <class F> static void rejects(F f, const char *message) {
    bool threw = false;
    try {
        f();
    } catch (const std::exception &) {
        threw = true;
    }
    require(threw, message);
}
static void createDatabase(const std::filesystem::path &path, const char *schema) {
    sqlite3 *db = nullptr;
    require(sqlite3_open(path.u8string().c_str(), &db) == SQLITE_OK, "create fixture");
    int rc = sqlite3_exec(db, schema, nullptr, nullptr, nullptr);
    sqlite3_close(db);
    require(rc == SQLITE_OK, "create schema");
}
static std::string scalar(Modrinth::Database &db, const char *sql) {
    Modrinth::Statement s(db, sql);
    require(s.row(), "missing row");
    return s.text(0);
}

int main() {
    namespace fs = std::filesystem;
    auto root =
        fs::temp_directory_path() / (L"EasyInject parity \u914d\u7f6e " + std::to_wstring(GetCurrentProcessId()));
    try {
        const std::string base = "\"$INST_DIR/Toolscreen.exe\" --prelaunch";
        const std::string external = "\"C:\\Program Files\\helper.exe\" \"a & b; c\"";
        auto plan = Prelaunch::merge(external, base, "Toolscreen");
        require(plan.needsChoice && plan.replace == base, "keep/replace choices");
        require(Prelaunch::forwarded(plan.keep) == external, "forward quotes and backslashes");
        require(Prelaunch::decodeIni(Prelaunch::encodeIni(plan.keep)) == plan.keep, "INI transport");
        auto tokens =
            Prelaunch::merge("\"$INST_JAVA\" -jar \"$INST_DIR/helper.jar\" $INST_JAVA_ARGS", base, "Toolscreen");
        require(tokens.keep.find("--chain-java \"$INST_JAVA\"") != tokens.keep.npos &&
                    tokens.keep.find("--chain-dir \"$INST_DIR\"") != tokens.keep.npos,
                "launcher placeholders remain available for launcher expansion");
        require(Prelaunch::expandTokens("$INST_DIR $INST_DIRECTORY $INST_NAME",
                                        [](const std::string &name, const std::string &) {
                                            return name == "INST_DIR" ? "C:/a b" : "test";
                                        }) == "C:/a b $INST_DIRECTORY test",
                "expand only complete known placeholders");
        auto reinstall = Prelaunch::merge(plan.keep, base, "Toolscreen");
        require(!reinstall.needsChoice && reinstall.keep == plan.keep, "idempotent reinstall preserves chain");
        auto migrate = Prelaunch::merge("\"$INST_JAVA\" -jar \"$INST_DIR/Toolscreen.jar\" --prelaunch && echo old",
                                        base, "Toolscreen");
        require(Prelaunch::forwarded(migrate.keep) == "echo old", "replace JAR without running it twice");
        require(!Prelaunch::isOurs("echo Toolscreen.exe --prelaunch", "Toolscreen"),
                "foreign command mentioning brand");
        require(!Prelaunch::isOurs("\"C:/OtherToolscreen.exe\" --prelaunch", "Toolscreen"),
                "foreign executable suffix");
        require(Prelaunch::split("echo \"a;b&&c\" && echo next; echo last").size() == 3, "split only outside quotes");
        require(Prelaunch::forwarded(R"(Toolscreen.jar --prelaunch --run-prelaunch-chain "echo C:\\test\\path")") ==
                    "echo C:\\test\\path",
                "legacy JAR forwarding");
        rejects([] { Prelaunch::unhex("xyz"); }, "invalid encoded chain");
        require(LauncherSupport::isMinecraft("java net.minecraft.client.main.Main"), "vanilla entry point");
        require(LauncherSupport::isMinecraft("java net.fabricmc.loader.impl.launch.knot.KnotClient"),
                "Fabric entry point");
        require(!LauncherSupport::isMinecraft("java -jar ATLauncher.jar"), "do not inject launcher");
        require(!LauncherSupport::isMinecraft("java -Ddescription=net.minecraft.client.main.Main OtherApp"),
                "entry point must be an argument");
        require(LauncherSupport::isAtLauncher("java -jar C:/Apps/ATLauncher.jar"), "AT JAR detection");
        require(!LauncherSupport::isAtLauncher("java -cp ATLauncher.jar AnotherApp"),
                "do not mistake a classpath dependency for ATLauncher");
        fs::create_directories(root / "profiles" / "quoted ' profile" / "minecraft");
        auto old = root / "app.db";
        createDatabase(old, "CREATE TABLE profiles(path TEXT PRIMARY KEY, override_hook_pre_launch TEXT, memory "
                            "INTEGER); INSERT INTO profiles VALUES('quoted '' profile',NULL,4096); INSERT INTO "
                            "profiles VALUES('other','echo sentinel',1234);");
        auto profile = Modrinth::detect(root / "profiles" / "quoted ' profile" / "minecraft");
        require(profile.has_value(), "legacy profile and minecraft subdirectory detection");
        auto ours = [](const std::string &s) { return Prelaunch::isOurs(s, "Toolscreen"); };
        Modrinth::update(*profile, base, ours);
        Modrinth::update(*profile, base, ours);
        {
            Modrinth::Database db(old);
            require(scalar(db, "SELECT override_hook_pre_launch FROM profiles WHERE memory=4096") == base,
                    "legacy install");
            require(scalar(db, "SELECT override_hook_pre_launch FROM profiles WHERE path='other'") == "echo sentinel",
                    "other profile unchanged");
        }
        Modrinth::update(*profile, std::nullopt, ours);
        {
            Modrinth::Database db(old);
            require(scalar(db, "SELECT override_hook_pre_launch IS NULL FROM profiles WHERE memory=4096") == "1",
                    "legacy uninstall null");
        }
        rejects([&] { Modrinth::update({old, "other"}, base, ours); }, "foreign hook preserved");
        rejects([&] { Modrinth::update({old, "missing"}, base, ours); }, "missing profile rejected");
        // Current schema with JSONB and a custom profiles directory separate from app.db.
        auto modern = root / "settings" / "app.db";
        fs::create_directories(modern.parent_path());
        createDatabase(modern,
                       "PRAGMA journal_mode=WAL; CREATE TABLE instances(id TEXT PRIMARY KEY,path TEXT); CREATE TABLE "
                       "instance_launch_overrides(instance_id TEXT PRIMARY KEY,overrides BLOB); INSERT INTO instances "
                       "VALUES('id1','custom'); INSERT INTO instances VALUES('id2','empty'); INSERT INTO "
                       "instance_launch_overrides VALUES('id1',jsonb('{\"memory\":8192,\"hooks\":{\"post_exit\":\"echo "
                       "done\"},\"java\":\"ARM64\"}'));");
        fs::create_directories(root / "custom" / "profiles" / "custom");
        auto current = Modrinth::detect(root / "custom" / "profiles" / "custom", {modern});
        require(current.has_value(), "custom database discovery");
        {
            std::ofstream stale(root / "custom" / "app.db");
            stale << "not a database";
        }
        require(Modrinth::detect(root / "custom" / "profiles" / "custom", {modern}).has_value(),
                "stale adjacent database does not hide custom database");
        Modrinth::update(*current, base, ours);
        {
            Modrinth::Database db(modern);
            auto j = Modrinth::Json::parse(
                scalar(db, "SELECT json(overrides) FROM instance_launch_overrides WHERE instance_id='id1'"));
            require(j["hooks"]["pre_launch"] == base && j["hooks"]["post_exit"] == "echo done" && j["memory"] == 8192 &&
                        j["java"] == "ARM64",
                    "preserve JSONB siblings");
            require(scalar(db, "PRAGMA journal_mode") == "wal", "preserve WAL mode");
        }
        Modrinth::update(*current, std::nullopt, ours);
        {
            Modrinth::Database db(modern);
            auto j = Modrinth::Json::parse(
                scalar(db, "SELECT json(overrides) FROM instance_launch_overrides WHERE instance_id='id1'"));
            require(!j["hooks"].contains("pre_launch") && j["hooks"]["post_exit"] == "echo done", "current uninstall");
        }
        Modrinth::update({modern, "empty"}, base, ours);
        Modrinth::update({modern, "empty"}, std::nullopt, ours);
        {
            Modrinth::Database db(modern);
            require(scalar(db, "SELECT json(overrides) FROM instance_launch_overrides WHERE instance_id='id2'") == "{}",
                    "create missing overrides and clear empty hooks");
        }
        {
            Modrinth::Database db(modern, true);
            db.exec("UPDATE instance_launch_overrides SET overrides=jsonb('{\"hooks\":[]}') WHERE instance_id='id1'");
        }
        rejects([&] { Modrinth::update(*current, base, ours); }, "malformed hooks rejected");
        {
            Modrinth::Database db(modern);
            require(scalar(db, "SELECT json(overrides) FROM instance_launch_overrides WHERE instance_id='id1'") ==
                        "{\"hooks\":[]}",
                    "rollback on invalid overrides");
        }
        {
            Modrinth::Database lock(modern, true);
            lock.exec("BEGIN IMMEDIATE");
            rejects([&] { Modrinth::update({modern, "empty"}, base, ours); }, "busy database fails without overwrite");
            lock.exec("ROLLBACK");
        }
        rejects([&] { Modrinth::Database db(root / "missing.db", true); }, "no accidental database creation");
        require(!fs::exists(root / "missing.db"), "missing database not created");
        fs::create_directories(root / "mcsr");
        {
            std::ofstream file(root / "mcsr" / "instance.json");
            file << R"({"lwjglVersion":{},"minecraftVersion":"1.16.1","displayName":"Ranked"})";
        }
        require(LauncherSupport::isMcsr(root / "mcsr"), "managed MCSR instance");
        fs::remove_all(root);
        std::cout << "PASS: command migration/transport, launcher detection, legacy/current Modrinth, Unicode/custom "
                     "paths, JSONB preservation, uninstall, foreign hooks, missing/locked/invalid databases\n";
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "FAIL: " << e.what() << "; fixtures at " << root.u8string() << '\n';
        return 1;
    }
}
