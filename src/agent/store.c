#include "agent_internal.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static maelys_git_result_t database_error(sqlite3 *db,
                                          maelys_git_error_t *error,
                                          const char *operation) {
    mg_error_set(error, MAELYS_GIT_ERR_IO, sqlite3_extended_errcode(db),
                 "%s: %s", operation, sqlite3_errmsg(db));
    return MAELYS_GIT_ERR_IO;
}

static int execute(sqlite3 *db, const char *sql) {
    return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
}

maelys_git_result_t mg_store_open(const char *path,
                                  maelys_git_agent_store_t **out,
                                  maelys_git_error_t *error) {
    if (!path || !out || path[0] != '/') return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    *out = NULL;
    struct stat status;
    int inspected = lstat(path, &status);
    if (inspected == 0) {
        if (!S_ISREG(status.st_mode) || S_ISLNK(status.st_mode)) {
            mg_error_set(error, MAELYS_GIT_ERR_DENIED, 0, "database path is not a regular file");
            return MAELYS_GIT_ERR_DENIED;
        }
    } else if (errno != ENOENT) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno, "cannot inspect database path");
        return MAELYS_GIT_ERR_IO;
    }
    maelys_git_agent_store_t *store = calloc(1u, sizeof(*store));
    if (!store) return MAELYS_GIT_ERR_IO;
    mode_t previous = umask(0077);
    int result = sqlite3_open_v2(path, &store->database,
                                 SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                                 SQLITE_OPEN_FULLMUTEX,
                                 NULL);
    (void)umask(previous);
    if (result != SQLITE_OK) {
        database_error(store->database, error, "cannot open agent database");
        mg_store_close(store);
        return MAELYS_GIT_ERR_IO;
    }
    (void)chmod(path, 0600);
    sqlite3_busy_timeout(store->database, 5000);
    sqlite3_extended_result_codes(store->database, 1);
    const char *schema =
        "PRAGMA journal_mode=WAL;"
        "PRAGMA synchronous=FULL;"
        "PRAGMA foreign_keys=ON;"
        "CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);"
        "CREATE TABLE IF NOT EXISTS commands("
        " id TEXT PRIMARY KEY, raw_json TEXT NOT NULL, command TEXT NOT NULL,"
        " state TEXT NOT NULL CHECK(state IN('pending','running','complete','failed')),"
        " result_json TEXT, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS outbox("
        " id TEXT PRIMARY KEY, kind TEXT NOT NULL, payload TEXT NOT NULL,"
        " attempts INTEGER NOT NULL DEFAULT 0, next_attempt_ms INTEGER NOT NULL,"
        " created_at_ms INTEGER NOT NULL, acked_at_ms INTEGER);"
        "CREATE INDEX IF NOT EXISTS outbox_pending ON outbox(acked_at_ms,next_attempt_ms,created_at_ms);"
        "CREATE TABLE IF NOT EXISTS audit("
        " sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE NOT NULL,"
        " kind TEXT NOT NULL, payload TEXT NOT NULL, created_at_ms INTEGER NOT NULL);"
        "UPDATE commands SET state='pending' WHERE state='running';";
    if (!execute(store->database, schema)) {
        database_error(store->database, error, "cannot initialize agent database");
        mg_store_close(store);
        return MAELYS_GIT_ERR_IO;
    }
    char sidecar[4096 + 8u];
    int sidecar_length = snprintf(sidecar, sizeof(sidecar), "%s-wal", path);
    if (sidecar_length > 0 && (size_t)sidecar_length < sizeof(sidecar)) (void)chmod(sidecar, 0600);
    sidecar_length = snprintf(sidecar, sizeof(sidecar), "%s-shm", path);
    if (sidecar_length > 0 && (size_t)sidecar_length < sizeof(sidecar)) (void)chmod(sidecar, 0600);
    *out = store;
    return MAELYS_GIT_OK;
}

void mg_store_close(maelys_git_agent_store_t *store) {
    if (!store) return;
    if (store->database) sqlite3_close(store->database);
    free(store);
}

static mg_store_command_state_t decode_state(const unsigned char *state) {
    if (!state) return MG_STORE_COMMAND_NEW;
    if (strcmp((const char *)state, "pending") == 0) return MG_STORE_COMMAND_PENDING;
    if (strcmp((const char *)state, "running") == 0) return MG_STORE_COMMAND_RUNNING;
    if (strcmp((const char *)state, "complete") == 0) return MG_STORE_COMMAND_COMPLETE;
    return MG_STORE_COMMAND_FAILED;
}

maelys_git_result_t mg_store_record_command(maelys_git_agent_store_t *store,
                                            const mg_agent_message_t *message,
                                            const char *raw_json,
                                            mg_store_command_state_t *out_state,
                                            char **out_result,
                                            maelys_git_error_t *error) {
    if (!store || !message || !raw_json || !out_state || !out_result) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    *out_result = NULL;
    sqlite3_stmt *statement = NULL;
    const char *insert = "INSERT OR IGNORE INTO commands"
        "(id,raw_json,command,state,created_at_ms,updated_at_ms) VALUES(?,?,?,'pending',?,?)";
    if (sqlite3_prepare_v2(store->database, insert, -1, &statement, NULL) != SQLITE_OK)
        return database_error(store->database, error, "prepare command insert");
    int64_t now = mg_now_ms();
    sqlite3_bind_text(statement, 1, message->message_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, raw_json, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 3, message->command, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 4, now);
    sqlite3_bind_int64(statement, 5, now);
    int step = sqlite3_step(statement);
    int inserted = sqlite3_changes(store->database) == 1;
    sqlite3_finalize(statement);
    if (step != SQLITE_DONE) return database_error(store->database, error, "insert command");
    if (inserted) { *out_state = MG_STORE_COMMAND_NEW; return MAELYS_GIT_OK; }

    const char *select = "SELECT raw_json,state,result_json FROM commands WHERE id=?";
    if (sqlite3_prepare_v2(store->database, select, -1, &statement, NULL) != SQLITE_OK)
        return database_error(store->database, error, "prepare command lookup");
    sqlite3_bind_text(statement, 1, message->message_id, -1, SQLITE_TRANSIENT);
    step = sqlite3_step(statement);
    if (step != SQLITE_ROW) {
        sqlite3_finalize(statement);
        return database_error(store->database, error, "lookup command");
    }
    const char *stored = (const char *)sqlite3_column_text(statement, 0);
    if (!stored || strcmp(stored, raw_json) != 0) {
        sqlite3_finalize(statement);
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0,
                     "message_id was reused with different content");
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    *out_state = decode_state(sqlite3_column_text(statement, 1));
    const unsigned char *result_json = sqlite3_column_text(statement, 2);
    if (result_json) *out_result = strdup((const char *)result_json);
    sqlite3_finalize(statement);
    if (result_json && !*out_result) return MAELYS_GIT_ERR_IO;
    return MAELYS_GIT_OK;
}

maelys_git_result_t mg_store_mark_running(maelys_git_agent_store_t *store,
                                          const char *command_id,
                                          maelys_git_error_t *error) {
    if (!store || !command_id) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    sqlite3_stmt *statement = NULL;
    const char *sql = "UPDATE commands SET state='running',updated_at_ms=? WHERE id=? AND state='pending'";
    if (sqlite3_prepare_v2(store->database, sql, -1, &statement, NULL) != SQLITE_OK)
        return database_error(store->database, error, "prepare running update");
    sqlite3_bind_int64(statement, 1, mg_now_ms());
    sqlite3_bind_text(statement, 2, command_id, -1, SQLITE_TRANSIENT);
    int step = sqlite3_step(statement);
    sqlite3_finalize(statement);
    if (step != SQLITE_DONE) return database_error(store->database, error, "mark command running");
    if (sqlite3_changes(store->database) != 1) {
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "command is not pending");
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    return MAELYS_GIT_OK;
}

maelys_git_result_t mg_store_enqueue(maelys_git_agent_store_t *store,
                                     const char *id,
                                     const char *kind,
                                     const char *payload,
                                     int64_t now_ms,
                                     maelys_git_error_t *error) {
    if (!store || !id || !kind || !payload) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    sqlite3_stmt *statement = NULL;
    const char *sql = "INSERT INTO outbox(id,kind,payload,next_attempt_ms,created_at_ms) VALUES(?,?,?,?,?) "
        "ON CONFLICT(id) DO UPDATE SET kind=excluded.kind,payload=excluded.payload,"
        "next_attempt_ms=excluded.next_attempt_ms,acked_at_ms=NULL";
    if (sqlite3_prepare_v2(store->database, sql, -1, &statement, NULL) != SQLITE_OK)
        return database_error(store->database, error, "prepare outbox insert");
    sqlite3_bind_text(statement, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, kind, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 3, payload, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 4, now_ms);
    sqlite3_bind_int64(statement, 5, now_ms);
    int step = sqlite3_step(statement);
    sqlite3_finalize(statement);
    return step == SQLITE_DONE ? MAELYS_GIT_OK : database_error(store->database, error, "enqueue outbox item");
}

maelys_git_result_t mg_store_complete_command(maelys_git_agent_store_t *store,
                                              const char *command_id,
                                              int succeeded,
                                              const char *result_json,
                                              int64_t now_ms,
                                              maelys_git_error_t *error) {
    if (!store || !command_id || !result_json) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    if (!execute(store->database, "BEGIN IMMEDIATE")) return database_error(store->database, error, "begin completion");
    sqlite3_stmt *statement = NULL;
    const char *sql = "UPDATE commands SET state=?,result_json=?,updated_at_ms=? WHERE id=? AND state='running'";
    int ok = sqlite3_prepare_v2(store->database, sql, -1, &statement, NULL) == SQLITE_OK;
    if (ok) {
        sqlite3_bind_text(statement, 1, succeeded ? "complete" : "failed", -1, SQLITE_STATIC);
        sqlite3_bind_text(statement, 2, result_json, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(statement, 3, now_ms);
        sqlite3_bind_text(statement, 4, command_id, -1, SQLITE_TRANSIENT);
        ok = sqlite3_step(statement) == SQLITE_DONE && sqlite3_changes(store->database) == 1;
    }
    sqlite3_finalize(statement);
    if (ok) ok = mg_store_enqueue(store, command_id, "command_result", result_json, now_ms, error) == MAELYS_GIT_OK;
    if (ok) {
        char event_id[MG_MESSAGE_ID_MAX + 16u];
        (void)snprintf(event_id, sizeof(event_id), "command:%s", command_id);
        ok = mg_store_audit(store, event_id, succeeded ? "command_complete" : "command_failed",
                            result_json, now_ms, error) == MAELYS_GIT_OK;
    }
    if (ok) ok = execute(store->database, "COMMIT");
    if (!ok) {
        (void)execute(store->database, "ROLLBACK");
        if (!error || error->code == MAELYS_GIT_OK)
            database_error(store->database, error, "complete command");
        return error ? error->code : MAELYS_GIT_ERR_IO;
    }
    return MAELYS_GIT_OK;
}

maelys_git_result_t mg_store_next_outbox(maelys_git_agent_store_t *store,
                                         int64_t now_ms,
                                         mg_outbox_item_t *out,
                                         maelys_git_error_t *error) {
    if (!store || !out) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    sqlite3_stmt *statement = NULL;
    const char *sql = "SELECT id,kind,payload,attempts FROM outbox "
                      "WHERE acked_at_ms IS NULL AND next_attempt_ms<=? ORDER BY created_at_ms LIMIT 1";
    if (sqlite3_prepare_v2(store->database, sql, -1, &statement, NULL) != SQLITE_OK)
        return database_error(store->database, error, "prepare outbox lookup");
    sqlite3_bind_int64(statement, 1, now_ms);
    int step = sqlite3_step(statement);
    if (step == SQLITE_DONE) { sqlite3_finalize(statement); return MAELYS_GIT_ERR_NOT_FOUND; }
    if (step != SQLITE_ROW ||
        !mg_copy_string(out->id, sizeof(out->id), (const char *)sqlite3_column_text(statement, 0)) ||
        !mg_copy_string(out->kind, sizeof(out->kind), (const char *)sqlite3_column_text(statement, 1))) {
        sqlite3_finalize(statement);
        return database_error(store->database, error, "read outbox item");
    }
    out->payload = strdup((const char *)sqlite3_column_text(statement, 2));
    out->attempts = (unsigned)sqlite3_column_int(statement, 3);
    sqlite3_finalize(statement);
    return out->payload ? MAELYS_GIT_OK : MAELYS_GIT_ERR_IO;
}

void mg_outbox_item_clear(mg_outbox_item_t *item) {
    if (!item) return;
    free(item->payload);
    memset(item, 0, sizeof(*item));
}

static maelys_git_result_t outbox_update(maelys_git_agent_store_t *store,
                                         const char *sql,
                                         const char *id,
                                         unsigned attempts,
                                         int64_t timestamp,
                                         maelys_git_error_t *error) {
    sqlite3_stmt *statement = NULL;
    if (sqlite3_prepare_v2(store->database, sql, -1, &statement, NULL) != SQLITE_OK)
        return database_error(store->database, error, "prepare outbox update");
    sqlite3_bind_int64(statement, 1, timestamp);
    int index = 2;
    if (attempts != UINT_MAX) sqlite3_bind_int(statement, index++, (int)attempts);
    sqlite3_bind_text(statement, index, id, -1, SQLITE_TRANSIENT);
    int step = sqlite3_step(statement);
    sqlite3_finalize(statement);
    return step == SQLITE_DONE ? MAELYS_GIT_OK : database_error(store->database, error, "update outbox item");
}

maelys_git_result_t mg_store_ack_outbox(maelys_git_agent_store_t *store,
                                        const char *id,
                                        maelys_git_error_t *error) {
    if (!store || !id) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    return outbox_update(store, "UPDATE outbox SET acked_at_ms=? WHERE id=?", id,
                         UINT_MAX, mg_now_ms(), error);
}

maelys_git_result_t mg_store_retry_outbox(maelys_git_agent_store_t *store,
                                          const char *id,
                                          unsigned attempts,
                                          int64_t next_attempt_ms,
                                          maelys_git_error_t *error) {
    if (!store || !id) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    return outbox_update(store,
        "UPDATE outbox SET next_attempt_ms=?,attempts=? WHERE id=?", id,
        attempts, next_attempt_ms, error);
}

maelys_git_result_t mg_store_get_cursor(maelys_git_agent_store_t *store,
                                        char *out,
                                        size_t capacity,
                                        maelys_git_error_t *error) {
    if (!store || !out || capacity == 0u) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    out[0] = '\0';
    sqlite3_stmt *statement = NULL;
    if (sqlite3_prepare_v2(store->database, "SELECT value FROM metadata WHERE key='cursor'", -1,
                           &statement, NULL) != SQLITE_OK)
        return database_error(store->database, error, "prepare cursor lookup");
    int step = sqlite3_step(statement);
    int valid = step == SQLITE_DONE ||
                (step == SQLITE_ROW && mg_copy_string(out, capacity,
                    (const char *)sqlite3_column_text(statement, 0)));
    sqlite3_finalize(statement);
    if (!valid) return database_error(store->database, error, "read cursor");
    return MAELYS_GIT_OK;
}

maelys_git_result_t mg_store_set_cursor(maelys_git_agent_store_t *store,
                                        const char *cursor,
                                        maelys_git_error_t *error) {
    if (!store || !cursor) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    sqlite3_stmt *statement = NULL;
    const char *sql = "INSERT INTO metadata(key,value) VALUES('cursor',?) "
                      "ON CONFLICT(key) DO UPDATE SET value=excluded.value";
    if (sqlite3_prepare_v2(store->database, sql, -1, &statement, NULL) != SQLITE_OK)
        return database_error(store->database, error, "prepare cursor update");
    sqlite3_bind_text(statement, 1, cursor, -1, SQLITE_TRANSIENT);
    int step = sqlite3_step(statement);
    sqlite3_finalize(statement);
    return step == SQLITE_DONE ? MAELYS_GIT_OK : database_error(store->database, error, "update cursor");
}

maelys_git_result_t mg_store_audit(maelys_git_agent_store_t *store,
                                   const char *event_id,
                                   const char *kind,
                                   const char *payload,
                                   int64_t now_ms,
                                   maelys_git_error_t *error) {
    if (!store || !event_id || !kind || !payload) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    sqlite3_stmt *statement = NULL;
    const char *sql = "INSERT OR IGNORE INTO audit(event_id,kind,payload,created_at_ms) VALUES(?,?,?,?)";
    if (sqlite3_prepare_v2(store->database, sql, -1, &statement, NULL) != SQLITE_OK)
        return database_error(store->database, error, "prepare audit insert");
    sqlite3_bind_text(statement, 1, event_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, kind, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 3, payload, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 4, now_ms);
    int step = sqlite3_step(statement);
    sqlite3_finalize(statement);
    return step == SQLITE_DONE ? MAELYS_GIT_OK : database_error(store->database, error, "write audit event");
}
