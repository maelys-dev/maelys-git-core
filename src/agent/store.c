#include "agent_internal.h"
#include "receipt/receipt_internal.h"

#include <maelys/cli/digest.h>

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

/* The form of commands.raw_json this build compares, recorded in metadata. */
#define DEDUPLICATION_FORM "v2"

/* Rewrites every raw_json of a v1 journal in the v2 form. A row that does not
 * convert stops the conversion and is named; the caller rolls back. */
static maelys_git_result_t convert_journal(sqlite3 *db, maelys_git_error_t *error) {
    sqlite3_stmt *rows = NULL, *update = NULL;
    if (sqlite3_prepare_v2(db, "SELECT id,raw_json FROM commands ORDER BY id", -1, &rows, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db, "UPDATE commands SET raw_json=? WHERE id=?", -1, &update, NULL) != SQLITE_OK) {
        sqlite3_finalize(rows);
        return database_error(db, error, "prepare journal conversion");
    }
    maelys_git_result_t result = MAELYS_GIT_OK;
    int step;
    while (result == MAELYS_GIT_OK && (step = sqlite3_step(rows)) == SQLITE_ROW) {
        const char *id = (const char *)sqlite3_column_text(rows, 0);
        const char *raw = (const char *)sqlite3_column_text(rows, 1);
        int size = sqlite3_column_bytes(rows, 1);
        maelys_git_error_t conversion = {0};
        char *form = raw ? mg_protocol_deduplication_form(raw, (size_t)size, &conversion) : NULL;
        if (!form) {
            mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0,
                         "journal command %.256s cannot take the deduplication form " DEDUPLICATION_FORM
                         ": %.512s", id ? id : "(null)", conversion.message);
            result = MAELYS_GIT_ERR_PROTOCOL;
            break;
        }
        sqlite3_bind_text(update, 1, form, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(update, 2, id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(update) != SQLITE_DONE) result = database_error(db, error, "convert journal command");
        sqlite3_reset(update);
        free(form);
    }
    if (result == MAELYS_GIT_OK && step != SQLITE_DONE) result = database_error(db, error, "read journal commands");
    sqlite3_finalize(rows);
    sqlite3_finalize(update);
    return result;
}

/* The logical opening of a journal, in one transaction: refuse a form this
 * build does not know, convert a v1 journal to the v2 form and record it,
 * then put back to pending the commands a stopped agent left running. A
 * failure changes nothing. A journal without the marker is v1 when it has
 * commands; an empty one is born v2. */
static maelys_git_result_t open_journal(sqlite3 *db, maelys_git_error_t *error) {
    if (!execute(db, "BEGIN IMMEDIATE")) return database_error(db, error, "begin journal opening");
    maelys_git_result_t result = MAELYS_GIT_OK;
    sqlite3_stmt *statement = NULL;
    char form[32] = "";
    int commands = 0;
    if (sqlite3_prepare_v2(db, "SELECT value FROM metadata WHERE key='dedup_form'", -1, &statement, NULL) != SQLITE_OK) {
        result = database_error(db, error, "read deduplication form");
    } else {
        if (sqlite3_step(statement) == SQLITE_ROW) {
            const unsigned char *value = sqlite3_column_text(statement, 0);
            (void)snprintf(form, sizeof(form), "%s", value ? (const char *)value : "?");
        }
        sqlite3_finalize(statement);
    }
    if (result == MAELYS_GIT_OK && form[0] && strcmp(form, DEDUPLICATION_FORM) != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0,
                     "agent journal has an unknown deduplication form: %s", form);
        result = MAELYS_GIT_ERR_PROTOCOL;
    }
    if (result == MAELYS_GIT_OK && !form[0]) {
        if (sqlite3_prepare_v2(db, "SELECT count(*) FROM commands", -1, &statement, NULL) != SQLITE_OK ||
            sqlite3_step(statement) != SQLITE_ROW)
            result = database_error(db, error, "count journal commands");
        else
            commands = sqlite3_column_int(statement, 0);
        sqlite3_finalize(statement);
        if (result == MAELYS_GIT_OK && commands > 0) result = convert_journal(db, error);
        if (result == MAELYS_GIT_OK &&
            !execute(db, "INSERT INTO metadata(key,value) VALUES('dedup_form','" DEDUPLICATION_FORM "')"))
            result = database_error(db, error, "record deduplication form");
    }
    if (result == MAELYS_GIT_OK &&
        !execute(db, "UPDATE commands SET state='pending' WHERE state='running'"))
        result = database_error(db, error, "recover running commands");
    if (result == MAELYS_GIT_OK && !execute(db, "COMMIT")) result = database_error(db, error, "commit journal opening");
    if (result != MAELYS_GIT_OK) (void)execute(db, "ROLLBACK");
    return result;
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
        " kind TEXT NOT NULL, payload TEXT NOT NULL, created_at_ms INTEGER NOT NULL);";
    if (!execute(store->database, schema)) {
        database_error(store->database, error, "cannot initialize agent database");
        mg_store_close(store);
        return MAELYS_GIT_ERR_IO;
    }
    maelys_git_result_t opened = open_journal(store->database, error);
    if (opened != MAELYS_GIT_OK) {
        mg_store_close(store);
        return opened;
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
                                              const mg_receipt_events_t *events,
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
    if (ok && events && events->receipt) {
        char event_id[MG_MESSAGE_ID_MAX + 16u];
        (void)snprintf(event_id, sizeof(event_id), "receipt:%s", command_id);
        ok = mg_store_audit(store, event_id, "authorization_receipt", events->receipt,
                            now_ms, error) == MAELYS_GIT_OK;
    }
    if (ok && events && events->text) {
        char event_id[MG_MESSAGE_ID_MAX + 16u];
        (void)snprintf(event_id, sizeof(event_id), "explanation:%s", command_id);
        ok = mg_store_audit(store, event_id, "authorization_explanation", events->text,
                            now_ms, error) == MAELYS_GIT_OK;
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

/* ---- receipts of executor results ------------------------------------------- */

void mg_receipt_events_clear(mg_receipt_events_t *events) {
    if (!events) return;
    free(events->receipt);
    free(events->text);
    free(events->published);
    memset(events, 0, sizeof(*events));
}

static maelys_git_result_t receipt_refused(const char *reason, maelys_git_error_t *error) {
    mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "executor result: %s", reason);
    return MAELYS_GIT_ERR_PROTOCOL;
}

/* The command asked for the explanation text: an authorize with explain. */
static int text_requested(const mg_agent_message_t *command) {
    int explain = 0;
    return strcmp(command->command, "authorize") == 0 &&
           maelys_json_object_get_boolean(command->document, command->payload, "explain",
                                          &explain) == MAELYS_JSON_OK && explain;
}

/* The result rewritten without payload.explanation_text, in canonical form. */
static char *without_text(const maelys_json_document_t *document, maelys_json_value_t root,
                          maelys_json_value_t payload) {
    static const char *const payload_key[] = {"payload"};
    static const char *const text_key[] = {"explanation_text"};
    const maelys_json_limits_t limits = {
        .maximum_bytes = MAELYS_GIT_MAX_PROTOCOL_LINE,
        .maximum_depth = MG_PROTOCOL_MAX_DEPTH,
        .maximum_tokens = MG_PROTOCOL_MAX_TOKENS,
    };
    maelys_json_writer_t *writer = NULL;
    maelys_json_result_t status = maelys_json_writer_create(MAELYS_JSON_PROFILE_RFC8259, &limits, 0u, &writer);
    if (status == MAELYS_JSON_OK)
        status = maelys_json_writer_object_begin_except(writer, document, root, payload_key, 1u);
    if (status == MAELYS_JSON_OK) status = maelys_json_writer_key_cstr(writer, "payload");
    if (status == MAELYS_JSON_OK)
        status = maelys_json_writer_object_begin_except(writer, document, payload, text_key, 1u);
    if (status == MAELYS_JSON_OK) status = maelys_json_writer_object_end(writer);
    if (status == MAELYS_JSON_OK) status = maelys_json_writer_object_end(writer);
    char *bytes = NULL;
    size_t size = 0u;
    if (status == MAELYS_JSON_OK) status = maelys_json_writer_finish(writer, &bytes, &size);
    maelys_json_writer_release(writer);
    return status == MAELYS_JSON_OK ? bytes : NULL;
}

maelys_git_result_t mg_receipt_events_prepare(const mg_agent_message_t *command, const char *result_json,
                                              mg_receipt_events_t *out, maelys_git_error_t *error) {
    if (!command || !result_json || !out) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    const maelys_json_limits_t limits = {
        .maximum_bytes = MAELYS_GIT_MAX_PROTOCOL_LINE,
        .maximum_depth = MG_PROTOCOL_MAX_DEPTH,
        .maximum_tokens = MG_PROTOCOL_MAX_TOKENS,
    };
    maelys_json_document_t *document = NULL;
    if (maelys_json_document_parse(result_json, strlen(result_json), MAELYS_JSON_PROFILE_RFC8259, &limits,
                                   &document, NULL) != MAELYS_JSON_OK)
        return receipt_refused("not a JSON object", error);
    maelys_json_value_t root = maelys_json_document_root(document);
    maelys_json_value_t payload = 0, receipt = 0, text = 0;
    maelys_git_result_t result = MAELYS_GIT_OK;
    if (maelys_json_object_get(document, root, "payload", &payload) != MAELYS_JSON_OK) {
        result = receipt_refused("no payload", error);
    } else if (maelys_json_object_get(document, payload, "receipt", &receipt) != MAELYS_JSON_OK) {
        /* No decision, no receipt; a text without a receipt vouches for nothing. */
        if (maelys_json_object_get(document, payload, "explanation_text", &text) == MAELYS_JSON_OK)
            result = receipt_refused("explanation text without a receipt", error);
        maelys_json_document_release(document);
        return result;
    }
    size_t size = 0u;
    char sha256[65];
    mg_receipt_text_t vouched;
    if (result == MAELYS_GIT_OK)
        result = mg_receipt_rewrite(document, receipt, &out->receipt, &size, sha256, &vouched, error);
    maelys_json_view_t view;
    if (result == MAELYS_GIT_OK &&
        (maelys_json_object_get_string(document, payload, "receipt_sha256", &view) != MAELYS_JSON_OK ||
         view.size != 64u || memcmp(view.data, sha256, 64u) != 0))
        result = receipt_refused("the receipt is not the one its digest names", error);
    int has_text = result == MAELYS_GIT_OK &&
        maelys_json_object_get(document, payload, "explanation_text", &text) == MAELYS_JSON_OK;
    if (has_text) {
        char text_sha256[MAELYS_CLI_SHA256_HEX_SIZE];
        if (maelys_json_value_string(document, text, &view) != MAELYS_JSON_OK ||
            memchr(view.data, '\0', view.size) != NULL || !vouched.has_text ||
            view.size != vouched.text_bytes) {
            result = receipt_refused("the explanation text is not the one the receipt vouches for", error);
        } else {
            maelys_cli_sha256_hex(view.data, view.size, text_sha256);
            if (strcmp(text_sha256, vouched.text_sha256) != 0)
                result = receipt_refused("the explanation text is not the one the receipt vouches for", error);
        }
        if (result == MAELYS_GIT_OK && !(out->text = strndup(view.data, view.size))) result = MAELYS_GIT_ERR_IO;
        if (result == MAELYS_GIT_OK && !text_requested(command) &&
            !(out->published = without_text(document, root, payload))) {
            mg_error_set(error, MAELYS_GIT_ERR_IO, 0, "cannot rewrite the executor result without its text");
            result = MAELYS_GIT_ERR_IO;
        }
    }
    maelys_json_document_release(document);
    if (result != MAELYS_GIT_OK) mg_receipt_events_clear(out);
    return result;
}
