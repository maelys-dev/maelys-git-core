/* The agent journal written by the build of 1016d1b (fixture
 * agent-store/v1.sqlite3: five commands, complete, failed, pending and
 * running, raw_json in deduplication form v1) opened by this build: the
 * opening converts it to the v2 form in one transaction, with the recovery
 * of running commands, and changes nothing when it fails. */
#include "agent/agent_internal.h"
#include "test_support.h"

#include <sqlite3.h>

#ifndef STORE_FIXTURE
#error "STORE_FIXTURE names the v1 journal"
#endif

static char g_root[256];

/* A fresh copy of the v1 journal, at NAME under the test root. */
static const char *copy_fixture(const char *name) {
    static char path[512];
    (void)snprintf(path, sizeof(path), "%s/%s", g_root, name);
    FILE *in = fopen(STORE_FIXTURE, "rb"), *out = fopen(path, "wb");
    int ok = in && out;
    char buffer[8192];
    size_t size;
    while (ok && (size = fread(buffer, 1u, sizeof(buffer), in)) > 0u)
        ok = fwrite(buffer, 1u, size, out) == size;
    if (in) (void)fclose(in);
    if (out && fclose(out) != 0) ok = 0;
    return ok ? path : NULL;
}

static int sql(const char *path, const char *statement) {
    sqlite3 *db = NULL;
    int ok = sqlite3_open(path, &db) == SQLITE_OK &&
             sqlite3_exec(db, statement, NULL, NULL, NULL) == SQLITE_OK;
    sqlite3_close(db);
    return ok;
}

/* Every command row and the deduplication marker, as one string. */
static char *snapshot(const char *path) {
    sqlite3 *db = NULL;
    sqlite3_stmt *rows = NULL;
    size_t capacity = 65536u, used = 0u;
    char *out = calloc(1u, capacity);
    if (!out || sqlite3_open(path, &db) != SQLITE_OK ||
        sqlite3_prepare_v2(db, "SELECT 'command',id,raw_json,state,coalesce(result_json,'-') FROM commands "
                               "UNION ALL SELECT 'metadata',key,value,'','' FROM metadata "
                               "ORDER BY 1,2", -1, &rows, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        free(out);
        return NULL;
    }
    while (sqlite3_step(rows) == SQLITE_ROW)
        for (int column = 0; column < 5; ++column)
            used += (size_t)snprintf(out + used, capacity - used, "%s%c",
                                     (const char *)sqlite3_column_text(rows, column), column == 4 ? '\n' : '|');
    sqlite3_finalize(rows);
    sqlite3_close(db);
    return out;
}

static char *column(const char *path, const char *query) {
    sqlite3 *db = NULL;
    sqlite3_stmt *statement = NULL;
    char *value = NULL;
    if (sqlite3_open(path, &db) == SQLITE_OK &&
        sqlite3_prepare_v2(db, query, -1, &statement, NULL) == SQLITE_OK &&
        sqlite3_step(statement) == SQLITE_ROW && sqlite3_column_text(statement, 0))
        value = strdup((const char *)sqlite3_column_text(statement, 0));
    sqlite3_finalize(statement);
    sqlite3_close(db);
    return value;
}

static const char *const k_ids[] = {"s-ascii", "s-complete", "s-failed", "s-pending", "s-running"};

/* Test 4: a real v1 journal migrates; every command is replayed. */
static int test_migration(void) {
    const char *path = copy_fixture("migrated.sqlite3");
    CHECK(path != NULL);
    /* The v1 rows, before: the expected v2 form of each is its rewrite. */
    char *before[5];
    for (size_t i = 0u; i < 5u; ++i) {
        char query[128];
        (void)snprintf(query, sizeof(query), "SELECT raw_json FROM commands WHERE id='%s'", k_ids[i]);
        before[i] = column(path, query);
        CHECK(before[i] != NULL);
    }
    CHECK(strstr(before[1], "\"\\uE000\":\"caf\\u00E9\",\"\\uD800\\uDC00\":2") != NULL);
    char *marker = column(path, "SELECT value FROM metadata WHERE key='dedup_form'");
    CHECK(marker == NULL);
    maelys_git_agent_store_t *store = NULL;
    maelys_git_error_t error = {0};
    CHECK(mg_store_open(path, &store, &error) == MAELYS_GIT_OK);
    mg_store_close(store);
    marker = column(path, "SELECT value FROM metadata WHERE key='dedup_form'");
    CHECK(marker && !strcmp(marker, "v2"));
    free(marker);
    char *migrated = column(path, "SELECT raw_json FROM commands WHERE id='s-complete'");
    CHECK(migrated && !strcmp(migrated,
        "{\"agent_id\":\"a\",\"command\":\"authorize\",\"expires_at_ms\":2,\"issued_at_ms\":1,"
        "\"message_id\":\"s-complete\",\"payload\":{\"\\ud800\\udc00\":2,\"\\ue000\":\"caf\\u00e9\"},"
        "\"principal\":\"alice\",\"protocol\":\"maelys-git-agent/1\",\"repository\":\"r.git\","
        "\"type\":\"command\"}"));
    free(migrated);
    char *running = column(path, "SELECT state FROM commands WHERE id='s-running'");
    CHECK(running && !strcmp(running, "pending"));
    free(running);

    /* Replay: each command comes back in the v2 form. */
    static const mg_store_command_state_t expected[] = {
        MG_STORE_COMMAND_COMPLETE, MG_STORE_COMMAND_COMPLETE, MG_STORE_COMMAND_FAILED,
        MG_STORE_COMMAND_PENDING, MG_STORE_COMMAND_PENDING};
    CHECK(mg_store_open(path, &store, &error) == MAELYS_GIT_OK);
    for (size_t i = 0u; i < 5u; ++i) {
        char *form = mg_protocol_deduplication_form(before[i], strlen(before[i]), &error);
        CHECK(form != NULL);
        mg_agent_message_t message;
        CHECK(mg_protocol_parse(form, strlen(form), &message, &error) == MAELYS_GIT_OK);
        mg_store_command_state_t state;
        char *result = NULL;
        CHECK(mg_store_record_command(store, &message, form, &state, &result, &error) == MAELYS_GIT_OK);
        CHECK(state == expected[i]);
        /* A command that ended keeps its result: it is answered, not run again. */
        CHECK((result != NULL) == (state == MG_STORE_COMMAND_COMPLETE || state == MG_STORE_COMMAND_FAILED));
        if (result) CHECK(strstr(result, k_ids[i]) != NULL);
        free(result);
        mg_protocol_message_clear(&message);
        free(form);
        free(before[i]);
    }
    /* The same message_id with other content is refused, as before. */
    char *changed = column(path, "SELECT replace(raw_json,'caf\\u00e9','cafe') FROM commands WHERE id='s-complete'");
    CHECK(changed != NULL);
    mg_agent_message_t message;
    CHECK(mg_protocol_parse(changed, strlen(changed), &message, &error) == MAELYS_GIT_OK);
    mg_store_command_state_t state;
    char *result = NULL;
    CHECK(mg_store_record_command(store, &message, changed, &state, &result, &error) == MAELYS_GIT_ERR_PROTOCOL);
    CHECK(strstr(error.message, "message_id was reused with different content") != NULL);
    mg_protocol_message_clear(&message);
    free(changed);
    mg_store_close(store);
    return 1;
}

/* Test 5: a row that does not convert, after valid rows and a running
 * command, refuses the opening and changes nothing. */
static int test_atomic_failure(void) {
    const char *path = copy_fixture("invalid.sqlite3");
    CHECK(path != NULL);
    CHECK(sql(path, "INSERT INTO commands(id,raw_json,command,state,created_at_ms,updated_at_ms) "
                    "VALUES('s-zzz-invalid','{not json','authorize','pending',1,1)"));
    char *before = snapshot(path);
    CHECK(before != NULL && strstr(before, "s-running|") && strstr(before, "|running|"));
    maelys_git_agent_store_t *store = NULL;
    maelys_git_error_t error = {0};
    CHECK(mg_store_open(path, &store, &error) == MAELYS_GIT_ERR_PROTOCOL && store == NULL);
    CHECK(strstr(error.message, "s-zzz-invalid") != NULL);
    char *after = snapshot(path);
    CHECK(after != NULL && !strcmp(before, after));
    CHECK(strstr(after, "dedup_form") == NULL);
    free(before);
    free(after);
    return 1;
}

/* Test 6: an unknown deduplication form refuses the opening, unchanged. */
static int test_unknown_form(void) {
    const char *path = copy_fixture("unknown.sqlite3");
    CHECK(path != NULL);
    CHECK(sql(path, "INSERT INTO metadata(key,value) VALUES('dedup_form','v3')"));
    char *before = snapshot(path);
    CHECK(before != NULL);
    maelys_git_agent_store_t *store = NULL;
    maelys_git_error_t error = {0};
    CHECK(mg_store_open(path, &store, &error) == MAELYS_GIT_ERR_PROTOCOL && store == NULL);
    CHECK(strstr(error.message, "unknown deduplication form: v3") != NULL);
    char *after = snapshot(path);
    CHECK(after != NULL && !strcmp(before, after));
    free(before);
    free(after);
    return 1;
}

/* Test 7: a v2 journal reopens without any conversion; running commands are
 * still recovered. */
static int test_reopen(void) {
    const char *path = copy_fixture("reopened.sqlite3");
    CHECK(path != NULL);
    maelys_git_agent_store_t *store = NULL;
    maelys_git_error_t error = {0};
    CHECK(mg_store_open(path, &store, &error) == MAELYS_GIT_OK);
    mg_store_close(store);
    CHECK(sql(path, "UPDATE commands SET state='running' WHERE id='s-pending'"));
    char *raw_before = column(path, "SELECT group_concat(raw_json,'\n') FROM commands ORDER BY id");
    CHECK(mg_store_open(path, &store, &error) == MAELYS_GIT_OK);
    mg_store_close(store);
    char *raw_after = column(path, "SELECT group_concat(raw_json,'\n') FROM commands ORDER BY id");
    CHECK(raw_before && raw_after && !strcmp(raw_before, raw_after));
    char *state = column(path, "SELECT state FROM commands WHERE id='s-pending'");
    CHECK(state && !strcmp(state, "pending"));
    free(raw_before);
    free(raw_after);
    free(state);
    return 1;
}

/* Test 8: a new journal is born in the v2 form. */
static int test_new_journal(void) {
    char path[512];
    (void)snprintf(path, sizeof(path), "%s/new.sqlite3", g_root);
    maelys_git_agent_store_t *store = NULL;
    maelys_git_error_t error = {0};
    CHECK(mg_store_open(path, &store, &error) == MAELYS_GIT_OK);
    mg_store_close(store);
    char *marker = column(path, "SELECT value FROM metadata WHERE key='dedup_form'");
    CHECK(marker && !strcmp(marker, "v2"));
    free(marker);
    return 1;
}

int main(void) {
    char template[] = "/tmp/maelys_git_store_migration_XXXXXX";
    char *root = mkdtemp(template);
    if (!root) return 1;
    (void)snprintf(g_root, sizeof(g_root), "%s", root);
    int ok = test_migration() && test_atomic_failure() && test_unknown_form() &&
             test_reopen() && test_new_journal();
    if (!test_remove_tree(g_root)) ok = 0;
    if (ok) puts("agent journal: v1 to v2 in one transaction, atomic refusal, replay: ok");
    return ok ? 0 : 1;
}
