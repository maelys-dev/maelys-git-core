#include "agent/agent_internal.h"
#include "maelys_git_receipt.h"
#include "test_json.h"
#include "test_support.h"

#include <maelys/cli/digest.h>
#include <sqlite3.h>

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* A command of agent-1, issued now, with `payload` (JSON text); `principal`
 * and `repository` are left out when NULL. The caller frees the result. */
static char *command_text(const char *id, const char *command, const char *principal,
                          const char *repository, const char *payload) {
    maelys_json_document_t *document = tj_parse(payload);
    mg_json_t json;
    mg_json_begin(&json, MG_JSON_DATA);
    mg_json_object(&json, NULL);
    mg_json_string(&json, "protocol", MAELYS_GIT_AGENT_PROTOCOL);
    mg_json_string(&json, "message_id", id);
    mg_json_string(&json, "agent_id", "agent-1");
    mg_json_string(&json, "type", "command");
    mg_json_string(&json, "command", command);
    if (principal) mg_json_string(&json, "principal", principal);
    if (repository) mg_json_string(&json, "repository", repository);
    mg_json_i64(&json, "issued_at_ms", (int64_t)mg_now_ms());
    mg_json_i64(&json, "expires_at_ms", (int64_t)(mg_now_ms() + 60000));
    if (document) mg_json_copy(&json, "payload", document, maelys_json_document_root(document));
    else mg_json_string(&json, "payload", NULL);
    mg_json_end_object(&json);
    char *encoded = NULL;
    (void)mg_json_finish(&json, &encoded, NULL);
    tj_release(document);
    return encoded;
}

static char *valid_command(const char *id) {
    return command_text(id, "health", NULL, NULL, "{}");
}

/* An authorize command of `principal` on r.git with the given payload. */
static char *authorize_command(const char *id, const char *principal, const char *payload) {
    return command_text(id, "authorize", principal, "r.git", payload);
}

/* Runs one command and returns its result, after checking that it is a
 * valid failed protocol result for that command, with `status`. */
static maelys_json_document_t *execute(maelys_git_policy_t *policy, const char *raw, const char *status,
                                       maelys_git_error_t *error) {
    mg_agent_message_t message;
    if (!raw || mg_protocol_parse(raw, strlen(raw), &message, error) != MAELYS_GIT_OK) return NULL;
    char *encoded = NULL;
    maelys_json_document_t *result = NULL;
    int succeeded = 1;
    if (mg_executor_execute(policy, "/usr/bin/git", "/tmp", &message, MAELYS_GIT_EXPLAIN_ON_DENIAL,
                            &encoded, error) == MAELYS_GIT_OK &&
        mg_protocol_validate_result(encoded, strlen(encoded), &message, &succeeded, error) ==
            MAELYS_GIT_OK && !succeeded) {
        result = tj_parse(encoded);
        if (!tj_string_is(result, "status", status)) {
            tj_release(result);
            result = NULL;
        }
    }
    free(encoded);
    mg_protocol_message_clear(&message);
    return result;
}

/* A policy failure carries its detail in the failure payload, beside the code
 * and the message it always had; any other failure carries none, even on an
 * error that held a policy detail before. */
static int test_policy_failure_detail(void) {
    maelys_git_policy_t *policy = NULL;
    maelys_git_error_t error = {0};
    CHECK(maelys_git_policy_open(FIXTURE_DIR "/derived-overflow/manifest.json", &policy, &error) ==
          MAELYS_GIT_OK);
    char *raw = authorize_command("m-detail", "u0", "{\"operation\":\"read\"}");
    maelys_json_document_t *result = execute(policy, raw, "failed", &error);
    free(raw);
    CHECK(result != NULL);
    CHECK(tj_string_is(result, "payload.code", "policy_error"));
    CHECK(!strncmp(tj_string(result, "payload.message"), "policy solve failed: ", 21u));
    CHECK(tj_type(result, "payload.detail") == MAELYS_JSON_TYPE_OBJECT);
    CHECK(tj_string_is(result, "payload.detail.kind", "capacity"));
    CHECK(tj_string_is(result, "payload.detail.budget", "MAX_FACTS_PER_PRED"));
    CHECK(tj_string_is(result, "payload.detail.diagnostic", "solve_idb_overflow"));
    int64_t limit = tj_i64(result, "payload.detail.limit", 0);
    CHECK(limit > 0 && tj_i64(result, "payload.detail.requested", 0) == limit + 1);
    CHECK(!tj_has(result, "payload.detail.line"));
    tj_release(result);
    CHECK(error.detail.kind == MAELYS_GIT_FAILURE_CAPACITY);

    raw = authorize_command("m-protocol", "u0", "{\"operation\":\"read\",\"surprise\":true}");
    result = execute(policy, raw, "failed", &error);
    free(raw);
    CHECK(result != NULL);
    CHECK(tj_string_is(result, "payload.code", "protocol_error"));
    CHECK(!tj_has(result, "payload.detail"));
    tj_release(result);
    maelys_git_policy_close(policy);
    return 1;
}

/* A command on example.git for `principal`, with the given payload. */
static char *command_for(const char *id, const char *command, const char *principal, const char *payload) {
    return command_text(id, command, principal, "example.git", payload);
}

/* Executes a command and returns the result line, valid for that command. */
static char *result_of(maelys_git_policy_t *policy, const char *raw, maelys_git_explain_mode_t denial_mode,
                       mg_agent_message_t *out_message) {
    maelys_git_error_t error = {0};
    if (!raw || mg_protocol_parse(raw, strlen(raw), out_message, &error) != MAELYS_GIT_OK) return NULL;
    char *encoded = NULL;
    int succeeded = 0;
    char root[] = "/tmp/maelys_git_receipts_XXXXXX";
    if (!mkdtemp(root) ||
        mg_executor_execute(policy, "/usr/bin/git", root, out_message, denial_mode, &encoded, &error) !=
            MAELYS_GIT_OK ||
        mg_protocol_validate_result(encoded, strlen(encoded), out_message, &succeeded, &error) != MAELYS_GIT_OK) {
        free(encoded);
        encoded = NULL;
    }
    (void)test_remove_tree(root);
    return encoded;
}

/* Test 12: a decision result names the deciding policy and carries its
 * receipt; explain: true adds the text; explain must be a boolean. */
static int test_authorize_receipt(void) {
    maelys_git_policy_t *policy = NULL;
    maelys_git_error_t error = {0};
    CHECK(maelys_git_policy_open(TEST_MANIFEST_FILE, &policy, &error) == MAELYS_GIT_OK);
    mg_agent_message_t message;
    char *raw = command_for("a-1", "authorize", "mallory",
                            "{\"operation\":\"push\",\"ref\":\"refs/heads/main\"}");
    char *encoded = result_of(policy, raw, MAELYS_GIT_EXPLAIN_ON_DENIAL, &message);
    mg_protocol_message_clear(&message);
    free(raw);
    maelys_json_document_t *result = tj_parse(encoded);
    free(encoded);
    CHECK(tj_has(result, "payload"));
    CHECK(tj_i64(result, "payload.matched_policy", -1) == 0);
    CHECK(tj_type(result, "payload.receipt") == MAELYS_JSON_TYPE_OBJECT);
    CHECK(tj_string(result, "payload.receipt_sha256") && strlen(tj_string(result, "payload.receipt_sha256")) == 64u);
    CHECK(!tj_has(result, "payload.explanation_text"));
    tj_release(result);

    raw = command_for("a-2", "authorize", "mallory",
                      "{\"operation\":\"push\",\"ref\":\"refs/heads/main\",\"explain\":true}");
    encoded = result_of(policy, raw, MAELYS_GIT_EXPLAIN_NEVER, &message);
    mg_protocol_message_clear(&message);
    free(raw);
    result = tj_parse(encoded);
    free(encoded);
    const char *text = tj_string(result, "payload.explanation_text");
    CHECK(text && !strncmp(text, "MAELYS-DATALOG-v2\n", 18u));
    tj_release(result);

    raw = command_for("a-3", "authorize", "mallory", "{\"operation\":\"push\",\"explain\":\"yes\"}");
    encoded = result_of(policy, raw, MAELYS_GIT_EXPLAIN_NEVER, &message);
    mg_protocol_message_clear(&message);
    free(raw);
    result = tj_parse(encoded);
    free(encoded);
    CHECK(tj_string_is(result, "payload.code", "protocol_error"));
    tj_release(result);
    maelys_git_policy_close(policy);
    return 1;
}

static int audit_count(const char *database, const char *event_id) {
    sqlite3 *db = NULL;
    sqlite3_stmt *statement = NULL;
    int count = -1;
    if (sqlite3_open(database, &db) == SQLITE_OK &&
        sqlite3_prepare_v2(db, "SELECT count(*) FROM audit WHERE event_id=?", -1, &statement, NULL) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, event_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(statement) == SQLITE_ROW) count = sqlite3_column_int(statement, 0);
    }
    sqlite3_finalize(statement);
    sqlite3_close(db);
    return count;
}

static char *audit_payload(const char *database, const char *event_id) {
    sqlite3 *db = NULL;
    sqlite3_stmt *statement = NULL;
    char *payload = NULL;
    if (sqlite3_open(database, &db) == SQLITE_OK &&
        sqlite3_prepare_v2(db, "SELECT payload FROM audit WHERE event_id=?", -1, &statement, NULL) == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, event_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(statement) == SQLITE_ROW)
            payload = strdup((const char *)sqlite3_column_text(statement, 0));
    }
    sqlite3_finalize(statement);
    sqlite3_close(db);
    return payload;
}

/* `text` with its first `from` replaced by `to`. */
static char *replaced(const char *text, const char *from, const char *to) {
    const char *at = strstr(text, from);
    if (!at) return NULL;
    size_t size = strlen(text) - strlen(from) + strlen(to) + 1u;
    char *out = malloc(size);
    if (out) (void)snprintf(out, size, "%.*s%s%s", (int)(at - text), text, to, at + strlen(from));
    return out;
}

static int refused_result(const mg_agent_message_t *command, const char *result, const char *reason) {
    mg_receipt_events_t events;
    maelys_git_error_t error = {0};
    int ok = result && mg_receipt_events_prepare(command, result, &events, &error) == MAELYS_GIT_ERR_PROTOCOL &&
             strstr(error.message, reason) != NULL;
    if (!ok) (void)fprintf(stderr, "not refused for %s: %s\n", reason, error.message);
    return ok;
}

/* Tests 13 and 14: a denied repository change carries its receipt and text;
 * the agent audits both, publishes the result without the text, refuses a
 * tampered receipt or text, and a replay adds no event. */
static int test_denial_audit(void) {
    maelys_git_policy_t *policy = NULL;
    maelys_git_error_t error = {0};
    CHECK(maelys_git_policy_open(TEST_MANIFEST_FILE, &policy, &error) == MAELYS_GIT_OK);
    mg_agent_message_t message;
    char *raw = command_for("deny-1", "create_repository", "nobody", "{}");
    char *encoded = result_of(policy, raw, MAELYS_GIT_EXPLAIN_ON_DENIAL, &message);
    CHECK(encoded != NULL);
    maelys_json_document_t *executor = tj_parse(encoded);
    CHECK(tj_string_is(executor, "status", "denied"));
    const char *text = tj_string(executor, "payload.explanation_text");
    CHECK(text && !strncmp(text, "MAELYS-DATALOG-v2\n", 18u));

    mg_receipt_events_t events;
    CHECK(mg_receipt_events_prepare(&message, encoded, &events, &error) == MAELYS_GIT_OK);
    CHECK(events.receipt && events.text && events.published && !strcmp(events.text, text));
    char receipt_sha256[65];
    CHECK(maelys_git_receipt_verify(events.receipt, strlen(events.receipt), receipt_sha256, &error) == MAELYS_GIT_OK);
    CHECK(tj_string_is(executor, "payload.receipt_sha256", receipt_sha256));
    /* What the agent publishes is the executor's value without the text. */
    char *payload = tj_extract(encoded, "payload");
    char *without_text = tj_with(payload, "explanation_text", NULL);
    char *expected = tj_with(encoded, "payload", without_text);
    CHECK(expected && tj_text_equal(events.published, expected));
    free(payload); free(without_text); free(expected);
    int succeeded = 1;
    CHECK(mg_protocol_validate_result(events.published, strlen(events.published), &message, &succeeded,
                                      &error) == MAELYS_GIT_OK && !succeeded);

    char directory[] = "/tmp/maelys_git_audit_XXXXXX";
    CHECK(mkdtemp(directory) != NULL);
    char database[4096];
    (void)snprintf(database, sizeof(database), "%s/agent.sqlite3", directory);
    maelys_git_agent_store_t *store = NULL;
    CHECK(mg_store_open(database, &store, &error) == MAELYS_GIT_OK);
    mg_store_command_state_t state;
    char *stored = NULL;
    CHECK(mg_store_record_command(store, &message, raw, &state, &stored, &error) == MAELYS_GIT_OK);
    CHECK(mg_store_mark_running(store, message.message_id, &error) == MAELYS_GIT_OK);
    CHECK(mg_store_complete_command(store, message.message_id, 0, events.published, &events, mg_now_ms(),
                                    &error) == MAELYS_GIT_OK);
    CHECK(audit_count(database, "receipt:deny-1") == 1 && audit_count(database, "explanation:deny-1") == 1);
    char *audited = audit_payload(database, "receipt:deny-1");
    char digest[MAELYS_CLI_SHA256_HEX_SIZE];
    CHECK(audited && maelys_git_receipt_verify(audited, strlen(audited), digest, &error) == MAELYS_GIT_OK);
    CHECK(!strcmp(digest, receipt_sha256));
    free(audited);
    char *explained = audit_payload(database, "explanation:deny-1");
    maelys_cli_sha256_hex(explained, strlen(explained), digest);
    CHECK(strstr(events.receipt, digest) != NULL);
    free(explained);
    /* A replay is answered from the stored result: no second event. */
    CHECK(mg_store_record_command(store, &message, raw, &state, &stored, &error) == MAELYS_GIT_OK);
    CHECK(state == MG_STORE_COMMAND_FAILED && stored && !strcmp(stored, events.published));
    free(stored);
    CHECK(audit_count(database, "receipt:deny-1") == 1);
    mg_store_close(store);
    CHECK(test_remove_tree(directory));
    mg_receipt_events_clear(&events);

    /* A receipt or a text that is not the executor's own is refused. */
    char *tampered = replaced(encoded, "\"evaluatedPolicies\":1", "\"evaluatedPolicies\":2");
    CHECK(refused_result(&message, tampered, "digest"));
    free(tampered);
    tampered = replaced(encoded, "MAELYS-DATALOG-v2\\n", "MAELYS-DATALOG-v3\\n");
    CHECK(refused_result(&message, tampered, "explanation text"));
    free(tampered);
    /* version 1.0 with the digest of what a rewrite yields: refused by the
     * verification of the rewritten bytes, not by the digest comparison. */
    char *fraction = replaced(encoded, "\"version\":1}", "\"version\":1.0}");
    CHECK(fraction != NULL);
    /* The writer copies the lexeme 1.0 as it was read. */
    char *receipt_bytes = tj_extract(fraction, "payload.receipt");
    CHECK(receipt_bytes && strstr(receipt_bytes, "\"version\":1.0}") != NULL);
    maelys_cli_sha256_hex(receipt_bytes, strlen(receipt_bytes), digest);
    char *quoted = tj_quote(digest);
    char *forged_payload = tj_extract(fraction, "payload");
    char *resigned = tj_with(forged_payload, "receipt_sha256", quoted);
    char *forged_line = tj_with(fraction, "payload", resigned);
    CHECK(refused_result(&message, forged_line, "canonical"));
    free(forged_line); free(resigned); free(forged_payload); free(quoted); free(receipt_bytes); free(fraction);
    tj_release(executor);
    free(encoded);
    free(raw);
    mg_protocol_message_clear(&message);

    /* authorize with explain keeps its text in the published result. */
    raw = command_for("keep-1", "authorize", "mallory",
                      "{\"operation\":\"push\",\"ref\":\"refs/heads/main\",\"explain\":true}");
    encoded = result_of(policy, raw, MAELYS_GIT_EXPLAIN_ON_DENIAL, &message);
    CHECK(mg_receipt_events_prepare(&message, encoded, &events, &error) == MAELYS_GIT_OK);
    CHECK(events.receipt && events.text && events.published == NULL);
    mg_receipt_events_clear(&events);
    mg_protocol_message_clear(&message);
    free(encoded);
    free(raw);
    maelys_git_policy_close(policy);
    return 1;
}

/* The local front-end publishes what it executes and keeps no audit: the
 * denial of a repository change carries its receipt, without an explanation
 * and without its summary, exactly as the Cloud agent would publish it. */
static int test_stdio_denial(void) {
    maelys_git_policy_t *policy = NULL;
    maelys_git_error_t error = {0};
    CHECK(maelys_git_policy_open(TEST_MANIFEST_FILE, &policy, &error) == MAELYS_GIT_OK);
    char *raw = command_for("stdio-1", "create_repository", "nobody", "{}");
    CHECK(raw != NULL);
    size_t length = strlen(raw);
    char *line = malloc(length + 2u);
    CHECK(line != NULL);
    (void)snprintf(line, length + 2u, "%s\n", raw);
    free(raw);
    char root[] = "/tmp/maelys_git_stdio_XXXXXX";
    CHECK(mkdtemp(root) != NULL);
    FILE *input = fmemopen(line, length + 1u, "r");
    char *output_text = NULL;
    size_t output_size = 0u;
    FILE *output = open_memstream(&output_text, &output_size);
    CHECK(input && output);
    CHECK(maelys_git_agent_serve(policy, "/usr/bin/git", root, input, output, stderr, &error) == MAELYS_GIT_OK);
    (void)fclose(input);
    (void)fclose(output);
    free(line);
    /* One line: the result and its separator. */
    CHECK(output_text && output_size > 0u && output_text[output_size - 1u] == '\n' &&
          memchr(output_text, '\n', output_size) == output_text + output_size - 1u);
    maelys_json_document_t *result = tj_parse(output_text);
    free(output_text);
    CHECK(tj_string_is(result, "status", "denied"));
    CHECK(!tj_has(result, "payload.explanation_text"));
    CHECK(tj_string_is(result, "payload.receipt.explanation.kind", "none"));
    CHECK(tj_string_is(result, "payload.receipt.explanation.status", "not_requested"));
    tj_release(result);
    CHECK(test_remove_tree(root));
    maelys_git_policy_close(policy);
    return 1;
}

static int test_protocol_strictness(void) {
    char *raw = valid_command("m1");
    CHECK(raw != NULL);
    mg_agent_message_t message;
    maelys_git_error_t error = {0};
    CHECK(mg_protocol_parse(raw, strlen(raw), &message, &error) == MAELYS_GIT_OK);
    CHECK(!strcmp(message.command, "health"));
    mg_protocol_message_clear(&message);
    const char *duplicate = "{\"protocol\":\"maelys-git-agent/1\",\"protocol\":\"maelys-git-agent/1\"}";
    CHECK(mg_protocol_parse(duplicate, strlen(duplicate), &message, &error) == MAELYS_GIT_ERR_PROTOCOL);
    char *unknown = tj_with(raw, "surprise", "true");
    CHECK(unknown != NULL);
    CHECK(mg_protocol_parse(unknown, strlen(unknown), &message, &error) == MAELYS_GIT_ERR_PROTOCOL);
    free(unknown); free(raw);
    return 1;
}

static int test_retry_is_bounded(void) {
    uint64_t first = mg_retry_delay_ms("m1", 0u, 100u, 10000u);
    uint64_t later = mg_retry_delay_ms("m1", 20u, 100u, 10000u);
    CHECK(first >= 87u && first <= 112u);
    CHECK(later >= 8750u && later <= 10000u);
    CHECK(first == mg_retry_delay_ms("m1", 0u, 100u, 10000u));
    return 1;
}

static int test_durable_store(void) {
    char temporary[] = "/tmp/maelys_git_agent_test_XXXXXX";
    char *directory = mkdtemp(temporary);
    CHECK(directory != NULL);
    char database[4096];
    (void)snprintf(database, sizeof(database), "%s/agent.sqlite3", directory);
    maelys_git_error_t error = {0};
    maelys_git_agent_store_t *store = NULL;
    CHECK(mg_store_open(database, &store, &error) == MAELYS_GIT_OK);
    char *raw = valid_command("durable-1");
    CHECK(raw != NULL);
    mg_agent_message_t message;
    CHECK(mg_protocol_parse(raw, strlen(raw), &message, &error) == MAELYS_GIT_OK);
    mg_store_command_state_t state;
    char *stored = NULL;
    CHECK(mg_store_record_command(store, &message, raw, &state, &stored, &error) == MAELYS_GIT_OK);
    CHECK(state == MG_STORE_COMMAND_NEW && stored == NULL);
    CHECK(mg_store_mark_running(store, message.message_id, &error) == MAELYS_GIT_OK);
    const char *result = "{\"status\":\"ok\"}";
    CHECK(mg_store_complete_command(store, message.message_id, 1, result, NULL, mg_now_ms(), &error) == MAELYS_GIT_OK);
    mg_outbox_item_t item;
    CHECK(mg_store_next_outbox(store, mg_now_ms(), &item, &error) == MAELYS_GIT_OK);
    CHECK(!strcmp(item.id, "durable-1") && !strcmp(item.payload, result));
    mg_outbox_item_clear(&item);
    CHECK(mg_store_ack_outbox(store, "durable-1", &error) == MAELYS_GIT_OK);
    CHECK(mg_store_next_outbox(store, mg_now_ms(), &item, &error) == MAELYS_GIT_ERR_NOT_FOUND);
    CHECK(mg_store_enqueue(store, "durable-1", "command_result", result,
                           mg_now_ms(), &error) == MAELYS_GIT_OK);
    CHECK(mg_store_next_outbox(store, mg_now_ms(), &item, &error) == MAELYS_GIT_OK);
    mg_outbox_item_clear(&item);

    char *interrupted_raw = valid_command("interrupted-1");
    mg_agent_message_t interrupted;
    CHECK(interrupted_raw != NULL);
    CHECK(mg_protocol_parse(interrupted_raw, strlen(interrupted_raw),
                            &interrupted, &error) == MAELYS_GIT_OK);
    CHECK(mg_store_record_command(store, &interrupted, interrupted_raw,
                                  &state, &stored, &error) == MAELYS_GIT_OK);
    CHECK(mg_store_mark_running(store, interrupted.message_id, &error) == MAELYS_GIT_OK);
    mg_store_close(store);
    store = NULL;
    CHECK(mg_store_open(database, &store, &error) == MAELYS_GIT_OK);
    CHECK(mg_store_record_command(store, &interrupted, interrupted_raw,
                                  &state, &stored, &error) == MAELYS_GIT_OK);
    CHECK(state == MG_STORE_COMMAND_PENDING);
    CHECK(mg_store_record_command(store, &message, raw, &state, &stored, &error) == MAELYS_GIT_OK);
    CHECK(state == MG_STORE_COMMAND_COMPLETE && stored && !strcmp(stored, result));
    free(stored);
    char *different = valid_command("other");
    CHECK(different != NULL);
    char *renamed = tj_with(different, "message_id", "\"durable-1\"");
    char *reused = tj_with(renamed, "command", "\"health_variant\"");
    free(renamed);
    CHECK(reused != NULL);
    mg_agent_message_t reused_message;
    CHECK(mg_protocol_parse(reused, strlen(reused), &reused_message, &error) == MAELYS_GIT_OK);
    CHECK(mg_store_record_command(store, &reused_message, reused, &state, &stored, &error) == MAELYS_GIT_ERR_PROTOCOL);
    mg_protocol_message_clear(&reused_message);
    free(different); free(reused);
    mg_protocol_message_clear(&interrupted); free(interrupted_raw);
    mg_protocol_message_clear(&message); free(raw); mg_store_close(store);
    CHECK(test_remove_tree(directory));
    return 1;
}

static int write_file(const char *path, const char *contents, mode_t mode) {
    FILE *file = fopen(path, "w");
    if (!file) return 0;
    int ok = fputs(contents, file) >= 0 && fclose(file) == 0 && chmod(path, mode) == 0;
    return ok;
}

static int test_provision_and_token_security(void) {
    char temporary[] = "/tmp/maelys_git_config_test_XXXXXX";
    char *directory = mkdtemp(temporary);
    CHECK(directory != NULL);
    char token[4096], ca[4096], config[4096], database[4096];
    (void)snprintf(token, sizeof(token), "%s/token", directory);
    (void)snprintf(ca, sizeof(ca), "%s/ca.pem", directory);
    (void)snprintf(config, sizeof(config), "%s/agent.json", directory);
    (void)snprintf(database, sizeof(database), "%s/agent.sqlite3", directory);
    CHECK(write_file(token, "secret-token\n", 0600));
    CHECK(write_file(ca, "test-ca\n", 0644));
    maelys_git_error_t error = {0};
    CHECK(maelys_git_agent_provision(config, "agent-1", "forge.example.test",
        ca, token, database, TEST_MANIFEST_FILE, directory, "/usr/bin/true", &error) == MAELYS_GIT_OK);
    struct stat status;
    CHECK(stat(config, &status) == 0 && (status.st_mode & 0777u) == 0600u);
    maelys_git_agent_config_t *loaded = NULL;
    CHECK(mg_config_load(config, &loaded, &error) == MAELYS_GIT_OK);
    mg_config_free(loaded);
    char value[MG_TOKEN_MAX];
    CHECK(mg_token_load(token, value, sizeof(value), &error) == MAELYS_GIT_OK);
    CHECK(!strcmp(value, "secret-token"));
    CHECK(chmod(token, 0644) == 0);
    CHECK(mg_token_load(token, value, sizeof(value), &error) == MAELYS_GIT_ERR_DENIED);
    CHECK(test_remove_tree(directory));
    return 1;
}

int main(void) {
    int passed = 0;
    passed += test_protocol_strictness();
    passed += test_retry_is_bounded();
    passed += test_durable_store();
    passed += test_provision_and_token_security();
    passed += test_policy_failure_detail();
    passed += test_authorize_receipt();
    passed += test_denial_audit();
    passed += test_stdio_denial();
    if (passed != 8) return 1;
    (void)printf("ok: %d agent test groups passed\n", passed);
    return 0;
}
