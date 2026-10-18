#include "agent/agent_internal.h"
#include "maelys_git_receipt.h"
#include "test_support.h"

#include <maelys/cli/digest.h>
#include <sqlite3.h>

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char *valid_command(const char *id) {
    json_t *payload = json_object();
    json_t *root = json_pack("{s:s,s:s,s:s,s:s,s:s,s:I,s:I,s:o}",
        "protocol", MAELYS_GIT_AGENT_PROTOCOL, "message_id", id,
        "agent_id", "agent-1", "type", "command", "command", "health",
        "issued_at_ms", (json_int_t)mg_now_ms(),
        "expires_at_ms", (json_int_t)(mg_now_ms() + 60000), "payload", payload);
    char *encoded = json_dumps(root, JSON_COMPACT | JSON_SORT_KEYS);
    json_decref(root);
    return encoded;
}

/* An authorize command of `principal` on r.git with the given payload. */
static char *authorize_command(const char *id, const char *principal, json_t *payload) {
    json_t *root = json_pack("{s:s,s:s,s:s,s:s,s:s,s:s,s:s,s:I,s:I,s:o}",
        "protocol", MAELYS_GIT_AGENT_PROTOCOL, "message_id", id,
        "agent_id", "agent-1", "type", "command", "command", "authorize",
        "principal", principal, "repository", "r.git",
        "issued_at_ms", (json_int_t)mg_now_ms(),
        "expires_at_ms", (json_int_t)(mg_now_ms() + 60000), "payload", payload);
    char *encoded = json_dumps(root, JSON_COMPACT | JSON_SORT_KEYS);
    json_decref(root);
    return encoded;
}

/* Runs one command and returns its result payload, after checking that the
 * result is a valid protocol result for that command. */
static json_t *execute(maelys_git_policy_t *policy, const char *raw, const char *status,
                       maelys_git_error_t *error) {
    mg_agent_message_t message;
    if (!raw || mg_protocol_parse(raw, strlen(raw), &message, error) != MAELYS_GIT_OK) return NULL;
    char *encoded = NULL;
    json_t *payload = NULL;
    int succeeded = 1;
    if (mg_executor_execute(policy, "/usr/bin/git", "/tmp", &message, MAELYS_GIT_EXPLAIN_ON_DENIAL,
                            &encoded, error) == MAELYS_GIT_OK &&
        mg_protocol_validate_result(encoded, strlen(encoded), &message, &succeeded, error) ==
            MAELYS_GIT_OK && !succeeded) {
        json_error_t json_error;
        json_t *root = json_loads(encoded, 0, &json_error);
        if (root && !strcmp(json_string_value(json_object_get(root, "status")), status))
            payload = json_incref(json_object_get(root, "payload"));
        json_decref(root);
    }
    free(encoded);
    mg_protocol_message_clear(&message);
    return payload;
}

/* A policy failure carries its detail in the failure payload, beside the code
 * and the message it always had; any other failure carries none, even on an
 * error that held a policy detail before. */
static int test_policy_failure_detail(void) {
    maelys_git_policy_t *policy = NULL;
    maelys_git_error_t error = {0};
    CHECK(maelys_git_policy_open(FIXTURE_DIR "/derived-overflow/manifest.json", &policy, &error) ==
          MAELYS_GIT_OK);
    char *raw = authorize_command("m-detail", "u0", json_pack("{s:s}", "operation", "read"));
    json_t *payload = execute(policy, raw, "failed", &error);
    free(raw);
    CHECK(payload != NULL);
    CHECK(!strcmp(json_string_value(json_object_get(payload, "code")), "policy_error"));
    CHECK(!strncmp(json_string_value(json_object_get(payload, "message")), "policy solve failed: ", 21u));
    json_t *detail = json_object_get(payload, "detail");
    CHECK(json_is_object(detail));
    CHECK(!strcmp(json_string_value(json_object_get(detail, "kind")), "capacity"));
    CHECK(!strcmp(json_string_value(json_object_get(detail, "budget")), "MAX_FACTS_PER_PRED"));
    CHECK(!strcmp(json_string_value(json_object_get(detail, "diagnostic")), "solve_idb_overflow"));
    json_int_t limit = json_integer_value(json_object_get(detail, "limit"));
    CHECK(limit > 0 && json_integer_value(json_object_get(detail, "requested")) == limit + 1);
    CHECK(json_object_get(detail, "line") == NULL);
    json_decref(payload);
    CHECK(error.detail.kind == MAELYS_GIT_FAILURE_CAPACITY);

    raw = authorize_command("m-protocol", "u0", json_pack("{s:s,s:b}", "operation", "read",
                                                        "surprise", 1));
    payload = execute(policy, raw, "failed", &error);
    free(raw);
    CHECK(payload != NULL);
    CHECK(!strcmp(json_string_value(json_object_get(payload, "code")), "protocol_error"));
    CHECK(json_object_get(payload, "detail") == NULL);
    json_decref(payload);
    maelys_git_policy_close(policy);
    return 1;
}

/* A command on example.git for `principal`, with the given payload. */
static char *command_for(const char *id, const char *command, const char *principal, json_t *payload) {
    json_t *root = json_pack("{s:s,s:s,s:s,s:s,s:s,s:s,s:s,s:I,s:I,s:o}",
        "protocol", MAELYS_GIT_AGENT_PROTOCOL, "message_id", id,
        "agent_id", "agent-1", "type", "command", "command", command,
        "principal", principal, "repository", "example.git",
        "issued_at_ms", (json_int_t)mg_now_ms(),
        "expires_at_ms", (json_int_t)(mg_now_ms() + 60000), "payload", payload);
    char *encoded = json_dumps(root, JSON_COMPACT | JSON_SORT_KEYS);
    json_decref(root);
    return encoded;
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

static json_t *payload_of(const char *encoded) {
    json_t *root = encoded ? json_loads(encoded, 0, NULL) : NULL;
    json_t *payload = json_incref(json_object_get(root, "payload"));
    json_decref(root);
    return payload;
}

/* Test 12: a decision result names the deciding policy and carries its
 * receipt; explain: true adds the text; explain must be a boolean. */
static int test_authorize_receipt(void) {
    maelys_git_policy_t *policy = NULL;
    maelys_git_error_t error = {0};
    CHECK(maelys_git_policy_open(TEST_MANIFEST_FILE, &policy, &error) == MAELYS_GIT_OK);
    mg_agent_message_t message;
    char *raw = command_for("a-1", "authorize", "mallory", json_pack("{s:s,s:s}", "operation", "push",
                                                                    "ref", "refs/heads/main"));
    char *encoded = result_of(policy, raw, MAELYS_GIT_EXPLAIN_ON_DENIAL, &message);
    mg_protocol_message_clear(&message);
    free(raw);
    json_t *payload = payload_of(encoded);
    free(encoded);
    CHECK(payload != NULL);
    CHECK(json_integer_value(json_object_get(payload, "matched_policy")) == 0);
    CHECK(json_is_object(json_object_get(payload, "receipt")));
    CHECK(strlen(json_string_value(json_object_get(payload, "receipt_sha256"))) == 64u);
    CHECK(json_object_get(payload, "explanation_text") == NULL);
    json_decref(payload);

    raw = command_for("a-2", "authorize", "mallory", json_pack("{s:s,s:s,s:b}", "operation", "push",
                                                              "ref", "refs/heads/main", "explain", 1));
    encoded = result_of(policy, raw, MAELYS_GIT_EXPLAIN_NEVER, &message);
    mg_protocol_message_clear(&message);
    free(raw);
    payload = payload_of(encoded);
    free(encoded);
    CHECK(payload && !strncmp(json_string_value(json_object_get(payload, "explanation_text")),
                              "MAELYS-DATALOG-v2\n", 18u));
    json_decref(payload);

    raw = command_for("a-3", "authorize", "mallory", json_pack("{s:s,s:s}", "operation", "push",
                                                              "explain", "yes"));
    encoded = result_of(policy, raw, MAELYS_GIT_EXPLAIN_NEVER, &message);
    mg_protocol_message_clear(&message);
    free(raw);
    payload = payload_of(encoded);
    free(encoded);
    CHECK(payload && !strcmp(json_string_value(json_object_get(payload, "code")), "protocol_error"));
    json_decref(payload);
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
    char *raw = command_for("deny-1", "create_repository", "nobody", json_object());
    char *encoded = result_of(policy, raw, MAELYS_GIT_EXPLAIN_ON_DENIAL, &message);
    CHECK(encoded != NULL);
    json_t *executor = json_loads(encoded, 0, NULL);
    json_t *payload = json_object_get(executor, "payload");
    CHECK(!strcmp(json_string_value(json_object_get(executor, "status")), "denied"));
    const char *text = json_string_value(json_object_get(payload, "explanation_text"));
    CHECK(text && !strncmp(text, "MAELYS-DATALOG-v2\n", 18u));

    mg_receipt_events_t events;
    CHECK(mg_receipt_events_prepare(&message, encoded, &events, &error) == MAELYS_GIT_OK);
    CHECK(events.receipt && events.text && events.published && !strcmp(events.text, text));
    char receipt_sha256[65];
    CHECK(maelys_git_receipt_verify(events.receipt, strlen(events.receipt), receipt_sha256, &error) == MAELYS_GIT_OK);
    CHECK(!strcmp(receipt_sha256, json_string_value(json_object_get(payload, "receipt_sha256"))));
    /* What the agent publishes is the executor's value without the text. */
    json_t *published = json_loads(events.published, 0, NULL);
    json_t *expected = json_deep_copy(executor);
    CHECK(json_object_del(json_object_get(expected, "payload"), "explanation_text") == 0);
    CHECK(published && json_equal(published, expected));
    int succeeded = 1;
    CHECK(mg_protocol_validate_result(events.published, strlen(events.published), &message, &succeeded,
                                      &error) == MAELYS_GIT_OK && !succeeded);
    json_decref(published);
    json_decref(expected);

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
    json_t *forged = json_loads(fraction, 0, NULL);
    json_t *forged_receipt = json_object_get(json_object_get(forged, "payload"), "receipt");
    json_t *one = json_real(1.0);
    CHECK(forged_receipt && json_object_set_new(forged_receipt, "version", one) == 0);
    char *receipt_bytes = json_dumps(forged_receipt, JSON_COMPACT | JSON_SORT_KEYS);
    char *lexeme = replaced(receipt_bytes, "\"version\":1.0", "\"version\":1.0");
    CHECK(lexeme != NULL);
    maelys_cli_sha256_hex(lexeme, strlen(lexeme), digest);
    CHECK(json_object_set_new(json_object_get(forged, "payload"), "receipt_sha256", json_string(digest)) == 0);
    char *forged_line = json_dumps(forged, JSON_COMPACT | JSON_SORT_KEYS);
    CHECK(refused_result(&message, forged_line, "canonical"));
    free(forged_line); free(lexeme); free(receipt_bytes); free(fraction);
    json_decref(forged);
    json_decref(executor);
    free(encoded);
    free(raw);
    mg_protocol_message_clear(&message);

    /* authorize with explain keeps its text in the published result. */
    raw = command_for("keep-1", "authorize", "mallory", json_pack("{s:s,s:s,s:b}", "operation", "push",
                                                                 "ref", "refs/heads/main", "explain", 1));
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
    char *raw = command_for("stdio-1", "create_repository", "nobody", json_object());
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
    json_t *result = json_loads(output_text, JSON_DISABLE_EOF_CHECK, NULL);
    free(output_text);
    json_t *payload = json_object_get(result, "payload");
    CHECK(!strcmp(json_string_value(json_object_get(result, "status")), "denied"));
    CHECK(json_object_get(payload, "explanation_text") == NULL);
    json_t *explanation = json_object_get(json_object_get(payload, "receipt"), "explanation");
    CHECK(!strcmp(json_string_value(json_object_get(explanation, "kind")), "none"));
    CHECK(!strcmp(json_string_value(json_object_get(explanation, "status")), "not_requested"));
    json_decref(result);
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
    json_error_t json_error;
    json_t *root = json_loads(raw, 0, &json_error);
    CHECK(root != NULL && json_object_set_new(root, "surprise", json_true()) == 0);
    char *unknown = json_dumps(root, JSON_COMPACT);
    CHECK(mg_protocol_parse(unknown, strlen(unknown), &message, &error) == MAELYS_GIT_ERR_PROTOCOL);
    free(unknown); json_decref(root); free(raw);
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
    json_error_t json_error;
    json_t *different_root = json_loads(different, 0, &json_error);
    CHECK(different_root != NULL);
    CHECK(json_object_set_new(different_root, "message_id", json_string("durable-1")) == 0);
    CHECK(json_object_set_new(different_root, "command", json_string("health_variant")) == 0);
    char *reused = json_dumps(different_root, JSON_COMPACT | JSON_SORT_KEYS);
    mg_agent_message_t reused_message;
    CHECK(mg_protocol_parse(reused, strlen(reused), &reused_message, &error) == MAELYS_GIT_OK);
    CHECK(mg_store_record_command(store, &reused_message, reused, &state, &stored, &error) == MAELYS_GIT_ERR_PROTOCOL);
    mg_protocol_message_clear(&reused_message);
    json_decref(different_root); free(different); free(reused);
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
