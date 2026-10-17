#include "agent/agent_internal.h"
#include "test_support.h"

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
    if (mg_executor_execute(policy, "/usr/bin/git", "/tmp", &message, &encoded, error) == MAELYS_GIT_OK &&
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
    CHECK(mg_store_complete_command(store, message.message_id, 1, result, mg_now_ms(), &error) == MAELYS_GIT_OK);
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
    if (passed != 5) return 1;
    (void)printf("ok: %d agent test groups passed\n", passed);
    return 0;
}
