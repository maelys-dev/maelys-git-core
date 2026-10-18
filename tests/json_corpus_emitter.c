/* Lines of JSON that no program prints on its own, for the JSON corpus:
 * the decision line of the public maelys_git_protocol_write_decision, and
 * the deduplication form the Cloud agent stores for each command of a poll.
 * `--names` prints the label of each line, in the same order.
 * `--store PATH` writes an agent journal as this build stores it: one
 * command in each state, the deduplication forms of a poll as raw_json. */
#include "agent/agent_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const k_names[] = {
    "decision/allowed", "decision/denied", "dedup/unicode", "dedup/ascii",
};

/* The deduplication form of command `index` of a parsed poll, as the agent
 * stores it in commands.raw_json. */
static char *deduplication_form(const mg_agent_poll_t *poll, size_t index) {
    return json_dumps(json_array_get(poll->deduplication_commands, index),
                      JSON_COMPACT | JSON_ENSURE_ASCII | JSON_SORT_KEYS);
}

/* Five commands, each with a payload whose keys or strings need escapes. */
static const char k_store_poll[] =
    "{\"cursor\":\"s1\",\"commands\":["
#define STORE_COMMAND(id, payload) \
    "{\"protocol\":\"maelys-git-agent/1\",\"message_id\":\"" id "\",\"agent_id\":\"a\"," \
    "\"type\":\"command\",\"command\":\"authorize\",\"repository\":\"r.git\"," \
    "\"principal\":\"alice\",\"issued_at_ms\":1,\"expires_at_ms\":2,\"payload\":" payload "}"
    STORE_COMMAND("s-complete", "{\"\\ue000\":\"caf\\u00e9\",\"\\ud800\\udc00\":2}") ","
    STORE_COMMAND("s-failed", "{\"ctl\":\"a\\u001fb\"}") ","
    STORE_COMMAND("s-pending", "{\"text\":\"caf\\u00e9\"}") ","
    STORE_COMMAND("s-running", "{\"\\u00e9\":1}") ","
    STORE_COMMAND("s-ascii", "{\"operation\":\"read\"}")
#undef STORE_COMMAND
    "]}";

static int write_store(const char *path) {
    maelys_git_error_t error = {0};
    mg_agent_poll_t poll;
    if (mg_protocol_poll_parse(k_store_poll, strlen(k_store_poll), &poll, &error) != MAELYS_GIT_OK) {
        (void)fprintf(stderr, "poll: %s\n", error.message);
        return 1;
    }
    maelys_git_agent_store_t *store = NULL;
    int ok = mg_store_open(path, &store, &error) == MAELYS_GIT_OK;
    for (size_t i = 0u; ok && i < poll.command_count; ++i) {
        char *raw = deduplication_form(&poll, i);
        mg_agent_message_t message;
        mg_store_command_state_t state;
        char *stored = NULL;
        ok = raw && mg_protocol_parse(raw, strlen(raw), &message, &error) == MAELYS_GIT_OK;
        if (ok) {
            ok = mg_store_record_command(store, &message, raw, &state, &stored, &error) == MAELYS_GIT_OK;
            const char *id = message.message_id;
            if (ok && strcmp(id, "s-pending") != 0)
                ok = mg_store_mark_running(store, id, &error) == MAELYS_GIT_OK;
            if (ok && (!strcmp(id, "s-complete") || !strcmp(id, "s-failed") || !strcmp(id, "s-ascii"))) {
                char result[256];
                (void)snprintf(result, sizeof(result),
                    "{\"agent_id\":\"a\",\"command\":\"authorize\",\"message_id\":\"%s\","
                    "\"payload\":{\"code\":\"denied\",\"message\":\"stored\"},"
                    "\"protocol\":\"maelys-git-agent/1\",\"status\":\"%s\",\"type\":\"result\"}",
                    id, strcmp(id, "s-failed") ? "denied" : "failed");
                ok = mg_store_complete_command(store, id, strcmp(id, "s-failed") != 0, result, NULL,
                                               1000, &error) == MAELYS_GIT_OK;
            }
            mg_protocol_message_clear(&message);
        }
        free(stored);
        free(raw);
    }
    if (!ok) (void)fprintf(stderr, "store: %s\n", error.message);
    mg_store_close(store);
    mg_protocol_poll_clear(&poll);
    return ok ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc > 2 && !strcmp(argv[1], "--store")) return write_store(argv[2]);
    if (argc > 1 && !strcmp(argv[1], "--names")) {
        for (size_t i = 0u; i < sizeof(k_names) / sizeof(k_names[0]); ++i) puts(k_names[i]);
        return 0;
    }
    maelys_git_policy_decision_t allowed = {.allowed = 1, .matched_policy = 0u};
    (void)snprintf(allowed.reason, sizeof(allowed.reason), "allowed by policy corpus");
    maelys_git_policy_decision_t denied = {.explicit_deny = 1, .matched_policy = 0u};
    (void)snprintf(denied.reason, sizeof(denied.reason), "caf\xc3\xa9 \x01 denied");
    maelys_git_error_t error = {0};
    if (maelys_git_protocol_write_decision(stdout, "corpus-1", &allowed, &error) != MAELYS_GIT_OK ||
        maelys_git_protocol_write_decision(stdout, "corpus-2", &denied, &error) != MAELYS_GIT_OK)
        return 1;
    /* Keys U+E000 and U+10000 order differently in UTF-8 and UTF-16. */
    static const char poll_body[] =
        "{\"cursor\":\"c1\",\"commands\":["
        "{\"protocol\":\"maelys-git-agent/1\",\"message_id\":\"u-1\",\"agent_id\":\"a\","
        "\"type\":\"command\",\"command\":\"authorize\",\"repository\":\"r.git\","
        "\"principal\":\"alice\",\"issued_at_ms\":1,\"expires_at_ms\":2,"
        "\"payload\":{\"\\ue000\":\"caf\\u00e9\",\"\\ud800\\udc00\":2,\"ctl\":\"a\\u001fb\"}},"
        "{\"protocol\":\"maelys-git-agent/1\",\"message_id\":\"a-1\",\"agent_id\":\"a\","
        "\"type\":\"command\",\"command\":\"health\",\"issued_at_ms\":1,\"expires_at_ms\":2,"
        "\"payload\":{}}]}";
    mg_agent_poll_t poll;
    if (mg_protocol_poll_parse(poll_body, strlen(poll_body), &poll, &error) != MAELYS_GIT_OK) {
        (void)fprintf(stderr, "poll: %s\n", error.message);
        return 1;
    }
    for (size_t i = 0u; i < poll.command_count; ++i) {
        char *form = deduplication_form(&poll, i);
        if (!form) return 1;
        (void)puts(form);
        free(form);
    }
    mg_protocol_poll_clear(&poll);
    return 0;
}
