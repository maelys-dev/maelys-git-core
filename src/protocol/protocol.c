#include "agent/agent_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

int mg_document_object_has_only(const maelys_json_document_t *document,
                                maelys_json_value_t object,
                                const char *const *allowed) {
    size_t size;
    if (maelys_json_object_size(document, object, &size) != MAELYS_JSON_OK) return 0;
    for (size_t member = 0u; member < size; ++member) {
        maelys_json_view_t key;
        maelys_json_value_t value;
        if (maelys_json_object_member_at(document, object, member, &key, &value) != MAELYS_JSON_OK)
            return 0;
        int found = 0;
        for (size_t i = 0u; allowed[i]; ++i) {
            if (strcmp(key.data, allowed[i]) == 0) { found = 1; break; }
        }
        if (!found) return 0;
    }
    return 1;
}

static int identifier_valid(const char *value) {
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
        unsigned char ch = *p;
        if (!((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
              (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' || ch == ':'))
            return 0;
    }
    return 1;
}

static int copy_text(const maelys_json_document_t *document,
                     maelys_json_value_t object,
                     const char *name, char *out, size_t capacity,
                     int optional, int identifier) {
    maelys_json_value_t member;
    maelys_json_result_t result = maelys_json_object_get(document, object, name, &member);
    if (result == MAELYS_JSON_ERR_NOT_FOUND && optional) { out[0] = '\0'; return 1; }
    maelys_json_view_t view;
    if (result != MAELYS_JSON_OK ||
        maelys_json_value_string(document, member, &view) != MAELYS_JSON_OK ||
        view.size == 0u || view.size >= capacity ||
        (identifier && !identifier_valid(view.data))) return 0;
    memcpy(out, view.data, view.size);
    out[view.size] = '\0';
    return 1;
}

/* All protocol JSON uses the byte-derived token budget, never library defaults. */
static maelys_git_result_t parse_document(const char *bytes, size_t length,
                                         size_t maximum_depth,
                                         maelys_json_document_t **out,
                                         maelys_git_error_t *error) {
    *out = NULL;
    if (length > MAELYS_GIT_MAX_PROTOCOL_LINE) {
        mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0, "JSON message exceeds 64 KiB");
        return MAELYS_GIT_ERR_LIMIT;
    }
    const maelys_json_limits_t limits = {
        .maximum_bytes = MAELYS_GIT_MAX_PROTOCOL_LINE,
        .maximum_depth = maximum_depth,
        .maximum_tokens = MG_PROTOCOL_MAX_TOKENS
    };
    maelys_json_error_t json_error;
    maelys_json_result_t parsed = maelys_json_document_parse(
        bytes, length, MAELYS_JSON_PROFILE_RFC8259, &limits, out, &json_error);
    if (parsed != MAELYS_JSON_OK) {
        char diagnostic[192];
        (void)maelys_json_error_format(&json_error, diagnostic, sizeof(diagnostic));
        maelys_git_result_t result = parsed == MAELYS_JSON_ERR_LIMIT ? MAELYS_GIT_ERR_LIMIT :
            parsed == MAELYS_JSON_ERR_MEMORY ? MAELYS_GIT_ERR_IO : MAELYS_GIT_ERR_PROTOCOL;
        mg_error_set(error, result, parsed == MAELYS_JSON_ERR_MEMORY ? ENOMEM : 0,
                     "invalid JSON: %s", diagnostic);
        return result;
    }
    return MAELYS_GIT_OK;
}

maelys_git_result_t mg_protocol_parse(const char *bytes,
                                      size_t length,
                                      mg_agent_message_t *out,
                                      maelys_git_error_t *error) {
    static const char *const allowed[] = {
        "protocol", "message_id", "agent_id", "type", "command",
        "repository", "principal", "issued_at_ms", "expires_at_ms", "payload", NULL
    };
    if (!out) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    out->payload = MAELYS_JSON_VALUE_NONE;
    if (!bytes) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    maelys_json_document_t *document = NULL;
    maelys_git_result_t parsed = parse_document(bytes, length, MG_PROTOCOL_MAX_DEPTH, &document, error);
    if (parsed != MAELYS_GIT_OK) return parsed;
    maelys_json_value_t root = maelys_json_document_root(document);
    maelys_json_value_t payload = MAELYS_JSON_VALUE_NONE;
    if (!mg_document_object_has_only(document, root, allowed)) {
        maelys_json_document_release(document);
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0,
                     "message must be an object with only documented fields");
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    int valid = copy_text(document, root, "protocol", out->protocol, sizeof(out->protocol), 0, 0) &&
        copy_text(document, root, "message_id", out->message_id, sizeof(out->message_id), 0, 1) &&
        copy_text(document, root, "agent_id", out->agent_id, sizeof(out->agent_id), 0, 1) &&
        copy_text(document, root, "type", out->type, sizeof(out->type), 0, 1) &&
        copy_text(document, root, "command", out->command, sizeof(out->command), 0, 1) &&
        copy_text(document, root, "repository", out->repository, sizeof(out->repository), 1, 0) &&
        copy_text(document, root, "principal", out->principal, sizeof(out->principal), 1, 0) &&
        maelys_json_object_get_i64(document, root, "issued_at_ms", &out->issued_at_ms) == MAELYS_JSON_OK &&
        maelys_json_object_get_i64(document, root, "expires_at_ms", &out->expires_at_ms) == MAELYS_JSON_OK &&
        maelys_json_object_get(document, root, "payload", &payload) == MAELYS_JSON_OK &&
        maelys_json_value_type(document, payload) == MAELYS_JSON_TYPE_OBJECT &&
        strcmp(out->protocol, MAELYS_GIT_AGENT_PROTOCOL) == 0 &&
        strcmp(out->type, "command") == 0 &&
        out->issued_at_ms > 0 && out->expires_at_ms >= out->issued_at_ms;
    if (!valid) {
        maelys_json_document_release(document);
        memset(out, 0, sizeof(*out));
        out->payload = MAELYS_JSON_VALUE_NONE;
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0,
                     "message does not match protocol %s", MAELYS_GIT_AGENT_PROTOCOL);
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    out->document = document;
    out->payload = payload;
    return MAELYS_GIT_OK;
}

void mg_protocol_message_clear(mg_agent_message_t *message) {
    if (!message) return;
    maelys_json_document_release(message->document);
    memset(message, 0, sizeof(*message));
    message->payload = MAELYS_JSON_VALUE_NONE;
}

/* Used only after bounded parsing, so recursion is capped at poll depth 34.
 * Jansson's compatibility tree must not round fractions or lose uint64 values. */
static int numbers_fit_jansson(const maelys_json_document_t *document,
                               maelys_json_value_t value) {
    maelys_json_type_t type = maelys_json_value_type(document, value);
    if (type == MAELYS_JSON_TYPE_NUMBER) {
        int64_t number;
        return maelys_json_value_i64(document, value, &number) == MAELYS_JSON_OK;
    }
    if (type != MAELYS_JSON_TYPE_OBJECT && type != MAELYS_JSON_TYPE_ARRAY) return 1;
    size_t count;
    maelys_json_result_t result = type == MAELYS_JSON_TYPE_OBJECT ?
        maelys_json_object_size(document, value, &count) :
        maelys_json_array_size(document, value, &count);
    if (result != MAELYS_JSON_OK) return 0;
    for (size_t i = 0u; i < count; ++i) {
        maelys_json_value_t child;
        maelys_json_view_t key;
        result = type == MAELYS_JSON_TYPE_OBJECT ?
            maelys_json_object_member_at(document, value, i, &key, &child) :
            maelys_json_array_get(document, value, i, &child);
        if (result != MAELYS_JSON_OK || !numbers_fit_jansson(document, child)) return 0;
    }
    return 1;
}

void mg_protocol_poll_clear(mg_agent_poll_t *poll) {
    if (!poll) return;
    json_decref(poll->deduplication_commands);
    maelys_json_document_release(poll->document);
    memset(poll, 0, sizeof(*poll));
}

maelys_git_result_t mg_protocol_poll_parse(const char *bytes, size_t length,
                                           mg_agent_poll_t *out,
                                           maelys_git_error_t *error) {
    if (!out) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    if (!bytes) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    maelys_git_result_t result = parse_document(bytes, length, MG_POLL_MAX_DEPTH, &out->document, error);
    if (result != MAELYS_GIT_OK) return result;
    static const char *const allowed[] = {"cursor", "commands", NULL};
    maelys_json_value_t root = maelys_json_document_root(out->document), commands;
    if (!mg_document_object_has_only(out->document, root, allowed) ||
        maelys_json_object_get_string(out->document, root, "cursor", &out->cursor) != MAELYS_JSON_OK ||
        out->cursor.size >= 1024u ||
        maelys_json_object_get(out->document, root, "commands", &commands) != MAELYS_JSON_OK ||
        maelys_json_array_size(out->document, commands, &out->command_count) != MAELYS_JSON_OK ||
        out->command_count > MG_POLL_MAX_COMMANDS || !numbers_fit_jansson(out->document, root)) {
        mg_protocol_poll_clear(out);
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0,
                     "invalid command poll response or non-int64 numeric lexeme");
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    /* Transitional double parse of exactly the same bytes after strict bounds,
     * poll schema and numeric-domain validation. This tree only supplies v1
     * deduplication bytes; command schemas and authorization remain mandatory. */
    json_error_t legacy_error;
    json_t *legacy = json_loadb(bytes, length, JSON_REJECT_DUPLICATES, &legacy_error);
    if (!legacy) {
        mg_protocol_poll_clear(out);
        result = json_error_code(&legacy_error) == json_error_out_of_memory ?
            MAELYS_GIT_ERR_IO : MAELYS_GIT_ERR_PROTOCOL;
        mg_error_set(error, result, 0, "could not create poll deduplication tree");
        return result;
    }
    out->deduplication_commands = json_incref(json_object_get(legacy, "commands"));
    json_decref(legacy);
    return MAELYS_GIT_OK;
}

static int text_equals(const maelys_json_document_t *document,
                        maelys_json_value_t object, const char *key, const char *expected) {
    maelys_json_view_t text;
    return maelys_json_object_get_string(document, object, key, &text) == MAELYS_JSON_OK &&
        strcmp(text.data, expected) == 0;
}

maelys_git_result_t mg_protocol_validate_result(const char *bytes, size_t length,
                                                const mg_agent_message_t *command,
                                                int *out_succeeded,
                                                maelys_git_error_t *error) {
    if (!out_succeeded) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    *out_succeeded = 0;
    if (!bytes || !command) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    maelys_json_document_t *document = NULL;
    maelys_git_result_t result = parse_document(bytes, length, MG_PROTOCOL_MAX_DEPTH, &document, error);
    if (result != MAELYS_GIT_OK) return result;
    static const char *const allowed[] = {
        "protocol", "message_id", "agent_id", "type", "command", "status", "payload", NULL};
    maelys_json_value_t root = maelys_json_document_root(document), payload;
    maelys_json_view_t status;
    int valid = mg_document_object_has_only(document, root, allowed) &&
        text_equals(document, root, "protocol", MAELYS_GIT_AGENT_PROTOCOL) &&
        text_equals(document, root, "type", "result") &&
        text_equals(document, root, "message_id", command->message_id) &&
        text_equals(document, root, "agent_id", command->agent_id) &&
        text_equals(document, root, "command", command->command) &&
        maelys_json_object_get_string(document, root, "status", &status) == MAELYS_JSON_OK &&
        (!strcmp(status.data, "ok") || !strcmp(status.data, "denied") || !strcmp(status.data, "failed")) &&
        maelys_json_object_get(document, root, "payload", &payload) == MAELYS_JSON_OK &&
        maelys_json_value_type(document, payload) == MAELYS_JSON_TYPE_OBJECT;
    if (valid) *out_succeeded = strcmp(status.data, "ok") == 0;
    maelys_json_document_release(document);
    if (!valid) {
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "executor result does not match its command envelope");
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    return MAELYS_GIT_OK;
}

static char *dump_message(json_t *root, maelys_git_error_t *error) {
    char *encoded = json_dumps(root, JSON_COMPACT | JSON_ENSURE_ASCII | JSON_SORT_KEYS);
    if (!encoded) mg_error_set(error, MAELYS_GIT_ERR_IO, 0, "could not encode JSON message");
    return encoded;
}

char *mg_protocol_encode_result(const mg_agent_message_t *command,
                                const char *status,
                                json_t *payload,
                                maelys_git_error_t *error) {
    if (!command || !status || !payload || !json_is_object(payload)) return NULL;
    json_t *root = json_object();
    if (!root || json_object_set_new(root, "protocol", json_string(MAELYS_GIT_AGENT_PROTOCOL)) != 0 ||
        json_object_set_new(root, "message_id", json_string(command->message_id)) != 0 ||
        json_object_set_new(root, "agent_id", json_string(command->agent_id)) != 0 ||
        json_object_set_new(root, "type", json_string("result")) != 0 ||
        json_object_set_new(root, "command", json_string(command->command)) != 0 ||
        json_object_set_new(root, "status", json_string(status)) != 0 ||
        json_object_set(root, "payload", payload) != 0) {
        json_decref(root);
        mg_error_set(error, MAELYS_GIT_ERR_IO, 0, "could not build result JSON");
        return NULL;
    }
    char *encoded = dump_message(root, error);
    json_decref(root);
    return encoded;
}

char *mg_protocol_encode_event(const char *agent_id,
                               const char *message_id,
                               const char *event_type,
                               json_t *payload,
                               maelys_git_error_t *error) {
    if (!agent_id || !message_id || !event_type || !json_is_object(payload)) return NULL;
    json_t *root = json_pack("{s:s,s:s,s:s,s:s,s:s,s:I,s:o}",
                             "protocol", MAELYS_GIT_AGENT_PROTOCOL,
                             "message_id", message_id,
                             "agent_id", agent_id,
                             "type", "event",
                             "event", event_type,
                             "created_at_ms", (json_int_t)mg_now_ms(),
                             "payload", json_incref(payload));
    if (!root) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, 0, "could not build event JSON");
        return NULL;
    }
    char *encoded = dump_message(root, error);
    json_decref(root);
    return encoded;
}

maelys_git_result_t maelys_git_protocol_write_decision(
    FILE *output,
    const char *request_id,
    const maelys_git_policy_decision_t *decision,
    maelys_git_error_t *error) {
    if (!output || !decision) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    json_t *root = json_pack("{s:s,s:s,s:s,s:b,s:b,s:s}",
                             "protocol", MAELYS_GIT_AGENT_PROTOCOL,
                             "type", "decision",
                             "message_id", request_id ? request_id : "",
                             "allowed", decision->allowed,
                             "explicit_deny", decision->explicit_deny,
                             "reason", decision->reason);
    if (!root || json_dumpf(root, output, JSON_COMPACT | JSON_ENSURE_ASCII) != 0 ||
        fputc('\n', output) == EOF || fflush(output) != 0) {
        json_decref(root);
        mg_error_set(error, MAELYS_GIT_ERR_IO, 0, "failed to write protocol response");
        return MAELYS_GIT_ERR_IO;
    }
    json_decref(root);
    return MAELYS_GIT_OK;
}
