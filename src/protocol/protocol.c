#include "agent/agent_internal.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

static int object_has_only(json_t *object, const char *const *allowed) {
    const char *key;
    json_t *value;
    json_object_foreach(object, key, value) {
        (void)value;
        int found = 0;
        for (size_t i = 0u; allowed[i]; ++i) {
            if (strcmp(key, allowed[i]) == 0) { found = 1; break; }
        }
        if (!found) return 0;
    }
    return 1;
}

static int identifier_valid(const char *value, size_t maximum) {
    size_t length = value ? strlen(value) : 0u;
    if (length == 0u || length >= maximum) return 0;
    for (size_t i = 0u; i < length; ++i) {
        unsigned char ch = (unsigned char)value[i];
        if (!(isalnum(ch) || ch == '-' || ch == '_' || ch == '.' || ch == ':')) return 0;
    }
    return 1;
}

static int copy_required_string(json_t *object,
                                const char *name,
                                char *out,
                                size_t capacity) {
    json_t *value = json_object_get(object, name);
    return json_is_string(value) &&
           identifier_valid(json_string_value(value), capacity) &&
           mg_copy_string(out, capacity, json_string_value(value));
}

static int copy_required_text(json_t *object,
                              const char *name,
                              char *out,
                              size_t capacity) {
    json_t *value = json_object_get(object, name);
    return json_is_string(value) && json_string_length(value) > 0u &&
           mg_copy_string(out, capacity, json_string_value(value));
}

static int copy_optional_string(json_t *object,
                                const char *name,
                                char *out,
                                size_t capacity) {
    json_t *value = json_object_get(object, name);
    if (!value) { out[0] = '\0'; return 1; }
    if (!json_is_string(value)) return 0;
    const char *text = json_string_value(value);
    return text[0] != '\0' && mg_copy_string(out, capacity, text);
}

maelys_git_result_t mg_protocol_parse(const char *bytes,
                                      size_t length,
                                      mg_agent_message_t *out,
                                      maelys_git_error_t *error) {
    static const char *const allowed[] = {
        "protocol", "message_id", "agent_id", "type", "command",
        "repository", "principal", "issued_at_ms", "expires_at_ms", "payload", NULL
    };
    if (!bytes || !out || length == 0u) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    if (length > MAELYS_GIT_MAX_PROTOCOL_LINE) {
        mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0, "JSON message exceeds 64 KiB");
        return MAELYS_GIT_ERR_LIMIT;
    }

    json_error_t json_error;
    json_t *root = json_loadb(bytes, length, JSON_REJECT_DUPLICATES, &json_error);
    if (!root) {
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0,
                     "invalid JSON at line %d, column %d: %.160s",
                     json_error.line, json_error.column, json_error.text);
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    if (!json_is_object(root) || !object_has_only(root, allowed)) {
        json_decref(root);
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0,
                     "message must be an object with only documented fields");
        return MAELYS_GIT_ERR_PROTOCOL;
    }

    json_t *issued = json_object_get(root, "issued_at_ms");
    json_t *expires = json_object_get(root, "expires_at_ms");
    json_t *payload = json_object_get(root, "payload");
    int valid = copy_required_text(root, "protocol", out->protocol, sizeof(out->protocol)) &&
                copy_required_string(root, "message_id", out->message_id, sizeof(out->message_id)) &&
                copy_required_string(root, "agent_id", out->agent_id, sizeof(out->agent_id)) &&
                copy_required_string(root, "type", out->type, sizeof(out->type)) &&
                copy_required_string(root, "command", out->command, sizeof(out->command)) &&
                copy_optional_string(root, "repository", out->repository, sizeof(out->repository)) &&
                copy_optional_string(root, "principal", out->principal, sizeof(out->principal)) &&
                json_is_integer(issued) && json_is_integer(expires) && json_is_object(payload);
    if (valid) {
        out->issued_at_ms = (int64_t)json_integer_value(issued);
        out->expires_at_ms = (int64_t)json_integer_value(expires);
        valid = strcmp(out->protocol, MAELYS_GIT_AGENT_PROTOCOL) == 0 &&
                strcmp(out->type, "command") == 0 &&
                out->issued_at_ms > 0 && out->expires_at_ms >= out->issued_at_ms;
    }
    if (!valid) {
        json_decref(root);
        memset(out, 0, sizeof(*out));
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0,
                     "message does not match protocol %s", MAELYS_GIT_AGENT_PROTOCOL);
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    out->payload = json_incref(payload);
    json_decref(root);
    return MAELYS_GIT_OK;
}

void mg_protocol_message_clear(mg_agent_message_t *message) {
    if (!message) return;
    json_decref(message->payload);
    memset(message, 0, sizeof(*message));
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
