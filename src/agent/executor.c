#include "agent_internal.h"

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

static const char *required_string(json_t *object, const char *name) {
    json_t *value = json_object_get(object, name);
    return json_is_string(value) && json_string_length(value) > 0u ? json_string_value(value) : NULL;
}

static char *failure(const mg_agent_message_t *message,
                     const char *status,
                     maelys_git_result_t code,
                     const char *description,
                     maelys_git_error_t *error) {
    json_t *payload = json_pack("{s:s,s:s}", "code", maelys_git_result_name(code),
                                "message", description && *description ? description : "operation failed");
    char *encoded = payload ? mg_protocol_encode_result(message, status, payload, error) : NULL;
    json_decref(payload);
    return encoded;
}

static maelys_git_result_t authorize(maelys_git_policy_t *policy,
                                     const mg_agent_message_t *message,
                                     const char *operation,
                                     const char *ref_name,
                                     const char *const *paths,
                                     size_t path_count,
                                     maelys_git_policy_decision_t *decision,
                                     maelys_git_error_t *error) {
    if (message->principal[0] == '\0' || message->repository[0] == '\0') {
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0,
                     "principal and repository are required for this command");
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    maelys_git_policy_request_t request = {
        .request_id = message->message_id,
        .principal = message->principal,
        .repository = message->repository,
        .operation = operation,
        .ref_name = ref_name,
        .paths = paths,
        .path_count = path_count,
    };
    return maelys_git_policy_authorize(policy, &request, decision, error);
}

static char *decision_result(const mg_agent_message_t *message,
                             const maelys_git_policy_decision_t *decision,
                             maelys_git_error_t *error) {
    json_t *payload = json_pack("{s:b,s:b,s:s}",
        "allowed", decision->allowed, "explicit_deny", decision->explicit_deny,
        "reason", decision->reason);
    char *encoded = payload ? mg_protocol_encode_result(
        message, decision->allowed ? "ok" : "denied", payload, error) : NULL;
    json_decref(payload);
    return encoded;
}

static char *execute_authorize(maelys_git_policy_t *policy,
                               const mg_agent_message_t *message,
                               maelys_git_error_t *error) {
    static const char *const allowed[] = {"operation", "ref", "paths", NULL};
    if (!object_has_only(message->payload, allowed))
        return failure(message, "failed", MAELYS_GIT_ERR_PROTOCOL, "unknown authorize field", error);
    const char *operation = required_string(message->payload, "operation");
    json_t *ref = json_object_get(message->payload, "ref");
    json_t *paths_json = json_object_get(message->payload, "paths");
    if (!operation || (ref && !json_is_string(ref)) || (paths_json && !json_is_array(paths_json)) ||
        (paths_json && json_array_size(paths_json) > MAELYS_GIT_MAX_CHANGED_PATHS))
        return failure(message, "failed", MAELYS_GIT_ERR_PROTOCOL, "invalid authorize payload", error);
    const char *paths[MAELYS_GIT_MAX_CHANGED_PATHS];
    size_t path_count = paths_json ? json_array_size(paths_json) : 0u;
    for (size_t i = 0u; i < path_count; ++i) {
        json_t *item = json_array_get(paths_json, i);
        if (!json_is_string(item) || json_string_length(item) == 0u) {
            return failure(message, "failed", MAELYS_GIT_ERR_PROTOCOL, "invalid path", error);
        }
        paths[i] = json_string_value(item);
    }
    maelys_git_policy_decision_t decision;
    maelys_git_result_t result = authorize(policy, message, operation,
        ref ? json_string_value(ref) : NULL, paths, path_count, &decision, error);
    if (result != MAELYS_GIT_OK) return failure(message, "failed", result, error->message, error);
    return decision_result(message, &decision, error);
}

static char *execute_repository_info(maelys_git_policy_t *policy,
                                     const char *root,
                                     const mg_agent_message_t *message,
                                     maelys_git_error_t *error) {
    static const char *const allowed[] = {NULL};
    if (!object_has_only(message->payload, allowed))
        return failure(message, "failed", MAELYS_GIT_ERR_PROTOCOL, "repository_info payload must be empty", error);
    maelys_git_policy_decision_t decision;
    maelys_git_result_t result = authorize(policy, message, "read", NULL, NULL, 0u, &decision, error);
    if (result != MAELYS_GIT_OK) return failure(message, "failed", result, error->message, error);
    if (!decision.allowed) return decision_result(message, &decision, error);
    char repository_path[4096];
    result = maelys_git_resolve_repository(root, message->repository, repository_path,
                                           sizeof(repository_path), error);
    if (result != MAELYS_GIT_OK) return failure(message, "failed", result, error->message, error);
    json_t *payload = json_pack("{s:s,s:b}", "repository", message->repository, "exists", 1);
    char *encoded = payload ? mg_protocol_encode_result(message, "ok", payload, error) : NULL;
    json_decref(payload);
    return encoded;
}

static char *execute_diff(maelys_git_policy_t *policy,
                          const char *git,
                          const char *root,
                          const mg_agent_message_t *message,
                          maelys_git_error_t *error) {
    static const char *const allowed[] = {"old_oid", "new_oid", NULL};
    const char *old_oid = required_string(message->payload, "old_oid");
    const char *new_oid = required_string(message->payload, "new_oid");
    if (!object_has_only(message->payload, allowed) || !old_oid || !new_oid)
        return failure(message, "failed", MAELYS_GIT_ERR_PROTOCOL, "invalid diff payload", error);
    maelys_git_policy_decision_t decision;
    maelys_git_result_t result = authorize(policy, message, "read", NULL, NULL, 0u, &decision, error);
    if (result != MAELYS_GIT_OK) return failure(message, "failed", result, error->message, error);
    if (!decision.allowed) return decision_result(message, &decision, error);
    char repository_path[4096];
    result = maelys_git_resolve_repository(root, message->repository, repository_path,
                                           sizeof(repository_path), error);
    maelys_git_path_list_t paths;
    if (result == MAELYS_GIT_OK)
        result = maelys_git_repository_changed_paths(git, repository_path, old_oid, new_oid, &paths, error);
    if (result != MAELYS_GIT_OK) return failure(message, "failed", result, error->message, error);
    json_t *array = json_array();
    for (size_t i = 0u; array && i < paths.count; ++i) {
        if (json_array_append_new(array, json_string(paths.items[i])) != 0) {
            json_decref(array); array = NULL;
        }
    }
    maelys_git_path_list_clear(&paths);
    json_t *payload = array ? json_pack("{s:o}", "paths", array) : NULL;
    char *encoded = payload ? mg_protocol_encode_result(message, "ok", payload, error) : NULL;
    json_decref(payload);
    return encoded;
}

static char *execute_update_ref(maelys_git_policy_t *policy,
                                const char *git,
                                const char *root,
                                const mg_agent_message_t *message,
                                maelys_git_error_t *error) {
    static const char *const allowed[] = {"ref", "old_oid", "new_oid", NULL};
    const char *ref = required_string(message->payload, "ref");
    const char *old_oid = required_string(message->payload, "old_oid");
    const char *new_oid = required_string(message->payload, "new_oid");
    if (!object_has_only(message->payload, allowed) || !ref || !old_oid || !new_oid)
        return failure(message, "failed", MAELYS_GIT_ERR_PROTOCOL, "invalid update_ref payload", error);
    char repository_path[4096];
    maelys_git_result_t result = maelys_git_resolve_repository(root, message->repository,
        repository_path, sizeof(repository_path), error);
    maelys_git_path_list_t changed = {0};
    if (result == MAELYS_GIT_OK)
        result = maelys_git_repository_changed_paths(git, repository_path, old_oid, new_oid, &changed, error);
    if (result != MAELYS_GIT_OK) return failure(message, "failed", result, error->message, error);
    maelys_git_policy_decision_t decision;
    result = authorize(policy, message, "push", ref, (const char *const *)changed.items,
                       changed.count, &decision, error);
    if (result != MAELYS_GIT_OK) {
        maelys_git_path_list_clear(&changed);
        return failure(message, "failed", result, error->message, error);
    }
    if (!decision.allowed) {
        maelys_git_path_list_clear(&changed);
        return decision_result(message, &decision, error);
    }
    result = maelys_git_repository_update_ref(git, repository_path, ref, new_oid, old_oid, error);
    size_t changed_count = changed.count;
    maelys_git_path_list_clear(&changed);
    if (result != MAELYS_GIT_OK) return failure(message, "failed", result, error->message, error);
    json_t *payload = json_pack("{s:s,s:I}", "ref", ref, "changed_paths", (json_int_t)changed_count);
    char *encoded = payload ? mg_protocol_encode_result(message, "ok", payload, error) : NULL;
    json_decref(payload);
    return encoded;
}

static char *execute_create_repository(maelys_git_policy_t *policy,
                                       const char *git,
                                       const char *root,
                                       const mg_agent_message_t *message,
                                       maelys_git_error_t *error) {
    static const char *const allowed[] = {NULL};
    if (!object_has_only(message->payload, allowed))
        return failure(message, "failed", MAELYS_GIT_ERR_PROTOCOL, "create_repository payload must be empty", error);
    maelys_git_policy_decision_t decision;
    maelys_git_result_t result = authorize(policy, message, "create", NULL, NULL, 0u, &decision, error);
    if (result != MAELYS_GIT_OK) return failure(message, "failed", result, error->message, error);
    if (!decision.allowed) return decision_result(message, &decision, error);
    result = maelys_git_repository_init_bare(git, root, message->repository, error);
    if (result != MAELYS_GIT_OK) return failure(message, "failed", result, error->message, error);
    json_t *payload = json_pack("{s:s}", "repository", message->repository);
    char *encoded = payload ? mg_protocol_encode_result(message, "ok", payload, error) : NULL;
    json_decref(payload);
    return encoded;
}

maelys_git_result_t mg_executor_execute(maelys_git_policy_t *policy,
                                        const char *git_executable,
                                        const char *repository_root,
                                        const mg_agent_message_t *message,
                                        char **out_result_json,
                                        maelys_git_error_t *error) {
    if (!policy || !git_executable || !repository_root || !message || !out_result_json)
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    *out_result_json = NULL;
    int64_t now = mg_now_ms();
    if (now > message->expires_at_ms || message->issued_at_ms > now + 300000) {
        *out_result_json = failure(message, "failed", MAELYS_GIT_ERR_DENIED,
                                   "command is expired or issued too far in the future", error);
    } else if (strcmp(message->command, "health") == 0) {
        static const char *const allowed[] = {NULL};
        if (!object_has_only(message->payload, allowed))
            *out_result_json = failure(message, "failed", MAELYS_GIT_ERR_PROTOCOL,
                                       "health payload must be empty", error);
        else {
            json_t *payload = json_pack("{s:b,s:s}", "healthy", 1, "version", MAELYS_GIT_VERSION);
            *out_result_json = payload ? mg_protocol_encode_result(message, "ok", payload, error) : NULL;
            json_decref(payload);
        }
    } else if (strcmp(message->command, "authorize") == 0) {
        *out_result_json = execute_authorize(policy, message, error);
    } else if (strcmp(message->command, "repository_info") == 0) {
        *out_result_json = execute_repository_info(policy, repository_root, message, error);
    } else if (strcmp(message->command, "diff") == 0) {
        *out_result_json = execute_diff(policy, git_executable, repository_root, message, error);
    } else if (strcmp(message->command, "update_ref") == 0) {
        *out_result_json = execute_update_ref(policy, git_executable, repository_root, message, error);
    } else if (strcmp(message->command, "create_repository") == 0) {
        *out_result_json = execute_create_repository(policy, git_executable, repository_root, message, error);
    } else {
        *out_result_json = failure(message, "failed", MAELYS_GIT_ERR_INVALID_COMMAND,
                                   "unsupported command", error);
    }
    if (!*out_result_json) {
        if (!error || error->code == MAELYS_GIT_OK)
            mg_error_set(error, MAELYS_GIT_ERR_IO, 0, "could not encode executor result");
        return MAELYS_GIT_ERR_IO;
    }
    return MAELYS_GIT_OK;
}
