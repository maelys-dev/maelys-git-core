#include "agent_internal.h"

#include <stdint.h>
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

static maelys_git_merge_style_t required_style(json_t *object) {
    const char *style = required_string(object, "style");
    if (style && strcmp(style, "ff") == 0) return MAELYS_GIT_MERGE_FAST_FORWARD;
    if (style && strcmp(style, "merge") == 0) return MAELYS_GIT_MERGE_COMMIT;
    if (style && strcmp(style, "squash") == 0) return MAELYS_GIT_MERGE_SQUASH;
    return 0;
}

static maelys_git_result_t pr_source_from_payload(
    json_t *payload,
    const char *root,
    char source_path[4096],
    maelys_git_pr_source_t *source,
    const maelys_git_pr_source_t **out_source,
    maelys_git_error_t *error) {
    json_t *repository_json = json_object_get(payload, "source_repository");
    json_t *ref_json = json_object_get(payload, "source_ref");
    json_t *objects_json = json_object_get(payload, "max_source_objects");
    json_t *bytes_json = json_object_get(payload, "max_source_bytes");
    json_t *identity_json = json_object_get(payload, "expected_source_identity");
    *out_source = NULL;
    memset(source, 0, sizeof(*source));
    if (!repository_json && !ref_json) {
        if (objects_json || bytes_json || identity_json) {
            mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0,
                         "source quota or identity requires a source repository and ref");
            return MAELYS_GIT_ERR_PROTOCOL;
        }
        return MAELYS_GIT_OK;
    }
    if (!json_is_string(repository_json) || json_string_length(repository_json) == 0u ||
        !json_is_string(ref_json) || json_string_length(ref_json) == 0u ||
        (objects_json && (!json_is_integer(objects_json) ||
                          json_integer_value(objects_json) <= 0 ||
                          (uint64_t)json_integer_value(objects_json) > SIZE_MAX)) ||
        (bytes_json && (!json_is_integer(bytes_json) ||
                        json_integer_value(bytes_json) <= 0)) ||
        (identity_json && (!json_is_string(identity_json) ||
                           json_string_length(identity_json) == 0u))) {
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0,
                     "invalid cross-repository PR source fields");
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    const char *repository = json_string_value(repository_json);
    maelys_git_result_t rc = maelys_git_resolve_repository(
        root, repository, source_path, 4096u, error);
    if (rc != MAELYS_GIT_OK) return rc;
    source->repository_path = source_path;
    source->repository_name = repository;
    source->ref_name = json_string_value(ref_json);
    source->expected_identity = identity_json ? json_string_value(identity_json) : NULL;
    source->max_objects = objects_json ?
        (size_t)json_integer_value(objects_json) : MAELYS_GIT_PR_DEFAULT_MAX_SOURCE_OBJECTS;
    source->max_bytes = bytes_json ?
        (uint64_t)json_integer_value(bytes_json) : MAELYS_GIT_PR_DEFAULT_MAX_SOURCE_BYTES;
    *out_source = source;
    return MAELYS_GIT_OK;
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

static json_t *pr_payload(maelys_git_pr_check_result_t *result, int applied) {
    json_t *payload = json_object();
    json_t *conflicts = json_array();
    if (!payload || !conflicts) {
        json_decref(payload);
        json_decref(conflicts);
        return NULL;
    }
    for (size_t i = 0u; i < result->conflict_paths.count; ++i)
        if (json_array_append_new(conflicts, json_string(result->conflict_paths.items[i])) != 0) {
            json_decref(payload);
            json_decref(conflicts);
            return NULL;
        }
    if (json_object_set(payload, "conflicts", conflicts) != 0) {
        json_decref(payload);
        json_decref(conflicts);
        return NULL;
    }
    json_decref(conflicts);
    const char *event_type = applied ? "pr_merged" :
                             (result->pr_id[0] ? "pr_planned" : "pr_checked");
    if (json_object_set_new(payload, "applied", json_boolean(applied)) != 0 ||
        json_object_set_new(payload, "mergeable", json_boolean(result->mergeable)) != 0 ||
        json_object_set_new(payload, "empty", json_boolean(result->empty)) != 0 ||
        json_object_set_new(payload, "cross_repository", json_boolean(result->cross_repository)) != 0 ||
        json_object_set_new(payload, "source_repository", json_string(result->source_repository)) != 0 ||
        json_object_set_new(payload, "source_ref", json_string(result->source_ref)) != 0 ||
        json_object_set_new(payload, "source_oid", json_string(result->source_oid)) != 0 ||
        json_object_set_new(payload, "source_identity", json_string(result->source_identity)) != 0 ||
        json_object_set_new(payload, "source_object_count",
                            json_integer((json_int_t)result->source_object_count)) != 0 ||
        json_object_set_new(payload, "source_object_bytes",
                            json_integer((json_int_t)result->source_object_bytes)) != 0 ||
        json_object_set_new(payload, "target_identity",
                            json_string(result->target_identity)) != 0 ||
        json_object_set_new(payload, "merge_base_oid", json_string(result->merge_base_oid)) != 0 ||
        json_object_set_new(payload, "merge_tree_oid", json_string(result->merge_tree_oid)) != 0 ||
        json_object_set_new(payload, "prepared_oid", json_string(result->prepared_oid)) != 0 ||
        json_object_set_new(payload, "policy_fingerprint", json_string(result->policy_fingerprint)) != 0 ||
        json_object_set_new(payload, "pr_id", json_string(result->pr_id)) != 0 ||
        json_object_set_new(payload, "pr_head_ref", json_string(result->pr_head_ref)) != 0 ||
        json_object_set_new(payload, "pr_merged_ref", json_string(result->pr_merged_ref)) != 0 ||
        json_object_set_new(payload, "event_type", json_string(event_type)) != 0 ||
        json_object_set_new(payload, "changed_count",
                            json_integer((json_int_t)result->changes.changed_count)) != 0 ||
        json_object_set_new(payload, "added_count",
                            json_integer((json_int_t)result->changes.added_count)) != 0 ||
        json_object_set_new(payload, "modified_count",
                            json_integer((json_int_t)result->changes.modified_count)) != 0 ||
        json_object_set_new(payload, "deleted_count",
                            json_integer((json_int_t)result->changes.deleted_count)) != 0 ||
        json_object_set_new(payload, "renamed_count",
                            json_integer((json_int_t)result->changes.renamed_count)) != 0 ||
        json_object_set_new(payload, "max_new_blob_size",
                            json_integer((json_int_t)result->changes.max_new_blob_size)) != 0 ||
        json_object_set_new(payload, "total_new_blob_size",
                            json_integer((json_int_t)result->changes.total_new_blob_size)) != 0 ||
        json_object_set_new(payload, "inspected_blob_bytes",
                            json_integer((json_int_t)result->changes.inspected_blob_bytes)) != 0 ||
        json_object_set_new(payload, "has_binary", json_boolean(result->changes.has_binary)) != 0) {
        json_decref(payload);
        return NULL;
    }
    return payload;
}

static char *execute_pr_check(maelys_git_policy_t *policy,
                              const char *git,
                              const char *root,
                              const mg_agent_message_t *message,
                              maelys_git_error_t *error) {
    static const char *const allowed[] = {
        "base_oid", "head_oid", "style", "message", "source_repository",
        "source_ref", "max_source_objects", "max_source_bytes", NULL};
    const char *base = required_string(message->payload, "base_oid");
    const char *head = required_string(message->payload, "head_oid");
    const char *merge_message = NULL;
    json_t *message_json = json_object_get(message->payload, "message");
    if (json_is_string(message_json)) merge_message = json_string_value(message_json);
    maelys_git_merge_style_t style = required_style(message->payload);
    if (!object_has_only(message->payload, allowed) || !base || !head || !style ||
        (message_json && !json_is_string(message_json)))
        return failure(message, "failed", MAELYS_GIT_ERR_PROTOCOL, "invalid pr_check payload", error);
    maelys_git_policy_decision_t decision;
    maelys_git_result_t result = authorize(policy, message, "read", NULL, NULL, 0u,
                                           &decision, error);
    if (result != MAELYS_GIT_OK) return failure(message, "failed", result, error->message, error);
    if (!decision.allowed) return decision_result(message, &decision, error);
    char repository_path[4096];
    result = maelys_git_resolve_repository(root, message->repository, repository_path,
                                           sizeof(repository_path), error);
    char source_path[4096];
    maelys_git_pr_source_t source_storage;
    const maelys_git_pr_source_t *source = NULL;
    if (result == MAELYS_GIT_OK)
        result = pr_source_from_payload(message->payload, root, source_path,
                                        &source_storage, &source, error);
    maelys_git_pr_check_result_t check;
    if (result == MAELYS_GIT_OK)
        result = maelys_git_pr_check_with_source(
            git, repository_path, base, head, style, merge_message,
            source, &check, error);
    if (result != MAELYS_GIT_OK) return failure(message, "failed", result, error->message, error);
    json_t *payload = pr_payload(&check, 0);
    maelys_git_pr_check_result_clear(&check);
    char *encoded = payload ? mg_protocol_encode_result(message, "ok", payload, error) : NULL;
    json_decref(payload);
    return encoded;
}

static char *execute_pr_merge(maelys_git_policy_t *policy,
                              const char *git,
                              const char *root,
                              const mg_agent_message_t *message,
                              maelys_git_error_t *error) {
    static const char *const allowed[] = {
        "base_ref", "base_oid", "head_oid", "style", "message", "approvals",
        "required_approvals", "status_checks_passed", "blocking_review", "apply",
        "expected_prepared_oid", "expected_policy_fingerprint", "pr_id",
        "source_repository", "source_ref", "max_source_objects", "max_source_bytes",
        "expected_source_identity", "expected_target_identity", NULL};
    const char *base_ref = required_string(message->payload, "base_ref");
    const char *base = required_string(message->payload, "base_oid");
    const char *head = required_string(message->payload, "head_oid");
    maelys_git_merge_style_t style = required_style(message->payload);
    json_t *approvals = json_object_get(message->payload, "approvals");
    json_t *required = json_object_get(message->payload, "required_approvals");
    json_t *checks = json_object_get(message->payload, "status_checks_passed");
    json_t *blocking = json_object_get(message->payload, "blocking_review");
    json_t *apply = json_object_get(message->payload, "apply");
    const char *expected_prepared_oid =
        required_string(message->payload, "expected_prepared_oid");
    const char *expected_policy_fingerprint =
        required_string(message->payload, "expected_policy_fingerprint");
    const char *expected_target_identity =
        required_string(message->payload, "expected_target_identity");
    json_t *pr_id_json = json_object_get(message->payload, "pr_id");
    const char *pr_id = json_is_string(pr_id_json) ? json_string_value(pr_id_json) : NULL;
    json_t *message_json = json_object_get(message->payload, "message");
    if (!object_has_only(message->payload, allowed) || !base_ref || !base || !head || !style ||
        !json_is_integer(approvals) || json_integer_value(approvals) < 0 ||
        !json_is_integer(required) || json_integer_value(required) < 0 ||
        !json_is_boolean(checks) || !json_is_boolean(blocking) || !json_is_boolean(apply) ||
        (json_is_true(apply) && (!expected_target_identity ||
                                 !expected_prepared_oid ||
                                 !expected_policy_fingerprint)) ||
        (pr_id_json && (!json_is_string(pr_id_json) || json_string_length(pr_id_json) == 0u)) ||
        (message_json && !json_is_string(message_json)))
        return failure(message, "failed", MAELYS_GIT_ERR_PROTOCOL, "invalid pr_merge payload", error);
    char repository_path[4096];
    maelys_git_result_t result = maelys_git_resolve_repository(
        root, message->repository, repository_path, sizeof(repository_path), error);
    if (result != MAELYS_GIT_OK) return failure(message, "failed", result, error->message, error);
    char source_path[4096];
    maelys_git_pr_source_t source_storage;
    const maelys_git_pr_source_t *source = NULL;
    result = pr_source_from_payload(message->payload, root, source_path,
                                    &source_storage, &source, error);
    if (result != MAELYS_GIT_OK)
        return failure(message, "failed", result, error->message, error);
    if (source && json_is_true(apply) && !source->expected_identity)
        return failure(message, "failed", MAELYS_GIT_ERR_PROTOCOL,
                       "cross-repository apply requires expected_source_identity", error);
    maelys_git_pr_gates_t gates = {
        .approvals = (size_t)json_integer_value(approvals),
        .required_approvals = (size_t)json_integer_value(required),
        .status_checks_passed = json_is_true(checks),
        .blocking_review = json_is_true(blocking),
    };
    maelys_git_pr_check_result_t merge;
    result = maelys_git_pr_merge_with_source(
        git, repository_path, message->repository, base_ref, base, head, style,
        json_is_string(message_json) ? json_string_value(message_json) : NULL,
        message->principal, &gates, policy, pr_id, source,
        expected_target_identity, expected_prepared_oid,
        expected_policy_fingerprint, json_is_true(apply), &merge, error);
    if (result == MAELYS_GIT_ERR_DENIED)
        return failure(message, "denied", result, error->message, error);
    if (result != MAELYS_GIT_OK) return failure(message, "failed", result, error->message, error);
    json_t *payload = pr_payload(&merge, json_is_true(apply));
    maelys_git_pr_check_result_clear(&merge);
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
    } else if (strcmp(message->command, "pr_check") == 0) {
        *out_result_json = execute_pr_check(policy, git_executable, repository_root, message, error);
    } else if (strcmp(message->command, "pr_merge") == 0) {
        *out_result_json = execute_pr_merge(policy, git_executable, repository_root, message, error);
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
