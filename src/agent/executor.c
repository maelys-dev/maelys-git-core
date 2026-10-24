#include "agent_internal.h"
#include "maelys_git_receipt.h"
#include "policy/policy_grants.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int payload_has_only(const mg_agent_message_t *message, const char *const *allowed) {
    return mg_document_object_has_only(message->document, message->payload, allowed);
}

/* The payload members each command accepts. protocol/agent-v1.schema.json
 * declares the same members for the same commands, which a test holds. */
static const char *const health_members[] = {NULL};
static const char *const authorize_members[] = {"operation", "ref", "paths", "explain", NULL};
static const char *const repository_info_members[] = {NULL};
static const char *const diff_members[] = {"old_oid", "new_oid", NULL};
static const char *const update_ref_members[] = {"ref", "old_oid", "new_oid", NULL};
static const char *const create_repository_members[] = {NULL};
static const char *const pr_check_members[] = {
    "base_oid", "head_oid", "style", "message", "source_repository",
    "source_ref", "max_source_objects", "max_source_bytes", NULL};
static const char *const pr_merge_members[] = {
    "base_ref", "base_oid", "head_oid", "style", "message", "approvals",
    "required_approvals", "status_checks_passed", "blocking_review", "apply",
    "expected_prepared_oid", "expected_policy_fingerprint", "expected_grants_fingerprint", "pr_id",
    "source_repository", "source_ref", "max_source_objects", "max_source_bytes",
    "expected_source_identity", "expected_target_identity", NULL};

const mg_executor_payload_t mg_executor_payloads[] = {
    {"health", health_members},
    {"authorize", authorize_members},
    {"repository_info", repository_info_members},
    {"diff", diff_members},
    {"update_ref", update_ref_members},
    {"create_repository", create_repository_members},
    {"pr_check", pr_check_members},
    {"pr_merge", pr_merge_members},
    {NULL, NULL}};

static const char *required_string(const mg_agent_message_t *message, const char *name) {
    maelys_json_view_t view;
    return maelys_json_object_get_string(message->document, message->payload, name, &view) == MAELYS_JSON_OK &&
           view.size > 0u ? view.data : NULL;
}

/* Absent is valid; a present field must be a nonempty string. */
static const char *optional_string(const mg_agent_message_t *message, const char *name,
                                   int *valid) {
    maelys_json_view_t view;
    maelys_json_result_t result = maelys_json_object_get_string(
        message->document, message->payload, name, &view);
    if (result == MAELYS_JSON_ERR_NOT_FOUND) return NULL;
    if (result != MAELYS_JSON_OK || view.size == 0u) { *valid = 0; return NULL; }
    return view.data;
}

static int optional_positive(const mg_agent_message_t *message, const char *name,
                             uint64_t *out, int *present) {
    int64_t value;
    maelys_json_result_t result = maelys_json_object_get_i64(
        message->document, message->payload, name, &value);
    *present = result != MAELYS_JSON_ERR_NOT_FOUND;
    if (!*present) return 1;
    if (result != MAELYS_JSON_OK || value <= 0) return 0;
    *out = (uint64_t)value;
    return 1;
}

static maelys_git_merge_style_t required_style(const mg_agent_message_t *message) {
    const char *style = required_string(message, "style");
    if (style && strcmp(style, "ff") == 0) return MAELYS_GIT_MERGE_FAST_FORWARD;
    if (style && strcmp(style, "merge") == 0) return MAELYS_GIT_MERGE_COMMIT;
    if (style && strcmp(style, "squash") == 0) return MAELYS_GIT_MERGE_SQUASH;
    return 0;
}

static maelys_git_result_t pr_source_from_payload(
    const mg_agent_message_t *message,
    const char *root,
    char source_path[4096],
    maelys_git_pr_source_t *source,
    const maelys_git_pr_source_t **out_source,
    maelys_git_error_t *error) {
    int valid = 1;
    const char *repository = optional_string(message, "source_repository", &valid);
    const char *ref = optional_string(message, "source_ref", &valid);
    const char *identity = optional_string(message, "expected_source_identity", &valid);
    uint64_t objects = MAELYS_GIT_PR_DEFAULT_MAX_SOURCE_OBJECTS;
    uint64_t bytes = MAELYS_GIT_PR_DEFAULT_MAX_SOURCE_BYTES;
    int objects_present = 0, bytes_present = 0;
    valid = optional_positive(message, "max_source_objects", &objects, &objects_present) && valid;
    valid = optional_positive(message, "max_source_bytes", &bytes, &bytes_present) && valid;
    *out_source = NULL;
    memset(source, 0, sizeof(*source));
    if (!valid || objects > SIZE_MAX) {
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "invalid cross-repository PR source fields");
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    if (!repository && !ref) {
        if (objects_present || bytes_present || identity) {
            mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0,
                         "source quota or identity requires a source repository and ref");
            return MAELYS_GIT_ERR_PROTOCOL;
        }
        return MAELYS_GIT_OK;
    }
    if (!repository || !ref) {
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0,
                     "source repository and ref must be supplied together");
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    maelys_git_result_t rc = maelys_git_resolve_repository(
        root, repository, source_path, 4096u, error);
    if (rc != MAELYS_GIT_OK) return rc;
    source->repository_path = source_path;
    source->repository_name = repository;
    source->ref_name = ref;
    source->expected_identity = identity;
    source->max_objects = (size_t)objects;
    source->max_bytes = bytes;
    *out_source = source;
    return MAELYS_GIT_OK;
}

/* A failed command reports its result code and message; a policy failure
 * adds its detail, with the members `validate` reports (mg_json_failure_detail).
 * The detail is read before encoding, which may reset it. */
static char *failure(const mg_agent_message_t *message,
                     const char *status,
                     maelys_git_result_t code,
                     const char *description,
                     maelys_git_error_t *error) {
    maelys_git_failure_detail_t detail = {.kind = MAELYS_GIT_FAILURE_NONE};
    if (code == MAELYS_GIT_ERR_POLICY && error && error->code == MAELYS_GIT_ERR_POLICY)
        detail = error->detail;
    mg_json_t json;
    mg_protocol_result_begin(&json, message, status);
    mg_json_string(&json, "code", maelys_git_result_name(code));
    mg_json_string(&json, "message", description && *description ? description : "operation failed");
    if (detail.kind != MAELYS_GIT_FAILURE_NONE) {
        mg_json_object(&json, "detail");
        mg_json_failure_detail(&json, &detail);
        mg_json_end_object(&json);
    }
    return mg_protocol_result_end(&json, error);
}

/* A decision with its receipt, and the explanation text when one was asked
 * for, rendered into the caller's buffer of the exposed size. */
typedef struct {
    maelys_git_policy_decision_t decision;
    maelys_git_receipt_t receipt;
    const char *text;
} judged_t;

#define EXPLANATION_CAPACITY (MAELYS_GIT_RECEIPT_MAX_EXPLANATION_TEXT + 1u)

/* Authorizes the command's request on the path that builds its receipt.
 * `text` holds EXPLANATION_CAPACITY bytes, or is NULL when mode is NEVER. */
static maelys_git_result_t authorize(maelys_git_policy_t *policy,
                                     const mg_agent_message_t *message,
                                     const char *operation,
                                     const char *ref_name,
                                     const char *const *paths,
                                     size_t path_count,
                                     maelys_git_explain_mode_t mode,
                                     char *text,
                                     judged_t *out,
                                     maelys_git_error_t *error) {
    memset(out, 0, sizeof(*out));
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
    out->text = text;
    return maelys_git_policy_authorize_receipt(policy, &request, mode, text,
                                               text ? EXPLANATION_CAPACITY : 0u,
                                               &out->decision, &out->receipt, error);
}

/* One attempt at a decision result, with or without the explanation text. */
static char *decision_line(const mg_agent_message_t *message, const judged_t *judged,
                           const maelys_json_document_t *receipt, const char *sha256,
                           int with_text, maelys_git_error_t *error) {
    const maelys_git_policy_decision_t *decision = &judged->decision;
    mg_json_t json;
    mg_protocol_result_begin(&json, message, decision->allowed ? "ok" : "denied");
    mg_json_boolean(&json, "allowed", decision->allowed);
    mg_json_boolean(&json, "explicit_deny", decision->explicit_deny);
    mg_json_string(&json, "reason", decision->reason);
    if (decision->matched_policy == SIZE_MAX) mg_json_null(&json, "matched_policy");
    else mg_json_i64(&json, "matched_policy", (int64_t)decision->matched_policy);
    mg_json_copy(&json, "receipt", receipt, maelys_json_document_root(receipt));
    mg_json_string(&json, "receipt_sha256", sha256);
    if (with_text) mg_json_string(&json, "explanation_text", judged->text);
    return mg_protocol_result_end(&json, error);
}

/* The only exit of a decision: its members, the deciding policy, the receipt
 * copied from its canonical bytes and their digest, and the explanation
 * text when one was rendered. A result that does not fit a protocol line is
 * built again, in a new document, without the text; the receipt keeps its
 * size and digest. */
static char *decision_result(const mg_agent_message_t *message,
                             const judged_t *judged,
                             maelys_git_error_t *error) {
    char *bytes = NULL;
    size_t size = 0u;
    char sha256[65];
    if (maelys_git_receipt_serialize(&judged->receipt, &bytes, &size, sha256, error) != MAELYS_GIT_OK)
        return NULL;
    const maelys_json_limits_t limits = {
        .maximum_bytes = MAELYS_GIT_RECEIPT_MAX_BYTES, .maximum_depth = 4u, .maximum_tokens = 512u};
    maelys_json_document_t *receipt = NULL;
    maelys_json_result_t parsed = maelys_json_document_parse(
        bytes, size, MAELYS_JSON_PROFILE_RFC8259, &limits, &receipt, NULL);
    free(bytes);
    if (parsed != MAELYS_JSON_OK) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, 0, "could not read the receipt back");
        return NULL;
    }
    int with_text = judged->text && judged->receipt.explanation.has_text && judged->text[0];
    char *encoded = decision_line(message, judged, receipt, sha256, with_text, error);
    if (!encoded && with_text && error && error->code == MAELYS_GIT_ERR_LIMIT)
        encoded = decision_line(message, judged, receipt, sha256, 0, error);
    maelys_json_document_release(receipt);
    return encoded;
}

static char *execute_authorize(maelys_git_policy_t *policy,
                               const mg_agent_message_t *message,
                               maelys_git_error_t *error) {
    if (!payload_has_only(message, authorize_members))
        return failure(message, "failed", MAELYS_GIT_ERR_PROTOCOL, "unknown authorize field", error);
    const char *operation = required_string(message, "operation");
    int valid = 1;
    const char *ref = optional_string(message, "ref", &valid);
    /* explain: true asks for the explanation text in the result. */
    int explain = 0;
    maelys_json_result_t got_explain = maelys_json_object_get_boolean(
        message->document, message->payload, "explain", &explain);
    if (got_explain != MAELYS_JSON_OK && got_explain != MAELYS_JSON_ERR_NOT_FOUND) valid = 0;
    maelys_json_value_t paths_value;
    maelys_json_result_t got_paths = maelys_json_object_get(
        message->document, message->payload, "paths", &paths_value);
    size_t path_count = 0u;
    if (!valid || !operation ||
        (got_paths != MAELYS_JSON_ERR_NOT_FOUND &&
         (got_paths != MAELYS_JSON_OK ||
          maelys_json_array_size(message->document, paths_value, &path_count) != MAELYS_JSON_OK)) ||
        path_count > MAELYS_GIT_MAX_CHANGED_PATHS)
        return failure(message, "failed", MAELYS_GIT_ERR_PROTOCOL, "invalid authorize payload", error);
    const char *paths[MAELYS_GIT_MAX_CHANGED_PATHS];
    for (size_t i = 0u; i < path_count; ++i) {
        maelys_json_value_t item;
        maelys_json_view_t view;
        if (maelys_json_array_get(message->document, paths_value, i, &item) != MAELYS_JSON_OK ||
            maelys_json_value_string(message->document, item, &view) != MAELYS_JSON_OK ||
            view.size == 0u)
            return failure(message, "failed", MAELYS_GIT_ERR_PROTOCOL, "invalid path", error);
        paths[i] = view.data;
    }
    char text[EXPLANATION_CAPACITY];
    judged_t judged;
    maelys_git_result_t result = authorize(policy, message, operation, ref, paths, path_count,
        explain ? MAELYS_GIT_EXPLAIN_ALWAYS : MAELYS_GIT_EXPLAIN_NEVER, explain ? text : NULL,
        &judged, error);
    if (result != MAELYS_GIT_OK) return failure(message, "failed", result, error->message, error);
    return decision_result(message, &judged, error);
}

static char *execute_repository_info(maelys_git_policy_t *policy,
                                     const char *root,
                                     const mg_agent_message_t *message,
                                     maelys_git_error_t *error) {
    if (!payload_has_only(message, repository_info_members))
        return failure(message, "failed", MAELYS_GIT_ERR_PROTOCOL, "repository_info payload must be empty", error);
    judged_t judged;
    maelys_git_result_t result = authorize(policy, message, "read", NULL, NULL, 0u,
                                           MAELYS_GIT_EXPLAIN_NEVER, NULL, &judged, error);
    if (result != MAELYS_GIT_OK) return failure(message, "failed", result, error->message, error);
    if (!judged.decision.allowed) return decision_result(message, &judged, error);
    char repository_path[4096];
    result = maelys_git_resolve_repository(root, message->repository, repository_path,
                                           sizeof(repository_path), error);
    if (result != MAELYS_GIT_OK) return failure(message, "failed", result, error->message, error);
    mg_json_t json;
    mg_protocol_result_begin(&json, message, "ok");
    mg_json_string(&json, "repository", message->repository);
    mg_json_boolean(&json, "exists", 1);
    return mg_protocol_result_end(&json, error);
}

static char *execute_diff(maelys_git_policy_t *policy,
                          const char *git,
                          const char *root,
                          const mg_agent_message_t *message,
                          maelys_git_error_t *error) {
    const char *old_oid = required_string(message, "old_oid");
    const char *new_oid = required_string(message, "new_oid");
    if (!payload_has_only(message, diff_members) || !old_oid || !new_oid)
        return failure(message, "failed", MAELYS_GIT_ERR_PROTOCOL, "invalid diff payload", error);
    judged_t judged;
    maelys_git_result_t result = authorize(policy, message, "read", NULL, NULL, 0u,
                                           MAELYS_GIT_EXPLAIN_NEVER, NULL, &judged, error);
    if (result != MAELYS_GIT_OK) return failure(message, "failed", result, error->message, error);
    if (!judged.decision.allowed) return decision_result(message, &judged, error);
    char repository_path[4096];
    result = maelys_git_resolve_repository(root, message->repository, repository_path,
                                           sizeof(repository_path), error);
    maelys_git_path_list_t paths;
    if (result == MAELYS_GIT_OK)
        result = maelys_git_repository_changed_paths(git, repository_path, old_oid, new_oid, &paths, error);
    if (result != MAELYS_GIT_OK) return failure(message, "failed", result, error->message, error);
    mg_json_t json;
    mg_protocol_result_begin(&json, message, "ok");
    mg_json_array(&json, "paths");
    for (size_t i = 0u; i < paths.count; ++i) mg_json_string(&json, NULL, paths.items[i]);
    mg_json_end_array(&json);
    maelys_git_path_list_clear(&paths);
    return mg_protocol_result_end(&json, error);
}

static char *execute_update_ref(maelys_git_policy_t *policy,
                                const char *git,
                                const char *root,
                                const mg_agent_message_t *message,
                                maelys_git_explain_mode_t denial_mode,
                                maelys_git_error_t *error) {
    const char *ref = required_string(message, "ref");
    const char *old_oid = required_string(message, "old_oid");
    const char *new_oid = required_string(message, "new_oid");
    if (!payload_has_only(message, update_ref_members) || !ref || !old_oid || !new_oid)
        return failure(message, "failed", MAELYS_GIT_ERR_PROTOCOL, "invalid update_ref payload", error);
    char repository_path[4096];
    maelys_git_result_t result = maelys_git_resolve_repository(root, message->repository,
        repository_path, sizeof(repository_path), error);
    if (result != MAELYS_GIT_OK) return failure(message, "failed", result, error->message, error);
    if (!maelys_git_ref_name_is_valid(ref) || !mg_is_oid(old_oid) || !mg_is_oid(new_oid) ||
        !message->principal[0])
        return failure(message, "failed", MAELYS_GIT_ERR_PROTOCOL, "invalid update_ref values", error);
    FILE *updates = tmpfile();
    FILE *diagnostics = tmpfile();
    if (!updates || !diagnostics) {
        if (updates) fclose(updates);
        if (diagnostics) fclose(diagnostics);
        return failure(message, "failed", MAELYS_GIT_ERR_IO, "cannot create authorization stream", error);
    }
    maelys_git_change_summary_t summary = {0};
    char text[EXPLANATION_CAPACITY];
    judged_t judged = {.text = denial_mode == MAELYS_GIT_EXPLAIN_NEVER ? NULL : text};
    mg_receive_receipt_t receipt = {.mode = denial_mode, .text = (char *)judged.text,
                                    .text_capacity = judged.text ? sizeof(text) : 0u};
    maelys_git_inspection_limits_t limits;
    maelys_git_inspection_limits_default(&limits);
    if (fprintf(updates, "%s %s %s\n", old_oid, new_oid, ref) < 0 ||
        fflush(updates) != 0 || fseek(updates, 0L, SEEK_SET) != 0) {
        result = MAELYS_GIT_ERR_IO;
        mg_error_set(error, result, 0, "cannot write authorization stream");
    } else {
        result = mg_receive_authorize(policy, git, repository_path, message->repository,
            message->principal, &limits, NULL, 0u, updates, diagnostics, &summary,
            &judged.decision, &receipt, error);
    }
    fclose(updates);
    fclose(diagnostics);
    if (result == MAELYS_GIT_ERR_DENIED) {
        judged.receipt = receipt.receipt;
        return decision_result(message, &judged, error);
    }
    if (result != MAELYS_GIT_OK) return failure(message, "failed", result, error->message, error);
    result = maelys_git_repository_update_ref(git, repository_path, ref, new_oid, old_oid, error);
    size_t changed_count = summary.changed_count + summary.renamed_count;
    if (result != MAELYS_GIT_OK) return failure(message, "failed", result, error->message, error);
    mg_json_t json;
    mg_protocol_result_begin(&json, message, "ok");
    mg_json_string(&json, "ref", ref);
    mg_json_i64(&json, "changed_paths", (int64_t)changed_count);
    return mg_protocol_result_end(&json, error);
}

static char *execute_create_repository(maelys_git_policy_t *policy,
                                       const char *git,
                                       const char *root,
                                       const mg_agent_message_t *message,
                                       maelys_git_explain_mode_t denial_mode,
                                       maelys_git_error_t *error) {
    if (!payload_has_only(message, create_repository_members))
        return failure(message, "failed", MAELYS_GIT_ERR_PROTOCOL, "create_repository payload must be empty", error);
    char text[EXPLANATION_CAPACITY];
    judged_t judged;
    maelys_git_result_t result = authorize(policy, message, "create", NULL, NULL, 0u, denial_mode,
        denial_mode == MAELYS_GIT_EXPLAIN_NEVER ? NULL : text, &judged, error);
    if (result != MAELYS_GIT_OK) return failure(message, "failed", result, error->message, error);
    if (!judged.decision.allowed) return decision_result(message, &judged, error);
    result = maelys_git_repository_init_bare(git, root, message->repository, error);
    if (result != MAELYS_GIT_OK) return failure(message, "failed", result, error->message, error);
    mg_json_t json;
    mg_protocol_result_begin(&json, message, "ok");
    mg_json_string(&json, "repository", message->repository);
    return mg_protocol_result_end(&json, error);
}

/* The result of a pull request check or merge. */
static char *pr_result(const mg_agent_message_t *message, maelys_git_pr_check_result_t *result,
                       int applied, maelys_git_error_t *error) {
    const char *event_type = applied ? "pr_merged" :
                             (result->pr_id[0] ? "pr_planned" : "pr_checked");
    mg_json_t json;
    mg_protocol_result_begin(&json, message, "ok");
    mg_json_array(&json, "conflicts");
    for (size_t i = 0u; i < result->conflict_paths.count; ++i)
        mg_json_string(&json, NULL, result->conflict_paths.items[i]);
    mg_json_end_array(&json);
    mg_json_boolean(&json, "applied", applied);
    mg_json_boolean(&json, "mergeable", result->mergeable);
    mg_json_boolean(&json, "empty", result->empty);
    mg_json_boolean(&json, "cross_repository", result->cross_repository);
    mg_json_string(&json, "source_repository", result->source_repository);
    mg_json_string(&json, "source_ref", result->source_ref);
    mg_json_string(&json, "source_oid", result->source_oid);
    mg_json_string(&json, "source_identity", result->source_identity);
    mg_json_i64(&json, "source_object_count", (int64_t)result->source_object_count);
    mg_json_i64(&json, "source_object_bytes", (int64_t)result->source_object_bytes);
    mg_json_string(&json, "target_identity", result->target_identity);
    mg_json_string(&json, "merge_base_oid", result->merge_base_oid);
    mg_json_string(&json, "merge_tree_oid", result->merge_tree_oid);
    mg_json_string(&json, "prepared_oid", result->prepared_oid);
    mg_json_string(&json, "policy_fingerprint", result->policy_fingerprint);
    mg_json_string(&json, "grants_fingerprint", result->grants_fingerprint);
    mg_json_string(&json, "pr_id", result->pr_id);
    mg_json_string(&json, "pr_head_ref", result->pr_head_ref);
    mg_json_string(&json, "pr_merged_ref", result->pr_merged_ref);
    mg_json_string(&json, "event_type", event_type);
    mg_json_i64(&json, "changed_count", (int64_t)result->changes.changed_count);
    mg_json_i64(&json, "added_count", (int64_t)result->changes.added_count);
    mg_json_i64(&json, "modified_count", (int64_t)result->changes.modified_count);
    mg_json_i64(&json, "deleted_count", (int64_t)result->changes.deleted_count);
    mg_json_i64(&json, "renamed_count", (int64_t)result->changes.renamed_count);
    mg_json_i64(&json, "max_new_blob_size", (int64_t)result->changes.max_new_blob_size);
    mg_json_i64(&json, "total_new_blob_size", (int64_t)result->changes.total_new_blob_size);
    mg_json_i64(&json, "inspected_blob_bytes", (int64_t)result->changes.inspected_blob_bytes);
    mg_json_boolean(&json, "has_binary", result->changes.has_binary);
    maelys_git_pr_check_result_clear(result);
    return mg_protocol_result_end(&json, error);
}

static char *execute_pr_check(maelys_git_policy_t *policy,
                              const char *git,
                              const char *root,
                              const mg_agent_message_t *message,
                              maelys_git_error_t *error) {
    const char *base = required_string(message, "base_oid");
    const char *head = required_string(message, "head_oid");
    int valid = 1;
    const char *merge_message = optional_string(message, "message", &valid);
    maelys_git_merge_style_t style = required_style(message);
    if (!valid || !payload_has_only(message, pr_check_members) || !base || !head || !style)
        return failure(message, "failed", MAELYS_GIT_ERR_PROTOCOL, "invalid pr_check payload", error);
    judged_t judged;
    maelys_git_result_t result = authorize(policy, message, "read", NULL, NULL, 0u,
                                           MAELYS_GIT_EXPLAIN_NEVER, NULL, &judged, error);
    if (result != MAELYS_GIT_OK) return failure(message, "failed", result, error->message, error);
    if (!judged.decision.allowed) return decision_result(message, &judged, error);
    char repository_path[4096];
    result = maelys_git_resolve_repository(root, message->repository, repository_path,
                                           sizeof(repository_path), error);
    char source_path[4096];
    maelys_git_pr_source_t source_storage;
    const maelys_git_pr_source_t *source = NULL;
    if (result == MAELYS_GIT_OK)
        result = pr_source_from_payload(message, root, source_path,
                                        &source_storage, &source, error);
    maelys_git_pr_check_result_t check;
    if (result == MAELYS_GIT_OK)
        result = maelys_git_pr_check_with_source(
            git, repository_path, base, head, style, merge_message,
            source, &check, error);
    if (result != MAELYS_GIT_OK) return failure(message, "failed", result, error->message, error);
    return pr_result(message, &check, 0, error);
}

static char *execute_pr_merge(maelys_git_policy_t *policy,
                              const char *git,
                              const char *root,
                              const mg_agent_message_t *message,
                              maelys_git_explain_mode_t denial_mode,
                              maelys_git_error_t *error) {
    const char *base_ref = required_string(message, "base_ref");
    const char *base = required_string(message, "base_oid");
    const char *head = required_string(message, "head_oid");
    maelys_git_merge_style_t style = required_style(message);
    int valid = 1;
    const char *expected_prepared_oid = optional_string(message, "expected_prepared_oid", &valid);
    const char *expected_policy_fingerprint = optional_string(message, "expected_policy_fingerprint", &valid);
    const char *expected_grants_fingerprint = optional_string(message, "expected_grants_fingerprint", &valid);
    const char *expected_target_identity = optional_string(message, "expected_target_identity", &valid);
    const char *pr_id = optional_string(message, "pr_id", &valid);
    const char *merge_message = optional_string(message, "message", &valid);
    int64_t approvals = 0, required = 0;
    int checks = 0, blocking = 0, apply = 0;
    if (!valid || !payload_has_only(message, pr_merge_members) || !base_ref || !base || !head || !style ||
        maelys_json_object_get_i64(message->document, message->payload, "approvals", &approvals) != MAELYS_JSON_OK ||
        approvals < 0 || (uint64_t)approvals > SIZE_MAX ||
        maelys_json_object_get_i64(message->document, message->payload, "required_approvals", &required) != MAELYS_JSON_OK ||
        required < 0 || (uint64_t)required > SIZE_MAX ||
        maelys_json_object_get_boolean(message->document, message->payload, "status_checks_passed", &checks) != MAELYS_JSON_OK ||
        maelys_json_object_get_boolean(message->document, message->payload, "blocking_review", &blocking) != MAELYS_JSON_OK ||
        maelys_json_object_get_boolean(message->document, message->payload, "apply", &apply) != MAELYS_JSON_OK ||
        (apply && (!expected_target_identity || !expected_prepared_oid || !expected_policy_fingerprint)))
        return failure(message, "failed", MAELYS_GIT_ERR_PROTOCOL, "invalid pr_merge payload", error);
    char repository_path[4096];
    maelys_git_result_t result = maelys_git_resolve_repository(
        root, message->repository, repository_path, sizeof(repository_path), error);
    if (result != MAELYS_GIT_OK) return failure(message, "failed", result, error->message, error);
    char source_path[4096];
    maelys_git_pr_source_t source_storage;
    const maelys_git_pr_source_t *source = NULL;
    result = pr_source_from_payload(message, root, source_path,
                                    &source_storage, &source, error);
    if (result != MAELYS_GIT_OK)
        return failure(message, "failed", result, error->message, error);
    if (source && apply && !source->expected_identity)
        return failure(message, "failed", MAELYS_GIT_ERR_PROTOCOL,
                       "cross-repository apply requires expected_source_identity", error);
    maelys_git_pr_gates_t gates = {
        .approvals = (size_t)approvals,
        .required_approvals = (size_t)required,
        .status_checks_passed = checks,
        .blocking_review = blocking,
    };
    maelys_git_pr_check_result_t merge;
    char text[EXPLANATION_CAPACITY];
    judged_t judged = {.text = denial_mode == MAELYS_GIT_EXPLAIN_NEVER ? NULL : text};
    mg_receive_receipt_t receipt = {.mode = denial_mode, .text = (char *)judged.text,
                                    .text_capacity = judged.text ? sizeof(text) : 0u};
    result = mg_pr_merge(
        git, repository_path, message->repository, base_ref, base, head, style,
        merge_message,
        message->principal, &gates, policy, pr_id, source,
        expected_target_identity, expected_prepared_oid,
        expected_policy_fingerprint, expected_grants_fingerprint, 1, apply, &merge, &judged.decision,
        &receipt, error);
    /* A policy denial is a decision with its receipt; the gates and the
     * mergeability refuse without one. */
    if (result == MAELYS_GIT_ERR_DENIED && receipt.decided) {
        judged.receipt = receipt.receipt;
        return decision_result(message, &judged, error);
    }
    if (result == MAELYS_GIT_ERR_DENIED)
        return failure(message, "denied", result, error->message, error);
    if (result != MAELYS_GIT_OK) return failure(message, "failed", result, error->message, error);
    return pr_result(message, &merge, apply, error);
}

maelys_git_result_t mg_executor_execute(maelys_git_policy_t *policy,
                                        const char *git_executable,
                                        const char *repository_root,
                                        const mg_agent_message_t *message,
                                        maelys_git_explain_mode_t denial_mode,
                                        char **out_result_json,
                                        maelys_git_error_t *error) {
    if (!policy || !git_executable || !repository_root || !message || !out_result_json ||
        !message->document ||
        maelys_json_value_type(message->document, message->payload) != MAELYS_JSON_TYPE_OBJECT)
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    *out_result_json = NULL;
    /* Every command counts, so that a pinned stream's first command, and it
     * alone, uses the reading verified at startup. */
    mg_policy_begin_command(policy);
    int64_t now = mg_now_ms();
    if (now > message->expires_at_ms || message->issued_at_ms > now + 300000) {
        *out_result_json = failure(message, "failed", MAELYS_GIT_ERR_DENIED,
                                   "command is expired or issued too far in the future", error);
    } else if (strcmp(message->command, "health") == 0) {
        if (!payload_has_only(message, health_members))
            *out_result_json = failure(message, "failed", MAELYS_GIT_ERR_PROTOCOL,
                                       "health payload must be empty", error);
        else {
            mg_json_t json;
            mg_protocol_result_begin(&json, message, "ok");
            mg_json_boolean(&json, "healthy", 1);
            mg_json_string(&json, "version", MAELYS_GIT_VERSION);
            *out_result_json = mg_protocol_result_end(&json, error);
        }
    } else if (mg_policy_refresh_grants(policy, error) != MAELYS_GIT_OK) {
        /* Each command decides on the grants read before it, or not at all:
         * this one and the next are refused until a reading succeeds. */
        maelys_git_result_t code = error->code;
        char reason[MAELYS_GIT_MAX_ERROR];
        (void)snprintf(reason, sizeof(reason), "grants snapshot unavailable: %.900s", error->message);
        *out_result_json = failure(message, "failed", code, reason, error);
    } else if (strcmp(message->command, "authorize") == 0) {
        *out_result_json = execute_authorize(policy, message, error);
    } else if (strcmp(message->command, "repository_info") == 0) {
        *out_result_json = execute_repository_info(policy, repository_root, message, error);
    } else if (strcmp(message->command, "diff") == 0) {
        *out_result_json = execute_diff(policy, git_executable, repository_root, message, error);
    } else if (strcmp(message->command, "update_ref") == 0) {
        *out_result_json = execute_update_ref(policy, git_executable, repository_root, message,
                                              denial_mode, error);
    } else if (strcmp(message->command, "create_repository") == 0) {
        *out_result_json = execute_create_repository(policy, git_executable, repository_root, message,
                                                     denial_mode, error);
    } else if (strcmp(message->command, "pr_check") == 0) {
        *out_result_json = execute_pr_check(policy, git_executable, repository_root, message, error);
    } else if (strcmp(message->command, "pr_merge") == 0) {
        *out_result_json = execute_pr_merge(policy, git_executable, repository_root, message,
                                            denial_mode, error);
    } else {
        *out_result_json = failure(message, "failed", MAELYS_GIT_ERR_INVALID_COMMAND,
                                   "unsupported command", error);
    }
    /* A result that does not fit the protocol line is never written: the
     * reader would refuse it and stop the stream. A short failure takes its
     * place, correlated with the command, and the stream goes on. */
    if (!*out_result_json && error && error->code == MAELYS_GIT_ERR_LIMIT)
        *out_result_json = failure(message, "failed", MAELYS_GIT_ERR_LIMIT, error->message, error);
    if (!*out_result_json) {
        if (!error || error->code == MAELYS_GIT_OK)
            mg_error_set(error, MAELYS_GIT_ERR_IO, 0, "could not encode executor result");
        return MAELYS_GIT_ERR_IO;
    }
    return MAELYS_GIT_OK;
}
