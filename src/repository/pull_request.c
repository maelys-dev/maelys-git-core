#include "internal.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef struct {
    char temporary_repository[PATH_MAX];
    maelys_git_pr_check_result_t result;
} prepared_pr_t;

static void trim_line(unsigned char *data, size_t *length) {
    while (*length && (data[*length - 1u] == '\n' || data[*length - 1u] == '\r'))
        data[--*length] = '\0';
}

static maelys_git_result_t capture_oid(const char *git,
                                       char *const argv[],
                                       char out[65],
                                       maelys_git_error_t *error) {
    unsigned char *data = NULL;
    size_t length = 0u;
    maelys_git_result_t result = mg_process_capture(git, argv, &data, &length, 256u, error);
    if (result != MAELYS_GIT_OK) return result;
    trim_line(data, &length);
    if (!mg_is_oid((char *)data)) {
        free(data);
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "Git did not return an object identifier");
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    memcpy(out, data, length + 1u);
    free(data);
    return MAELYS_GIT_OK;
}

static maelys_git_result_t parse_merge_tree(unsigned char *data,
                                            size_t length,
                                            maelys_git_pr_check_result_t *result,
                                            maelys_git_error_t *error) {
    size_t oid_length = 0u;
    while (oid_length < length && oid_length <= 64u && data[oid_length] != '\0')
        ++oid_length;
    if (oid_length >= length || oid_length > 64u || !mg_is_oid((char *)data)) {
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "invalid git merge-tree output");
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    memcpy(result->merge_tree_oid, data, oid_length + 1u);
    size_t count = 0u;
    for (size_t offset = oid_length + 1u; offset < length;) {
        size_t end = offset;
        while (end < length && data[end] != '\0') ++end;
        if (end == length || end == offset) {
            mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "invalid merge conflict path stream");
            return MAELYS_GIT_ERR_PROTOCOL;
        }
        if (count >= MAELYS_GIT_MAX_CONFLICT_PATHS) {
            mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0, "too many merge conflict paths");
            return MAELYS_GIT_ERR_LIMIT;
        }
        char **grown = realloc(result->conflict_paths.items, (count + 1u) * sizeof(*grown));
        if (!grown) return MAELYS_GIT_ERR_IO;
        result->conflict_paths.items = grown;
        grown[count] = malloc(end - offset + 1u);
        if (!grown[count]) return MAELYS_GIT_ERR_IO;
        memcpy(grown[count], data + offset, end - offset);
        grown[count][end - offset] = '\0';
        ++count;
        offset = end + 1u;
    }
    result->conflict_paths.count = count;
    return MAELYS_GIT_OK;
}

static void prepared_clear(prepared_pr_t *prepared) {
    maelys_git_pr_check_result_clear(&prepared->result);
    if (prepared->temporary_repository[0])
        (void)mg_remove_tree(prepared->temporary_repository);
    memset(prepared, 0, sizeof(*prepared));
}

static maelys_git_result_t prepare_pr(const char *git,
                                      const char *repository,
                                      const char *base_oid,
                                      const char *head_oid,
                                      maelys_git_merge_style_t style,
                                      const char *message,
                                      prepared_pr_t *prepared,
                                      maelys_git_error_t *error) {
    memset(prepared, 0, sizeof(*prepared));
    if (!git || !repository || !mg_is_oid(base_oid) || !mg_is_oid(head_oid) ||
        mg_is_zero_oid(base_oid) || mg_is_zero_oid(head_oid) ||
        style < MAELYS_GIT_MERGE_FAST_FORWARD || style > MAELYS_GIT_MERGE_SQUASH)
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    char template[] = "/tmp/maelys-git-pr-XXXXXX";
    int temporary_fd = mkstemp(template);
    if (temporary_fd < 0) return MAELYS_GIT_ERR_IO;
    close(temporary_fd);
    if (unlink(template) != 0 ||
        !mg_copy_string(prepared->temporary_repository,
                        sizeof(prepared->temporary_repository), template))
        return MAELYS_GIT_ERR_IO;
    char *clone_argv[] = {(char *)git, "clone", "--quiet", "--bare", "--shared",
                          (char *)repository, prepared->temporary_repository, NULL};
    maelys_git_result_t rc = mg_process_run(git, clone_argv, NULL, error);
    if (rc != MAELYS_GIT_OK) { prepared_clear(prepared); return rc; }
    char *base_argv[] = {(char *)git, "--git-dir", prepared->temporary_repository,
                         "merge-base", (char *)base_oid, (char *)head_oid, NULL};
    rc = capture_oid(git, base_argv, prepared->result.merge_base_oid, error);
    if (rc != MAELYS_GIT_OK) { prepared_clear(prepared); return rc; }

    int status = 0;
    char *empty_argv[] = {(char *)git, "--git-dir", prepared->temporary_repository,
                          "diff", "--quiet", prepared->result.merge_base_oid,
                          (char *)head_oid, "--", NULL};
    rc = mg_process_run_status(git, empty_argv, &status, error);
    if (rc != MAELYS_GIT_OK || (status != 0 && status != 1)) {
        if (rc == MAELYS_GIT_OK)
            mg_error_set(error, MAELYS_GIT_ERR_PROCESS, 0, "git diff failed with status %d", status);
        prepared_clear(prepared);
        return rc == MAELYS_GIT_OK ? MAELYS_GIT_ERR_PROCESS : rc;
    }
    prepared->result.empty = status == 0;
    rc = maelys_git_repository_visit_changes(
        git, repository, prepared->result.merge_base_oid, head_oid,
        NULL, NULL, &prepared->result.changes, error);
    if (rc != MAELYS_GIT_OK) { prepared_clear(prepared); return rc; }

    if (style == MAELYS_GIT_MERGE_FAST_FORWARD) {
        char *ancestor_argv[] = {(char *)git, "--git-dir", prepared->temporary_repository,
                                 "merge-base", "--is-ancestor", (char *)base_oid,
                                 (char *)head_oid, NULL};
        rc = mg_process_run_status(git, ancestor_argv, &status, error);
        if (rc != MAELYS_GIT_OK || (status != 0 && status != 1)) {
            prepared_clear(prepared);
            return rc == MAELYS_GIT_OK ? MAELYS_GIT_ERR_PROCESS : rc;
        }
        prepared->result.mergeable = status == 0;
        if (prepared->result.mergeable) {
            char treeish[72];
            (void)snprintf(treeish, sizeof(treeish), "%s^{tree}", head_oid);
            char *tree_argv[] = {(char *)git, "--git-dir", prepared->temporary_repository,
                                 "rev-parse", treeish, NULL};
            rc = capture_oid(git, tree_argv, prepared->result.merge_tree_oid, error);
            if (rc == MAELYS_GIT_OK)
                (void)mg_copy_string(prepared->result.prepared_oid,
                                     sizeof(prepared->result.prepared_oid), head_oid);
        }
        if (rc != MAELYS_GIT_OK) prepared_clear(prepared);
        return rc;
    }

    char *merge_tree_argv[] = {(char *)git, "--git-dir", prepared->temporary_repository,
                               "merge-tree", "--write-tree", "-z", "--name-only",
                               "--no-messages", (char *)base_oid, (char *)head_oid, NULL};
    unsigned char *merge_output = NULL;
    size_t merge_length = 0u;
    rc = mg_process_capture_status(git, merge_tree_argv, &merge_output, &merge_length,
                                   4u * 1024u * 1024u, &status, error);
    if (rc != MAELYS_GIT_OK || (status != 0 && status != 1)) {
        free(merge_output); prepared_clear(prepared);
        return rc == MAELYS_GIT_OK ? MAELYS_GIT_ERR_PROCESS : rc;
    }
    rc = parse_merge_tree(merge_output, merge_length, &prepared->result, error);
    free(merge_output);
    if (rc != MAELYS_GIT_OK) { prepared_clear(prepared); return rc; }
    prepared->result.mergeable = status == 0;
    if (!prepared->result.mergeable || prepared->result.empty) return MAELYS_GIT_OK;

    const char *commit_message = message && *message ? message :
        (style == MAELYS_GIT_MERGE_SQUASH ? "Squash merge" : "Merge pull request");
    char *merge_commit_argv[] = {
        (char *)git, "--git-dir", prepared->temporary_repository,
        "-c", "user.name=Maelys Forge", "-c", "user.email=forge@maelys.local",
        "commit-tree", prepared->result.merge_tree_oid, "-p", (char *)base_oid,
        "-p", (char *)head_oid, "-m", (char *)commit_message, NULL};
    char *squash_commit_argv[] = {
        (char *)git, "--git-dir", prepared->temporary_repository,
        "-c", "user.name=Maelys Forge", "-c", "user.email=forge@maelys.local",
        "commit-tree", prepared->result.merge_tree_oid, "-p", (char *)base_oid,
        "-m", (char *)commit_message, NULL};
    rc = capture_oid(git,
                     style == MAELYS_GIT_MERGE_SQUASH ? squash_commit_argv : merge_commit_argv,
                     prepared->result.prepared_oid, error);
    if (rc != MAELYS_GIT_OK) { prepared_clear(prepared); return rc; }
    char *ref_argv[] = {(char *)git, "--git-dir", prepared->temporary_repository,
                        "update-ref", "refs/maelys/prepared",
                        prepared->result.prepared_oid, NULL};
    rc = mg_process_run(git, ref_argv, NULL, error);
    if (rc != MAELYS_GIT_OK) prepared_clear(prepared);
    return rc;
}

void maelys_git_pr_check_result_clear(maelys_git_pr_check_result_t *result) {
    if (!result) return;
    maelys_git_path_list_clear(&result->conflict_paths);
    memset(result, 0, sizeof(*result));
}

maelys_git_result_t maelys_git_pr_check(
    const char *git_executable, const char *repository_path,
    const char *base_oid, const char *head_oid, maelys_git_merge_style_t style,
    const char *message, maelys_git_pr_check_result_t *out_result,
    maelys_git_error_t *error) {
    maelys_git_error_clear(error);
    if (!out_result) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    memset(out_result, 0, sizeof(*out_result));
    prepared_pr_t prepared;
    maelys_git_result_t result = prepare_pr(git_executable, repository_path, base_oid,
                                            head_oid, style, message, &prepared, error);
    if (result != MAELYS_GIT_OK) return result;
    *out_result = prepared.result;
    memset(&prepared.result, 0, sizeof(prepared.result));
    prepared_clear(&prepared);
    return MAELYS_GIT_OK;
}

typedef struct {
    maelys_git_policy_t *policy;
    const char *repository;
    const char *principal;
    const char *ref;
} pr_auth_context_t;

static maelys_git_result_t authorize_pr_request(pr_auth_context_t *context,
                                                const maelys_git_change_t *change,
                                                const maelys_git_change_summary_t *summary,
                                                maelys_git_error_t *error) {
    const char *path = change ? change->path : NULL;
    maelys_git_policy_request_t request = {
        .request_id = context->ref, .principal = context->principal,
        .repository = context->repository, .operation = "merge",
        .ref_name = context->ref, .ref_kind = "branch", .update_kind = "fast_forward",
        .change_kind = change ? maelys_git_change_kind_name(change->kind) : NULL,
        .paths = change ? &path : NULL, .path_count = change ? 1u : 0u,
        .has_summary = summary != NULL,
    };
    if (summary) {
        request.changed_count = summary->changed_count;
        request.added_count = summary->added_count;
        request.modified_count = summary->modified_count;
        request.deleted_count = summary->deleted_count;
        request.renamed_count = summary->renamed_count;
        request.max_new_blob_size = summary->max_new_blob_size;
        request.has_binary = summary->has_binary;
    }
    maelys_git_policy_decision_t decision;
    maelys_git_result_t result = maelys_git_policy_authorize(context->policy, &request,
                                                             &decision, error);
    if (result != MAELYS_GIT_OK) return result;
    if (decision.allowed) return MAELYS_GIT_OK;
    mg_error_set(error, MAELYS_GIT_ERR_DENIED, 0, "%s", decision.reason);
    return MAELYS_GIT_ERR_DENIED;
}

static maelys_git_result_t authorize_pr_change(const maelys_git_change_t *change,
                                               void *opaque,
                                               maelys_git_error_t *error) {
    return authorize_pr_request(opaque, change, NULL, error);
}

static maelys_git_result_t authorize_pr(const char *git, const char *repository_path,
                                        const char *base, const char *head,
                                        const maelys_git_change_summary_t *summary,
                                        pr_auth_context_t *context,
                                        maelys_git_error_t *error) {
    maelys_git_change_summary_t ignored;
    maelys_git_result_t result = authorize_pr_request(context, NULL, NULL, error);
    if (result == MAELYS_GIT_OK)
        result = maelys_git_repository_visit_changes(git, repository_path, base, head,
                                                      authorize_pr_change, context, &ignored, error);
    if (result == MAELYS_GIT_OK)
        result = authorize_pr_request(context, NULL, summary, error);
    return result;
}

maelys_git_result_t maelys_git_pr_merge(
    const char *git, const char *repository_path, const char *repository_name,
    const char *base_ref, const char *base_oid, const char *head_oid,
    maelys_git_merge_style_t style, const char *message, const char *principal,
    const maelys_git_pr_gates_t *gates, maelys_git_policy_t *policy, int apply,
    maelys_git_pr_check_result_t *out_result, maelys_git_error_t *error) {
    maelys_git_error_clear(error);
    if (!repository_name || !base_ref || !maelys_git_ref_name_is_valid(base_ref) ||
        maelys_git_classify_ref(base_ref) != MAELYS_GIT_REF_BRANCH ||
        !principal || !*principal || !gates || !policy || !out_result)
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    memset(out_result, 0, sizeof(*out_result));
    if (gates->blocking_review || !gates->status_checks_passed ||
        gates->approvals < gates->required_approvals) {
        mg_error_set(error, MAELYS_GIT_ERR_DENIED, 0, "pull request gates are not satisfied");
        return MAELYS_GIT_ERR_DENIED;
    }
    prepared_pr_t prepared;
    maelys_git_result_t result = prepare_pr(git, repository_path, base_oid, head_oid,
                                            style, message, &prepared, error);
    if (result != MAELYS_GIT_OK) return result;
    if (!prepared.result.mergeable || prepared.result.empty) {
        mg_error_set(error, MAELYS_GIT_ERR_DENIED, 0,
                     prepared.result.empty ? "pull request is empty" : "pull request is not mergeable");
        prepared_clear(&prepared);
        return MAELYS_GIT_ERR_DENIED;
    }
    pr_auth_context_t auth = {.policy = policy, .repository = repository_name,
                              .principal = principal, .ref = base_ref};
    result = authorize_pr(git, repository_path, prepared.result.merge_base_oid, head_oid,
                          &prepared.result.changes, &auth, error);
    if (result != MAELYS_GIT_OK) { prepared_clear(&prepared); return result; }
    char *current_argv[] = {(char *)git, "--git-dir", (char *)repository_path,
                            "rev-parse", "--verify", (char *)base_ref, NULL};
    char current[65];
    result = capture_oid(git, current_argv, current, error);
    if (result != MAELYS_GIT_OK || strcmp(current, base_oid) != 0) {
        if (result == MAELYS_GIT_OK)
            mg_error_set(error, MAELYS_GIT_ERR_PROCESS, 0, "base reference changed; refresh the pull request");
        prepared_clear(&prepared);
        return result == MAELYS_GIT_OK ? MAELYS_GIT_ERR_PROCESS : result;
    }
    if (apply) {
        /* Authorization is deliberately repeated immediately before the state change. */
        result = authorize_pr(git, repository_path, prepared.result.merge_base_oid, head_oid,
                              &prepared.result.changes, &auth, error);
        if (result == MAELYS_GIT_OK && style != MAELYS_GIT_MERGE_FAST_FORWARD) {
            char *fetch_argv[] = {(char *)git, "--git-dir", (char *)repository_path,
                                  "fetch", "--quiet", "--no-tags",
                                  prepared.temporary_repository,
                                  "refs/maelys/prepared", NULL};
            result = mg_process_run(git, fetch_argv, NULL, error);
        }
        if (result == MAELYS_GIT_OK)
            result = maelys_git_repository_update_ref(git, repository_path, base_ref,
                                                       prepared.result.prepared_oid,
                                                       base_oid, error);
    }
    if (result == MAELYS_GIT_OK) {
        *out_result = prepared.result;
        memset(&prepared.result, 0, sizeof(prepared.result));
    }
    prepared_clear(&prepared);
    return result;
}
