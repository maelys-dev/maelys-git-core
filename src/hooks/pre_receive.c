#include "internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    maelys_git_policy_t *policy;
    const char *repository_name;
    const char *principal;
    const maelys_git_receive_update_t *update;
    const maelys_git_inspector_t *inspectors;
    size_t inspector_count;
    FILE *diagnostics;
} authorize_changes_context_t;

static maelys_git_result_t authorize_request(maelys_git_policy_t *policy,
                                             const maelys_git_policy_request_t *request,
                                             FILE *diagnostics,
                                             maelys_git_error_t *error) {
    maelys_git_policy_decision_t decision;
    maelys_git_result_t result = maelys_git_policy_authorize(policy, request, &decision, error);
    if (result != MAELYS_GIT_OK) return result;
    if (decision.allowed) return MAELYS_GIT_OK;
    (void)fprintf(diagnostics, "maelys-git: %s to %s denied: %s\n",
                  request->operation, request->ref_name ? request->ref_name : "(no ref)",
                  decision.reason);
    mg_error_set(error, MAELYS_GIT_ERR_DENIED, 0, "%s", decision.reason);
    return MAELYS_GIT_ERR_DENIED;
}

static maelys_git_policy_request_t update_request(const authorize_changes_context_t *context) {
    maelys_git_policy_request_t request;
    memset(&request, 0, sizeof(request));
    request.request_id = context->update->ref_name;
    request.principal = context->principal;
    request.repository = context->repository_name;
    request.operation = "push";
    request.ref_name = context->update->ref_name;
    request.ref_kind = maelys_git_ref_kind_name(context->update->ref_kind);
    request.update_kind = maelys_git_update_kind_name(context->update->update_kind);
    return request;
}

static maelys_git_result_t authorize_change(const maelys_git_change_t *change,
                                            void *opaque,
                                            maelys_git_error_t *error) {
    authorize_changes_context_t *context = opaque;
    maelys_git_result_t inspected = maelys_git_run_inspectors(
        context->inspectors, context->inspector_count, context->update, change, error);
    if (inspected != MAELYS_GIT_OK) return inspected;
    const char *path = change->path;
    maelys_git_policy_request_t request = update_request(context);
    request.paths = &path;
    request.path_count = 1u;
    request.change_kind = maelys_git_change_kind_name(change->kind);
    request.max_new_blob_size = change->new_blob_size;
    return authorize_request(context->policy, &request, context->diagnostics, error);
}

static maelys_git_result_t authorize_commits(const char *git,
                                             const char *repository_path,
                                             authorize_changes_context_t *context,
                                             maelys_git_error_t *error) {
    if (mg_is_zero_oid(context->update->new_oid)) return MAELYS_GIT_OK;
    FILE *commits = tmpfile();
    if (!commits) return MAELYS_GIT_ERR_IO;
    char excluded[70];
    char *create_argv[] = {(char *)git, "--git-dir", (char *)repository_path,
                           "rev-list", (char *)context->update->new_oid, "--not", "--all", NULL};
    (void)snprintf(excluded, sizeof(excluded), "^%s", context->update->old_oid);
    char *update_argv[] = {(char *)git, "--git-dir", (char *)repository_path,
                           "rev-list", (char *)context->update->new_oid, excluded, NULL};
    int status = 0;
    maelys_git_result_t result = mg_process_to_file(
        git, mg_is_zero_oid(context->update->old_oid) ? create_argv : update_argv,
        commits, &status, error);
    if (result != MAELYS_GIT_OK || status != 0) {
        fclose(commits);
        return result == MAELYS_GIT_OK ? MAELYS_GIT_ERR_PROCESS : result;
    }
    rewind(commits);
    char oid[70];
    while (fgets(oid, sizeof(oid), commits)) {
        size_t oid_length = strlen(oid);
        while (oid_length && (oid[oid_length - 1u] == '\n' || oid[oid_length - 1u] == '\r'))
            oid[--oid_length] = '\0';
        if (!mg_is_oid(oid)) { result = MAELYS_GIT_ERR_PROTOCOL; break; }
        char *email_argv[] = {(char *)git, "--git-dir", (char *)repository_path,
                              "show", "-s", "--format=%ae", oid, NULL};
        unsigned char *email_data = NULL;
        size_t email_length = 0u;
        result = mg_process_capture(git, email_argv, &email_data, &email_length, 1024u, error);
        if (result != MAELYS_GIT_OK) break;
        while (email_length && (email_data[email_length - 1u] == '\n' ||
                                email_data[email_length - 1u] == '\r'))
            email_data[--email_length] = '\0';
        if (!email_length || memchr(email_data, '\n', email_length)) {
            free(email_data); result = MAELYS_GIT_ERR_PROTOCOL; break;
        }
        char *verify_argv[] = {(char *)git, "--git-dir", (char *)repository_path,
                               "verify-commit", "--raw", oid, NULL};
        int verify_status = 0;
        result = mg_process_run_status(git, verify_argv, &verify_status, error);
        if (result != MAELYS_GIT_OK) { free(email_data); break; }
        maelys_git_policy_request_t request = update_request(context);
        request.request_id = oid;
        request.commit_email = (char *)email_data;
        request.has_commit_signed = 1;
        request.commit_signed = verify_status == 0;
        result = authorize_request(context->policy, &request, context->diagnostics, error);
        free(email_data);
        if (result != MAELYS_GIT_OK) break;
    }
    if (ferror(commits) && result == MAELYS_GIT_OK) result = MAELYS_GIT_ERR_IO;
    fclose(commits);
    if (result == MAELYS_GIT_ERR_PROTOCOL)
        mg_error_set(error, result, 0, "invalid commit inspection stream");
    return result;
}

maelys_git_result_t maelys_git_pre_receive_ex(maelys_git_policy_t *policy,
                                               const char *git_executable,
                                               const char *repository_path,
                                               const char *repository_name,
                                               const char *principal,
                                               const maelys_git_inspector_t *inspectors,
                                               size_t inspector_count,
                                               FILE *input,
                                               FILE *diagnostics,
                                               maelys_git_error_t *error) {
    if (!policy || !git_executable || !repository_path || !repository_name ||
        !principal || !input || !diagnostics) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    maelys_git_receive_transaction_t transaction;
    maelys_git_result_t result = maelys_git_receive_transaction_read(input, &transaction, error);
    if (result != MAELYS_GIT_OK) return result;
    for (size_t i = 0u; i < transaction.update_count; ++i) {
        maelys_git_receive_update_t *update = &transaction.updates[i];
        result = maelys_git_repository_classify_update(
            git_executable, repository_path, update->old_oid, update->new_oid,
            &update->update_kind, error);
        if (result != MAELYS_GIT_OK) break;
        authorize_changes_context_t context = {
            .policy = policy,
            .repository_name = repository_name,
            .principal = principal,
            .update = update,
            .inspectors = inspectors,
            .inspector_count = inspector_count,
            .diagnostics = diagnostics,
        };
        result = maelys_git_run_inspectors(inspectors, inspector_count, update, NULL, error);
        if (result != MAELYS_GIT_OK) break;
        maelys_git_policy_request_t request = update_request(&context);
        result = authorize_request(policy, &request, diagnostics, error);
        if (result != MAELYS_GIT_OK) break;
        result = authorize_commits(git_executable, repository_path, &context, error);
        if (result != MAELYS_GIT_OK) break;
        result = maelys_git_repository_visit_changes(
            git_executable, repository_path, update->old_oid, update->new_oid,
            authorize_change, &context, &update->changes, error);
        if (result != MAELYS_GIT_OK) break;
        request = update_request(&context);
        request.has_summary = 1;
        request.changed_count = update->changes.changed_count;
        request.added_count = update->changes.added_count;
        request.modified_count = update->changes.modified_count;
        request.deleted_count = update->changes.deleted_count;
        request.renamed_count = update->changes.renamed_count;
        request.max_new_blob_size = update->changes.max_new_blob_size;
        request.has_binary = update->changes.has_binary;
        result = authorize_request(policy, &request, diagnostics, error);
        if (result != MAELYS_GIT_OK) break;
        transaction.changes.changed_count += update->changes.changed_count;
        transaction.changes.added_count += update->changes.added_count;
        transaction.changes.modified_count += update->changes.modified_count;
        transaction.changes.deleted_count += update->changes.deleted_count;
        transaction.changes.renamed_count += update->changes.renamed_count;
        if (update->changes.max_new_blob_size > transaction.changes.max_new_blob_size)
            transaction.changes.max_new_blob_size = update->changes.max_new_blob_size;
        transaction.changes.has_binary |= update->changes.has_binary;
    }
    if (result == MAELYS_GIT_OK) {
        maelys_git_policy_request_t summary_request = {
            .request_id = "receive-transaction",
            .principal = principal,
            .repository = repository_name,
            .operation = "push",
            .has_summary = 1,
            .changed_count = transaction.changes.changed_count,
            .added_count = transaction.changes.added_count,
            .modified_count = transaction.changes.modified_count,
            .deleted_count = transaction.changes.deleted_count,
            .renamed_count = transaction.changes.renamed_count,
            .max_new_blob_size = transaction.changes.max_new_blob_size,
            .has_binary = transaction.changes.has_binary,
        };
        result = authorize_request(policy, &summary_request, diagnostics, error);
    }
    maelys_git_receive_transaction_clear(&transaction);
    return result;
}

maelys_git_result_t maelys_git_pre_receive(maelys_git_policy_t *policy,
                                            const char *git_executable,
                                            const char *repository_path,
                                            const char *repository_name,
                                            const char *principal,
                                            FILE *input,
                                            FILE *diagnostics,
                                            maelys_git_error_t *error) {
    return maelys_git_pre_receive_ex(policy, git_executable, repository_path,
                                     repository_name, principal, NULL, 0u,
                                     input, diagnostics, error);
}

maelys_git_result_t maelys_git_post_receive(const char *repository_name,
                                             const char *principal,
                                             FILE *input,
                                             FILE *events,
                                             maelys_git_error_t *error) {
    if (!repository_name || !principal || !input || !events) {
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    }
    char line[MAELYS_GIT_MAX_REF + 160u];
    while (fgets(line, sizeof(line), input)) {
        size_t length = strlen(line);
        if (length == 0u || line[length - 1u] != '\n') {
            mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "post-receive input line is incomplete");
            return MAELYS_GIT_ERR_PROTOCOL;
        }
        line[length - 1u] = '\0';
        char old_oid[65];
        char new_oid[65];
        char ref_name[MAELYS_GIT_MAX_REF];
        char extra;
        if (sscanf(line, "%64s %64s %511s %c", old_oid, new_oid, ref_name, &extra) != 3 ||
            !mg_is_oid(old_oid) || !mg_is_oid(new_oid) || !maelys_git_ref_name_is_valid(ref_name)) {
            mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "invalid post-receive update");
            return MAELYS_GIT_ERR_PROTOCOL;
        }
        if (fputs("{\"version\":\"1\",\"type\":\"ref_updated\",\"principal\":", events) == EOF ||
            !mg_json_write_string(events, principal) || fputs(",\"repository\":", events) == EOF ||
            !mg_json_write_string(events, repository_name) || fputs(",\"ref\":", events) == EOF ||
            !mg_json_write_string(events, ref_name) || fputs(",\"old_oid\":", events) == EOF ||
            !mg_json_write_string(events, old_oid) || fputs(",\"new_oid\":", events) == EOF ||
            !mg_json_write_string(events, new_oid) || fputs("}\n", events) == EOF) {
            mg_error_set(error, MAELYS_GIT_ERR_IO, 0, "failed to write post-receive event");
            return MAELYS_GIT_ERR_IO;
        }
    }
    if (ferror(input) || fflush(events) != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, 0, "post-receive event stream failed");
        return MAELYS_GIT_ERR_IO;
    }
    return MAELYS_GIT_OK;
}
