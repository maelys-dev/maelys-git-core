#include "internal.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    maelys_git_policy_t *policy;
    const char *repository_name;
    const char *principal;
    maelys_git_receive_update_t *update;
    const maelys_git_inspector_t *inspectors;
    size_t inspector_count;
    const maelys_git_inspection_limits_t *limits;
    size_t *transaction_commit_count;
    size_t *transaction_merge_commit_count;
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
    const char *paths[2] = {change->path, change->old_path};
    maelys_git_policy_request_t request = update_request(context);
    request.paths = paths;
    request.path_count = change->old_path[0] ? 2u : 1u;
    request.change_kind = maelys_git_change_kind_name(change->kind);
    request.old_path = change->old_path[0] ? change->old_path : NULL;
    request.has_change_details = 1;
    request.change_blob_size = change->new_blob_size;
    request.old_mode = change->old_mode;
    request.new_mode = change->new_mode;
    request.change_binary = change->binary;
    request.change_symlink = change->symlink;
    request.change_submodule = change->submodule;
    request.change_lfs_pointer = change->lfs_pointer;
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
    maelys_git_result_t result = mg_process_spool_status(
        git, mg_is_zero_oid(context->update->old_oid) ? create_argv : update_argv,
        commits, 64u * 1024u * 1024u, &status, error);
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
        char *signature_argv[] = {
            (char *)git, "--git-dir", (char *)repository_path,
            "show", "-s", "--format=%ae%x00%G?%x00%GF%x00%GS%x00%P", oid, NULL};
        unsigned char *signature_data = NULL;
        size_t signature_length = 0u;
        result = mg_process_capture(git, signature_argv, &signature_data,
                                    &signature_length, 4096u, error);
        if (result != MAELYS_GIT_OK) break;
        while (signature_length && (signature_data[signature_length - 1u] == '\n' ||
                                    signature_data[signature_length - 1u] == '\r'))
            signature_data[--signature_length] = '\0';
        unsigned char *fields[5] = {signature_data, NULL, NULL, NULL, NULL};
        size_t field = 1u;
        for (size_t j = 0u; j < signature_length && field < 5u; ++j)
            if (signature_data[j] == '\0') fields[field++] = signature_data + j + 1u;
        if (field != 5u || !fields[0][0] || !fields[1][0] || fields[1][1] != '\0') {
            free(signature_data); result = MAELYS_GIT_ERR_PROTOCOL; break;
        }
        if (*context->transaction_commit_count >= context->limits->max_commits) {
            free(signature_data);
            mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0,
                         "commit count exceeds configured limit %zu",
                         context->limits->max_commits);
            result = MAELYS_GIT_ERR_LIMIT;
            break;
        }
        ++*context->transaction_commit_count;
        ++context->update->commit_count;
        size_t parent_count = fields[4][0] ? 1u : 0u;
        for (const unsigned char *parent = fields[4]; *parent; ++parent)
            if (*parent == ' ') ++parent_count;
        if (parent_count > 1u) {
            ++*context->transaction_merge_commit_count;
            ++context->update->merge_commit_count;
        }
        const char *signature_status =
            fields[1][0] == 'G' ? "good" :
            fields[1][0] == 'U' ? "good_untrusted" :
            fields[1][0] == 'B' ? "bad" :
            fields[1][0] == 'X' ? "expired" :
            fields[1][0] == 'Y' ? "expired_key" :
            fields[1][0] == 'R' ? "revoked_key" :
            fields[1][0] == 'E' ? "verification_error" :
            fields[1][0] == 'N' ? "unsigned" : "unknown";
        maelys_git_policy_request_t request = update_request(context);
        request.request_id = oid;
        request.commit_email = (char *)fields[0];
        request.has_commit_signed = 1;
        request.commit_signed = fields[1][0] == 'G' || fields[1][0] == 'U';
        request.commit_signature_status = signature_status;
        request.commit_signer_fingerprint = fields[2][0] ? (char *)fields[2] : NULL;
        request.commit_signer_identity = fields[3][0] ? (char *)fields[3] : NULL;
        request.has_commit_signature_trusted = 1;
        request.commit_signature_trusted = fields[1][0] == 'G';
        result = authorize_request(context->policy, &request, context->diagnostics, error);
        free(signature_data);
        if (result != MAELYS_GIT_OK) break;
    }
    if (ferror(commits) && result == MAELYS_GIT_OK) result = MAELYS_GIT_ERR_IO;
    fclose(commits);
    if (result == MAELYS_GIT_ERR_PROTOCOL)
        mg_error_set(error, result, 0, "invalid commit inspection stream");
    return result;
}

maelys_git_result_t maelys_git_pre_receive_with_limits(
    maelys_git_policy_t *policy,
    const char *git_executable,
    const char *repository_path,
    const char *repository_name,
    const char *principal,
    const maelys_git_inspection_limits_t *limits,
    const maelys_git_inspector_t *inspectors,
    size_t inspector_count,
    FILE *input,
    FILE *diagnostics,
    maelys_git_error_t *error) {
    if (!policy || !git_executable || !repository_path || !repository_name ||
        !principal || !limits || !input || !diagnostics ||
        limits->max_commits == 0u || limits->max_changes == 0u ||
        limits->max_total_new_blob_size == 0u ||
        limits->max_inspected_blob_bytes == 0u)
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    maelys_git_receive_transaction_t transaction;
    maelys_git_result_t result = maelys_git_receive_transaction_read(input, &transaction, error);
    if (result != MAELYS_GIT_OK) return result;
    size_t transaction_commit_count = 0u;
    size_t transaction_merge_commit_count = 0u;
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
            .limits = limits,
            .transaction_commit_count = &transaction_commit_count,
            .transaction_merge_commit_count = &transaction_merge_commit_count,
            .diagnostics = diagnostics,
        };
        result = maelys_git_run_inspectors(inspectors, inspector_count, update, NULL, error);
        if (result != MAELYS_GIT_OK) break;
        maelys_git_policy_request_t request = update_request(&context);
        result = authorize_request(policy, &request, diagnostics, error);
        if (result != MAELYS_GIT_OK) break;
        result = authorize_commits(git_executable, repository_path, &context, error);
        if (result != MAELYS_GIT_OK) break;
        if (transaction.changes.changed_count >= limits->max_changes ||
            transaction.changes.total_new_blob_size >= limits->max_total_new_blob_size ||
            transaction.changes.inspected_blob_bytes >= limits->max_inspected_blob_bytes) {
            mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0,
                         "receive transaction exhausted its inspection quota");
            result = MAELYS_GIT_ERR_LIMIT;
            break;
        }
        maelys_git_inspection_limits_t remaining = *limits;
        remaining.max_changes -= transaction.changes.changed_count;
        remaining.max_total_new_blob_size -= transaction.changes.total_new_blob_size;
        remaining.max_inspected_blob_bytes -= transaction.changes.inspected_blob_bytes;
        result = maelys_git_repository_visit_changes_ex(
            git_executable, repository_path, update->old_oid, update->new_oid,
            &remaining, authorize_change, &context, &update->changes, error);
        if (result != MAELYS_GIT_OK) break;
        request = update_request(&context);
        request.has_summary = 1;
        request.changed_count = update->changes.changed_count;
        request.added_count = update->changes.added_count;
        request.modified_count = update->changes.modified_count;
        request.deleted_count = update->changes.deleted_count;
        request.renamed_count = update->changes.renamed_count;
        request.max_new_blob_size = update->changes.max_new_blob_size;
        request.total_new_blob_size = update->changes.total_new_blob_size;
        request.commit_count = update->commit_count;
        request.merge_commit_count = update->merge_commit_count;
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
        if (update->changes.total_new_blob_size > ULLONG_MAX -
                transaction.changes.total_new_blob_size) {
            result = MAELYS_GIT_ERR_LIMIT;
            mg_error_set(error, result, 0, "transaction blob byte count overflow");
            break;
        }
        transaction.changes.total_new_blob_size += update->changes.total_new_blob_size;
        transaction.changes.inspected_blob_bytes += update->changes.inspected_blob_bytes;
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
            .total_new_blob_size = transaction.changes.total_new_blob_size,
            .commit_count = transaction_commit_count,
            .merge_commit_count = transaction_merge_commit_count,
            .has_binary = transaction.changes.has_binary,
        };
        result = authorize_request(policy, &summary_request, diagnostics, error);
    }
    maelys_git_receive_transaction_clear(&transaction);
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
    maelys_git_inspection_limits_t limits;
    maelys_git_inspection_limits_default(&limits);
    return maelys_git_pre_receive_with_limits(
        policy, git_executable, repository_path, repository_name, principal,
        &limits, inspectors, inspector_count, input, diagnostics, error);
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
