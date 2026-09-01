#include "internal.h"

#include <stdio.h>
#include <string.h>

maelys_git_result_t maelys_git_pre_receive(maelys_git_policy_t *policy,
                                            const char *git_executable,
                                            const char *repository_path,
                                            const char *repository_name,
                                            const char *principal,
                                            FILE *input,
                                            FILE *diagnostics,
                                            maelys_git_error_t *error) {
    if (!policy || !git_executable || !repository_path || !repository_name ||
        !principal || !input || !diagnostics) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    char line[MAELYS_GIT_MAX_REF + 160u];
    size_t update_count = 0u;
    while (fgets(line, sizeof(line), input)) {
        size_t length = strlen(line);
        if (length == 0u || line[length - 1u] != '\n') {
            mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "pre-receive input line is too long or incomplete");
            return MAELYS_GIT_ERR_PROTOCOL;
        }
        line[length - 1u] = '\0';
        char old_oid[65];
        char new_oid[65];
        char ref_name[MAELYS_GIT_MAX_REF];
        char extra;
        int matched = sscanf(line, "%64s %64s %511s %c", old_oid, new_oid, ref_name, &extra);
        if (matched != 3 || !mg_is_oid(old_oid) || !mg_is_oid(new_oid) ||
            !maelys_git_ref_name_is_valid(ref_name)) {
            mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "invalid pre-receive update");
            return MAELYS_GIT_ERR_PROTOCOL;
        }

        maelys_git_path_list_t paths;
        maelys_git_result_t result = maelys_git_repository_changed_paths(
            git_executable, repository_path, old_oid, new_oid, &paths, error);
        if (result != MAELYS_GIT_OK) return result;
        maelys_git_policy_request_t request = {
            .request_id = ref_name,
            .principal = principal,
            .repository = repository_name,
            .operation = "push",
            .ref_name = ref_name,
            .paths = (const char *const *)paths.items,
            .path_count = paths.count,
        };
        maelys_git_policy_decision_t decision;
        result = maelys_git_policy_authorize(policy, &request, &decision, error);
        maelys_git_path_list_clear(&paths);
        if (result != MAELYS_GIT_OK) return result;
        if (!decision.allowed) {
            (void)fprintf(diagnostics,
                          "maelys-git: push to %s denied: %s\n",
                          ref_name,
                          decision.reason);
            mg_error_set(error, MAELYS_GIT_ERR_DENIED, 0, "%s", decision.reason);
            return MAELYS_GIT_ERR_DENIED;
        }
        ++update_count;
    }
    if (ferror(input)) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, 0, "failed to read pre-receive input");
        return MAELYS_GIT_ERR_IO;
    }
    if (update_count == 0u) {
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "pre-receive input contains no update");
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    return MAELYS_GIT_OK;
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
