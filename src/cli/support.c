#include "cli/support.h"

#include <stdio.h>
#include <string.h>

const char *maelys_git_cli_git(const maelys_cli_context_t *context) {
    return maelys_cli_option_or(context, "git", MAELYS_GIT_CLI_DEFAULT_GIT);
}

typedef struct {
    const char *code;
    const char *hint;
} failure_mapping_t;

static failure_mapping_t map_result(maelys_git_result_t result) {
    static const char *const default_hint =
        "Inspect the diagnostic and retry only after correcting its cause.";
    static const char *const validation_hint =
        "Correct the stated input, then retry the same command.";
    failure_mapping_t mapping = {MAELYS_CLI_CODE_UNEXPECTED, default_hint};
    switch (result) {
        case MAELYS_GIT_ERR_INVALID_ARGUMENT:
        case MAELYS_GIT_ERR_INVALID_COMMAND:
        case MAELYS_GIT_ERR_INVALID_REPOSITORY:
        case MAELYS_GIT_ERR_LIMIT:
            mapping.code = MAELYS_CLI_CODE_VALIDATION_FAILED;
            mapping.hint = validation_hint;
            break;
        case MAELYS_GIT_ERR_POLICY:
            mapping.code = MAELYS_CLI_CODE_POLICY_FAILED;
            mapping.hint = "Validate the current policy manifest before retrying.";
            break;
        case MAELYS_GIT_ERR_DENIED:
            mapping.code = MAELYS_CLI_CODE_ACCESS_DENIED;
            mapping.hint = "Inspect the matching policy decision; do not bypass the denial.";
            break;
        case MAELYS_GIT_ERR_IO: mapping.code = MAELYS_CLI_CODE_IO_FAILED; break;
        case MAELYS_GIT_ERR_PROCESS: mapping.code = MAELYS_CLI_CODE_PROCESS_FAILED; break;
        case MAELYS_GIT_ERR_PROTOCOL: mapping.code = MAELYS_CLI_CODE_PROTOCOL_FAILED; break;
        case MAELYS_GIT_ERR_NOT_FOUND: mapping.code = MAELYS_CLI_CODE_NOT_FOUND; break;
        case MAELYS_GIT_OK: break;
    }
    return mapping;
}

int maelys_git_cli_fail_result(
    maelys_cli_context_t *context,
    maelys_git_result_t result,
    const maelys_git_error_t *error) {
    failure_mapping_t mapping = map_result(result);
    return maelys_cli_fail(context, mapping.code, mapping.hint, "%s",
        error && error->message[0] ? error->message : maelys_git_result_name(result));
}

int maelys_git_cli_stream_error(
    maelys_cli_context_t *context,
    const char *operation,
    maelys_git_result_t result,
    const maelys_git_error_t *error) {
    FILE *err = context && context->err ? context->err : stderr;
    const char *program = context && context->app ? context->app->program : "maelys-git";
    (void)fprintf(err, "%s %s error [%s]: %s\n", program, operation,
        maelys_git_result_name(result),
        error && error->message[0] ? error->message : "operation failed");
    (void)fflush(err);
    return MAELYS_CLI_EXIT_FAILURE;
}

int maelys_git_cli_open_policy(
    maelys_cli_context_t *context,
    const char *manifest_path,
    maelys_git_policy_t **out_policy) {
    maelys_git_error_t error = {0};
    maelys_git_result_t result = maelys_git_policy_open(manifest_path, out_policy, &error);
    return result == MAELYS_GIT_OK ? 0 : maelys_git_cli_fail_result(context, result, &error);
}

int maelys_git_cli_resolve_repository(
    maelys_cli_context_t *context,
    const char *repository_root,
    const char *repository_name,
    char *out_path,
    size_t out_capacity) {
    maelys_git_error_t error = {0};
    maelys_git_result_t result = maelys_git_resolve_repository(
        repository_root, repository_name, out_path, out_capacity, &error);
    return result == MAELYS_GIT_OK ? 0 : maelys_git_cli_fail_result(context, result, &error);
}
