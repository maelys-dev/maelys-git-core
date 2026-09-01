#include "maelys_git_cli.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int emit_version(const maelys_cli_invocation_t *invocation) {
    json_t *data = json_pack("{s:s,s:s,s:s}", "product", "Maelys Git Hook",
                             "version", MAELYS_GIT_VERSION, "contract", MAELYS_CLI_CONTRACT);
    int result = maelys_cli_emit_success(invocation, data, "maelys-git-hook " MAELYS_GIT_VERSION, 0);
    json_decref(data);
    return result;
}

static const char *principal(const maelys_cli_invocation_t *invocation) {
    const char *user = maelys_cli_option(invocation, "user");
    return user ? user : getenv("MAELYS_GIT_PRINCIPAL");
}

static int stream_error(const char *operation,
                        maelys_git_result_t result,
                        const maelys_git_error_t *error) {
    (void)fprintf(stderr, "maelys-git-hook %s error [%s]: %s\n", operation,
                  maelys_git_result_name(result),
                  error && error->message[0] ? error->message : "operation failed");
    return 1;
}

static int parse_limit(const maelys_cli_invocation_t *invocation,
                       const char *name,
                       unsigned long long *out_value) {
    const char *value = maelys_cli_option(invocation, name);
    if (!value) return 1;
    if (!*value || *value == '-') return 0;
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(value, &end, 10);
    if (errno || end == value || *end || parsed == 0u) return 0;
    *out_value = parsed;
    return 1;
}

static int pre_receive(const maelys_cli_invocation_t *invocation) {
    const char *user = principal(invocation);
    if (!user || !*user) {
        maelys_git_error_t error = {.code = MAELYS_GIT_ERR_INVALID_ARGUMENT};
        (void)snprintf(error.message, sizeof(error.message),
                       "principal is missing; pass --user or MAELYS_GIT_PRINCIPAL");
        return stream_error("pre-receive", error.code, &error);
    }
    const char *git = maelys_cli_option(invocation, "git");
    const char *git_dir = maelys_cli_option(invocation, "git-dir");
    if (!git) git = "/usr/bin/git";
    if (!git_dir) { git_dir = getenv("GIT_DIR"); if (!git_dir || !*git_dir) git_dir = "."; }
    maelys_git_error_t error = {0};
    maelys_git_inspection_limits_t limits;
    maelys_git_inspection_limits_default(&limits);
    unsigned long long max_commits = limits.max_commits;
    unsigned long long max_changes = limits.max_changes;
    unsigned long long max_total = limits.max_total_new_blob_size;
    unsigned long long max_inspected = limits.max_inspected_blob_bytes;
    if (!parse_limit(invocation, "max-commits", &max_commits) ||
        !parse_limit(invocation, "max-changes", &max_changes) ||
        !parse_limit(invocation, "max-total-blob-bytes", &max_total) ||
        !parse_limit(invocation, "max-inspected-blob-bytes", &max_inspected) ||
        max_commits > SIZE_MAX || max_changes > SIZE_MAX || max_inspected > SIZE_MAX) {
        error.code = MAELYS_GIT_ERR_INVALID_ARGUMENT;
        (void)snprintf(error.message, sizeof(error.message),
                       "inspection limits must be positive host-sized integers");
        return stream_error("pre-receive", error.code, &error);
    }
    limits.max_commits = (size_t)max_commits;
    limits.max_changes = (size_t)max_changes;
    limits.max_total_new_blob_size = max_total;
    limits.max_inspected_blob_bytes = (size_t)max_inspected;
    maelys_git_policy_t *policy = NULL;
    maelys_git_result_t result = maelys_git_policy_open(
        maelys_cli_option(invocation, "manifest"), &policy, &error);
    if (result == MAELYS_GIT_OK)
        result = maelys_git_pre_receive_with_limits(
            policy, git, git_dir, maelys_cli_option(invocation, "repository"), user,
            &limits, NULL, 0u, stdin, stderr, &error);
    maelys_git_policy_close(policy);
    return result == MAELYS_GIT_OK ? 0 : stream_error("pre-receive", result, &error);
}

static int post_receive(const maelys_cli_invocation_t *invocation) {
    const char *user = principal(invocation);
    if (!user || !*user) {
        maelys_git_error_t error = {.code = MAELYS_GIT_ERR_INVALID_ARGUMENT};
        (void)snprintf(error.message, sizeof(error.message),
                       "principal is missing; pass --user or MAELYS_GIT_PRINCIPAL");
        return stream_error("post-receive", error.code, &error);
    }
    const char *events_path = maelys_cli_option(invocation, "events");
    FILE *events = events_path ? fopen(events_path, "a") : stdout;
    if (!events) {
        maelys_git_error_t error = {.code = MAELYS_GIT_ERR_IO, .system_error = errno};
        (void)snprintf(error.message, sizeof(error.message), "cannot open event output: %s", strerror(errno));
        return stream_error("post-receive", error.code, &error);
    }
    maelys_git_error_t error = {0};
    maelys_git_result_t result = maelys_git_post_receive(
        maelys_cli_option(invocation, "repository"), user, stdin, events, &error);
    if (events_path) (void)fclose(events);
    return result == MAELYS_GIT_OK ? 0 : stream_error("post-receive", result, &error);
}

int main(int argc, char **argv) {
    maelys_cli_invocation_t invocation;
    maelys_cli_error_t parse_error;
    if (!maelys_cli_parse("maelys-git-hook", argc - 1, argv + 1, &invocation, &parse_error))
        return maelys_cli_emit_error(&invocation, &parse_error, 1);
    if (!strcmp(invocation.command->id, "help")) return maelys_cli_emit_help(&invocation);
    if (!strcmp(invocation.command->id, "version")) return emit_version(&invocation);
    if (!strcmp(invocation.command->id, "describe")) return maelys_cli_emit_describe(&invocation);
    if (!strcmp(invocation.command->id, "pre-receive")) return pre_receive(&invocation);
    if (!strcmp(invocation.command->id, "post-receive")) return post_receive(&invocation);
    return 1;
}
