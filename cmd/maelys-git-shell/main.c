#include "maelys_git_cli.h"

#include <stdlib.h>
#include <string.h>

static int emit_version(const maelys_cli_invocation_t *invocation) {
    json_t *data = json_pack("{s:s,s:s,s:s}", "product", "Maelys Git Shell",
                             "version", MAELYS_GIT_VERSION, "contract", MAELYS_CLI_CONTRACT);
    int result = maelys_cli_emit_success(invocation, data, "maelys-git-shell " MAELYS_GIT_VERSION, 0);
    json_decref(data);
    return result;
}

static int serve(const maelys_cli_invocation_t *invocation) {
    const char *user = maelys_cli_option(invocation, "user");
    const char *root = maelys_cli_option(invocation, "root");
    const char *manifest = maelys_cli_option(invocation, "manifest");
    const char *git = maelys_cli_option(invocation, "git");
    if (!git) git = "/usr/bin/git";
    const char *original = getenv("SSH_ORIGINAL_COMMAND");
    if (!original) {
        (void)fprintf(stderr, "maelys-git-shell stream error [VALIDATION_FAILED]: SSH_ORIGINAL_COMMAND is missing\n");
        return 1;
    }
    maelys_git_error_t error = {0};
    maelys_git_ssh_command_t command;
    maelys_git_result_t result = maelys_git_parse_ssh_command(original, &command, &error);
    const char *restricted_repository =
        maelys_cli_option(invocation, "restrict-repository");
    if (result == MAELYS_GIT_OK && restricted_repository &&
        (!maelys_git_repository_name_is_valid(restricted_repository) ||
         strcmp(restricted_repository, command.repository) != 0)) {
        result = MAELYS_GIT_ERR_DENIED;
        error.code = result;
        (void)snprintf(error.message, sizeof(error.message),
                       "deploy key is restricted to repository %s",
                       restricted_repository);
    }
    if (result == MAELYS_GIT_OK && maelys_cli_flag(invocation, "read-only") &&
        command.service == MAELYS_GIT_SERVICE_RECEIVE_PACK) {
        result = MAELYS_GIT_ERR_DENIED;
        error.code = result;
        (void)snprintf(error.message, sizeof(error.message),
                       "deploy key is read-only");
    }
    char repository_path[4096];
    if (result == MAELYS_GIT_OK)
        result = maelys_git_resolve_repository(root, command.repository, repository_path,
                                               sizeof(repository_path), &error);
    maelys_git_policy_t *policy = NULL;
    if (result == MAELYS_GIT_OK) result = maelys_git_policy_open(manifest, &policy, &error);
    maelys_git_policy_decision_t decision = {0};
    if (result == MAELYS_GIT_OK) {
        maelys_git_policy_request_t request = {
            .request_id = "ssh", .principal = user, .repository = command.repository,
            .operation = command.service == MAELYS_GIT_SERVICE_UPLOAD_PACK ? "read" : "write",
            .ssh_key = getenv("MAELYS_GIT_SSH_KEY"), .remote_address = getenv("SSH_CONNECTION"),
        };
        result = maelys_git_policy_authorize(policy, &request, &decision, &error);
        if (result == MAELYS_GIT_OK && !decision.allowed) {
            result = MAELYS_GIT_ERR_DENIED;
            error.code = result;
            (void)snprintf(error.message, sizeof(error.message), "%s", decision.reason);
        }
    }
    maelys_git_policy_close(policy);
    if (result != MAELYS_GIT_OK) {
        (void)fprintf(stderr, "maelys-git-shell stream error [%s]: %s\n",
                      maelys_git_result_name(result), error.message);
        return 1;
    }
    result = maelys_git_exec_service(git, command.service, repository_path, user, &error);
    (void)fprintf(stderr, "maelys-git-shell stream error [%s]: %s\n",
                  maelys_git_result_name(result), error.message);
    return result == MAELYS_GIT_OK ? 0 : 1;
}

int main(int argc, char **argv) {
    maelys_cli_invocation_t invocation;
    maelys_cli_error_t parse_error;
    if (!maelys_cli_parse("maelys-git-shell", argc - 1, argv + 1, &invocation, &parse_error))
        return maelys_cli_emit_error(&invocation, &parse_error, 1);
    if (!strcmp(invocation.command->id, "help")) return maelys_cli_emit_help(&invocation);
    if (!strcmp(invocation.command->id, "version")) return emit_version(&invocation);
    if (!strcmp(invocation.command->id, "describe")) return maelys_cli_emit_describe(&invocation);
    if (!strcmp(invocation.command->id, "serve")) return serve(&invocation);
    return 1;
}
