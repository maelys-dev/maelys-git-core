/* maelys-git-shell: the SSH forced command. `serve` authorizes
 * SSH_ORIGINAL_COMMAND and replaces the process with Git. */
#include "cli/support.h"

#include <stdlib.h>
#include <string.h>

static const maelys_cli_option_t serve_options[] = {
    {MAELYS_CLI_STRING("user", "PRINCIPAL", "Authenticated SSH principal."),
     .required = 1},
    {MAELYS_CLI_PATH("root", "DIR", "Repository root."), .required = 1},
    {MAELYS_CLI_PATH("manifest", "FILE", "Datalog manifest path."), .required = 1},
    MAELYS_GIT_CLI_GIT_OPTION,
    {MAELYS_CLI_STRING("restrict-repository", "NAME",
     "Restrict a deploy key to one exact repository.")},
    {MAELYS_CLI_FLAG("read-only", "Reject receive-pack for this deploy key."),
     .depends_on = "restrict-repository"},
};

static maelys_git_result_t deny(maelys_git_error_t *error, const char *message) {
    error->code = MAELYS_GIT_ERR_DENIED;
    (void)snprintf(error->message, sizeof(error->message), "%s", message);
    return error->code;
}

static int command_serve(maelys_cli_context_t *context) {
    const char *user = maelys_cli_option(context, "user");
    const char *root = maelys_cli_option(context, "root");
    const char *manifest = maelys_cli_option(context, "manifest");
    const char *git = maelys_git_cli_git(context);
    const char *original = getenv("SSH_ORIGINAL_COMMAND");
    maelys_git_error_t error = {0};
    if (!original) {
        error.code = MAELYS_GIT_ERR_INVALID_ARGUMENT;
        (void)snprintf(error.message, sizeof(error.message),
                       "SSH_ORIGINAL_COMMAND is missing");
        return maelys_git_cli_stream_error(context, "stream", error.code, &error);
    }
    maelys_git_ssh_command_t command;
    maelys_git_result_t result = maelys_git_parse_ssh_command(original, &command, &error);
    const char *restricted = maelys_cli_option(context, "restrict-repository");
    if (result == MAELYS_GIT_OK && restricted &&
        (!maelys_git_repository_name_is_valid(restricted) ||
         strcmp(restricted, command.repository) != 0)) {
        char message[MAELYS_GIT_MAX_ERROR];
        (void)snprintf(message, sizeof(message),
                       "deploy key is restricted to repository %s", restricted);
        result = deny(&error, message);
    }
    if (result == MAELYS_GIT_OK && maelys_cli_flag(context, "read-only") &&
        command.service == MAELYS_GIT_SERVICE_RECEIVE_PACK) {
        result = deny(&error, "deploy key is read-only");
    }
    char repository_path[MAELYS_GIT_CLI_PATH_MAX];
    if (result == MAELYS_GIT_OK)
        result = maelys_git_resolve_repository(root, command.repository, repository_path,
                                               sizeof(repository_path), &error);
    maelys_git_policy_t *policy = NULL;
    if (result == MAELYS_GIT_OK) result = maelys_git_policy_open(manifest, &policy, &error);
    if (result == MAELYS_GIT_OK) {
        maelys_git_policy_request_t request = {
            .request_id = "ssh",
            .principal = user,
            .repository = command.repository,
            .operation = command.service == MAELYS_GIT_SERVICE_UPLOAD_PACK ? "read" : "write",
            .ssh_key = getenv("MAELYS_GIT_SSH_KEY"),
            .remote_address = getenv("SSH_CONNECTION"),
        };
        maelys_git_policy_decision_t decision = {0};
        result = maelys_git_policy_authorize(policy, &request, &decision, &error);
        if (result == MAELYS_GIT_OK && !decision.allowed)
            result = deny(&error, decision.reason);
    }
    maelys_git_policy_close(policy);
    if (result != MAELYS_GIT_OK)
        return maelys_git_cli_stream_error(context, "stream", result, &error);
    result = maelys_git_exec_service(git, command.service, repository_path, user, &error);
    /* Only reached when execve failed. */
    return maelys_git_cli_stream_error(context, "stream", result, &error);
}

static const maelys_cli_command_t commands[] = {
    {MAELYS_CLI_PROTOCOL_STREAM("serve", "serve",
     "Authorize SSH_ORIGINAL_COMMAND then replace the process with Git.",
     command_serve, "git-smart"),
     MAELYS_CLI_OPTIONS(serve_options),
     MAELYS_CLI_SCHEMA(maelys_git_schema_protocol_stream)},
};

const maelys_cli_app_t maelys_git_cli_shell_app = {
    .program = "maelys-git-shell",
    .product = "Maelys Git Shell",
    .version = MAELYS_GIT_VERSION,
    .summary = "policy-checked SSH forced command for Git",
    .commands = commands,
    .command_count = MAELYS_CLI_COUNT(commands),
};
