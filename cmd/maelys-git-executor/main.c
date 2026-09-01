#include "maelys_git_agent.h"
#include "maelys_git_cli.h"

#include <string.h>

static int emit_version(const maelys_cli_invocation_t *invocation) {
    json_t *data = json_pack("{s:s,s:s,s:s}", "product", "Maelys Git Executor",
                             "version", MAELYS_GIT_VERSION, "contract", MAELYS_CLI_CONTRACT);
    int result = maelys_cli_emit_success(invocation, data, "maelys-git-executor " MAELYS_GIT_VERSION, 0);
    json_decref(data);
    return result;
}

static int serve(const maelys_cli_invocation_t *invocation) {
    const char *manifest = maelys_cli_option(invocation, "manifest");
    const char *root = maelys_cli_option(invocation, "root");
    const char *git = maelys_cli_option(invocation, "git");
    if (!git) git = "/usr/bin/git";
    maelys_git_error_t error = {0};
    maelys_git_policy_t *policy = NULL;
    maelys_git_result_t result = maelys_git_policy_open(manifest, &policy, &error);
    if (result == MAELYS_GIT_OK)
        result = maelys_git_agent_serve(policy, git, root, stdin, stdout, stderr, &error);
    maelys_git_policy_close(policy);
    if (result != MAELYS_GIT_OK) {
        (void)fprintf(stderr, "maelys-git-executor stream error [%s]: %s\n",
                      maelys_git_result_name(result), error.message);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    maelys_cli_invocation_t invocation;
    maelys_cli_error_t parse_error;
    if (!maelys_cli_parse("maelys-git-executor", argc - 1, argv + 1, &invocation, &parse_error))
        return maelys_cli_emit_error(&invocation, &parse_error, 1);
    if (!strcmp(invocation.command->id, "help")) return maelys_cli_emit_help(&invocation);
    if (!strcmp(invocation.command->id, "version")) return emit_version(&invocation);
    if (!strcmp(invocation.command->id, "describe")) return maelys_cli_emit_describe(&invocation);
    if (!strcmp(invocation.command->id, "serve")) return serve(&invocation);
    return 1;
}
