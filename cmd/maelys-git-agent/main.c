#include "maelys_git_agent.h"
#include "maelys_git_cli.h"

#include <string.h>
#include <sys/stat.h>

static int emit_version(const maelys_cli_invocation_t *invocation) {
    json_t *data = json_pack("{s:s,s:s,s:s}", "product", "Maelys Git Agent",
                             "version", MAELYS_GIT_VERSION, "contract", MAELYS_CLI_CONTRACT);
    char human[128];
    (void)snprintf(human, sizeof(human), "maelys-git-agent %s", MAELYS_GIT_VERSION);
    int result = maelys_cli_emit_success(invocation, data, human, 0);
    json_decref(data);
    return result;
}

static int command_stdio(const maelys_cli_invocation_t *invocation) {
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
        (void)fprintf(stderr, "maelys-git-agent stream error [%s]: %s\n",
                      maelys_git_result_name(result), error.message);
        return 1;
    }
    return 0;
}

static int command_provision(const maelys_cli_invocation_t *invocation) {
    const char *config = maelys_cli_option(invocation, "config");
    const char *agent = maelys_cli_option(invocation, "agent-id");
    const char *authority = maelys_cli_option(invocation, "authority");
    const char *ca = maelys_cli_option(invocation, "ca");
    const char *token = maelys_cli_option(invocation, "token");
    const char *database = maelys_cli_option(invocation, "database");
    const char *manifest = maelys_cli_option(invocation, "manifest");
    const char *root = maelys_cli_option(invocation, "root");
    const char *executor = maelys_cli_option(invocation, "executor");
    maelys_git_error_t error = {0};
    maelys_git_result_t result = maelys_git_agent_validate_provision(
        config, agent, authority, ca, token, database, manifest, root, executor, &error);
    if (result != MAELYS_GIT_OK) return maelys_cli_emit_maelys_error(invocation, result, &error);
    int apply = maelys_cli_flag(invocation, "apply");
    if (apply) result = maelys_git_agent_provision(
        config, agent, authority, ca, token, database, manifest, root, executor, &error);
    if (result != MAELYS_GIT_OK) return maelys_cli_emit_maelys_error(invocation, result, &error);
    json_t *data = json_pack("{s:s,s:b,s:s,s:s,s:s,s:s,s:o}",
        "mode", apply ? "apply" : "plan", "changed", apply,
        "config", config, "agentId", agent, "authority", authority,
        "database", database, "precondition", json_pack("{s:b}", "configAbsent", 1));
    int emitted = maelys_cli_emit_success(invocation, data,
        apply ? "Agent configuration created." :
                "Plan only; add --apply to create the agent configuration.", 0);
    json_decref(data);
    return emitted;
}

static int command_run(const maelys_cli_invocation_t *invocation) {
#ifdef MAELYS_GIT_ENABLE_CLOUD_AGENT
    maelys_git_error_t error = {0};
    int once = maelys_cli_flag(invocation, "once");
    maelys_git_result_t result = maelys_git_agent_run_cloud(
        maelys_cli_option(invocation, "config"), once, &error);
    if (result != MAELYS_GIT_OK) return maelys_cli_emit_maelys_error(invocation, result, &error);
    json_t *data = json_pack("{s:b,s:s}", "completed", 1,
                             "mode", once ? "once" : "continuous");
    int emitted = maelys_cli_emit_success(invocation, data, "Agent run completed.", 0);
    json_decref(data);
    return emitted;
#else
    maelys_cli_error_t error = {"UNSUPPORTED", "This binary was built without Cloud support.",
                                "Rebuild with MAELYS_GIT_ENABLE_CLOUD_AGENT=ON."};
    return maelys_cli_emit_error(invocation, &error, 1);
#endif
}

int main(int argc, char **argv) {
    (void)umask(0077);
    maelys_cli_invocation_t invocation;
    maelys_cli_error_t parse_error;
    if (!maelys_cli_parse("maelys-git-agent", argc - 1, argv + 1, &invocation, &parse_error))
        return maelys_cli_emit_error(&invocation, &parse_error, 1);
    const char *command = invocation.command->id;
    if (!strcmp(command, "help")) return maelys_cli_emit_help(&invocation);
    if (!strcmp(command, "version")) return emit_version(&invocation);
    if (!strcmp(command, "describe")) return maelys_cli_emit_describe(&invocation);
    if (!strcmp(command, "provision")) return command_provision(&invocation);
    if (!strcmp(command, "run")) return command_run(&invocation);
    if (!strcmp(command, "stdio")) return command_stdio(&invocation);
    return 1;
}
