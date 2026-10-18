/* maelys-git-agent and maelys-git-executor. The executor's `serve` and the
 * agent's `stdio` share one handler: the local JSONL protocol on stdio. */
#include "agent/agent_internal.h"
#include "cli/json_support.h"
#include "maelys_git_agent.h"

/* Every provisioned path becomes durable configuration: absolute only. */
static const maelys_cli_option_t provision_options[] = {
    {MAELYS_CLI_ABSOLUTE_PATH("config", "FILE", "Configuration file to create."),
     .required = 1},
    {MAELYS_CLI_STRING("agent-id", "ID", "Stable agent identifier."), .required = 1},
    {MAELYS_CLI_STRING("authority", "HOST[:PORT]", "HTTPS authority without scheme."),
     .required = 1},
    {MAELYS_CLI_ABSOLUTE_PATH("ca", "FILE", "Trusted CA bundle."), .required = 1},
    {MAELYS_CLI_ABSOLUTE_PATH("token", "FILE", "Mode-0600 bearer token file."),
     .required = 1},
    {MAELYS_CLI_ABSOLUTE_PATH("database", "FILE", "SQLite journal path."), .required = 1},
    {MAELYS_CLI_ABSOLUTE_PATH("manifest", "FILE", "Datalog manifest path."),
     .required = 1},
    {MAELYS_CLI_ABSOLUTE_PATH("root", "DIR", "Repository root."), .required = 1},
    {MAELYS_CLI_ABSOLUTE_PATH("executor", "FILE", "Executor binary path."),
     .required = 1},
    {MAELYS_CLI_FLAG("apply", "Create the reviewed configuration.")},
};

static const maelys_cli_option_t run_options[] = {
    {MAELYS_CLI_PATH("config", "FILE", "Agent configuration file (v1, at most 64 KiB)."), .required = 1},
    {MAELYS_CLI_FLAG("once", "Run one synchronization cycle.")},
};

static const maelys_cli_option_t serve_options[] = {
    {MAELYS_CLI_PATH("manifest", "FILE", "Datalog manifest path."), .required = 1},
    {MAELYS_CLI_PATH("root", "DIR", "Repository root."), .required = 1},
    MAELYS_GIT_CLI_GIT_OPTION,
};

static int command_provision(maelys_cli_context_t *context) {
    const char *config = maelys_cli_option(context, "config");
    const char *agent = maelys_cli_option(context, "agent-id");
    const char *authority = maelys_cli_option(context, "authority");
    const char *ca = maelys_cli_option(context, "ca");
    const char *token = maelys_cli_option(context, "token");
    const char *database = maelys_cli_option(context, "database");
    const char *manifest = maelys_cli_option(context, "manifest");
    const char *root = maelys_cli_option(context, "root");
    const char *executor = maelys_cli_option(context, "executor");
    maelys_git_error_t error = {0};
    maelys_git_result_t result = maelys_git_agent_validate_provision(
        config, agent, authority, ca, token, database, manifest, root, executor, &error);
    if (result != MAELYS_GIT_OK) return maelys_git_cli_fail_result(context, result, &error);
    int apply = maelys_cli_flag(context, "apply");
    if (apply)
        result = maelys_git_agent_provision(
            config, agent, authority, ca, token, database, manifest, root, executor, &error);
    if (result != MAELYS_GIT_OK) return maelys_git_cli_fail_result(context, result, &error);
    mg_json_t data;
    mg_json_begin(&data, MG_JSON_DATA);
    mg_json_object(&data, NULL);
    mg_json_string(&data, "mode", apply ? "apply" : "plan");
    mg_json_boolean(&data, "changed", apply);
    mg_json_string(&data, "config", config);
    mg_json_string(&data, "agentId", agent);
    mg_json_string(&data, "authority", authority);
    mg_json_string(&data, "database", database);
    mg_json_object(&data, "precondition");
    mg_json_boolean(&data, "configAbsent", 1);
    mg_json_end_object(&data);
    mg_json_end_object(&data);
    return maelys_git_cli_succeed_document(context, &data,
        apply ? "Agent configuration created." :
                "Plan only; add --apply to create the agent configuration.",
        MAELYS_CLI_EXIT_OK);
}

#ifdef MAELYS_GIT_ENABLE_CLOUD_AGENT
static int command_run(maelys_cli_context_t *context) {
    maelys_git_error_t error = {0};
    int once = maelys_cli_flag(context, "once");
    maelys_git_result_t result = maelys_git_agent_run_cloud(
        maelys_cli_option(context, "config"), once, &error);
    if (result != MAELYS_GIT_OK) return maelys_git_cli_fail_result(context, result, &error);
    mg_json_t data;
    mg_json_begin(&data, MG_JSON_DATA);
    mg_json_object(&data, NULL);
    mg_json_boolean(&data, "completed", 1);
    mg_json_string(&data, "mode", once ? "once" : "continuous");
    mg_json_end_object(&data);
    return maelys_git_cli_succeed_document(context, &data, "Agent run completed.",
                                           MAELYS_CLI_EXIT_OK);
}
#endif

static int serve(maelys_cli_context_t *context, maelys_git_explain_mode_t denial_mode) {
    maelys_git_error_t error = {0};
    maelys_git_policy_t *policy = NULL;
    maelys_git_result_t result = maelys_git_policy_open(
        maelys_cli_option(context, "manifest"), &policy, &error);
    if (result == MAELYS_GIT_OK)
        result = mg_agent_serve(policy, maelys_git_cli_git(context),
                                maelys_cli_option(context, "root"),
                                stdin, context->out, context->err, denial_mode, &error);
    maelys_git_policy_close(policy);
    return result == MAELYS_GIT_OK ? MAELYS_CLI_EXIT_OK :
        maelys_git_cli_stream_error(context, "stream", result, &error);
}

/* The local front-end publishes its results itself: no denial text. */
static int command_stdio(maelys_cli_context_t *context) {
    return serve(context, MAELYS_GIT_EXPLAIN_NEVER);
}

/* The executor answers the agent that supervises it, which keeps the text of
 * a denial in its audit and removes it from the result it publishes. */
static int command_executor_serve(maelys_cli_context_t *context) {
    return serve(context, MAELYS_GIT_EXPLAIN_ON_DENIAL);
}

static const maelys_cli_command_t agent_commands[] = {
    {MAELYS_CLI_TRANSACTION("provision", "provision", "Plan or create an agent configuration.",
     command_provision),
     MAELYS_CLI_OPTIONS(provision_options),
     MAELYS_CLI_SCHEMA(maelys_git_schema_agent_provision)},
#ifdef MAELYS_GIT_ENABLE_CLOUD_AGENT
    {MAELYS_CLI_EXECUTE("run", "run", "Run the persistent Cloud synchronization loop.",
     command_run),
     MAELYS_CLI_OPTIONS(run_options),
     MAELYS_CLI_SCHEMA(maelys_git_schema_agent_run)},
#else
    /* Described, so agents learn it exists; fails with UNSUPPORTED. */
    {.id = "run", .pattern = "run",
     .purpose = "Run the persistent Cloud synchronization loop.",
     .effect = MAELYS_CLI_EFFECT_EXECUTE, .output = MAELYS_CLI_OUTPUT_ENVELOPE,
     MAELYS_CLI_OPTIONS(run_options),
     MAELYS_CLI_SCHEMA(maelys_git_schema_agent_run),
     .unavailable = "This binary was built without Cloud support; rebuild with "
                    "MAELYS_GIT_ENABLE_CLOUD_AGENT=ON."},
#endif
    {MAELYS_CLI_PROTOCOL_STREAM("stdio", "stdio", "Serve the executor JSONL protocol on stdio.",
     command_stdio, MAELYS_GIT_AGENT_PROTOCOL),
     MAELYS_CLI_OPTIONS(serve_options),
     MAELYS_CLI_SCHEMA(maelys_git_schema_protocol_stream)},
};

static const maelys_cli_command_t executor_commands[] = {
    {MAELYS_CLI_PROTOCOL_STREAM("serve", "serve", "Serve one-command-at-a-time JSONL execution.",
     command_executor_serve, MAELYS_GIT_AGENT_PROTOCOL),
     MAELYS_CLI_OPTIONS(serve_options),
     MAELYS_CLI_SCHEMA(maelys_git_schema_protocol_stream)},
};

const maelys_cli_app_t maelys_git_cli_agent_app = {
    .program = "maelys-git-agent",
    .product = "Maelys Git Agent",
    .version = MAELYS_GIT_VERSION,
    .summary = "persistent HTTPS agent and local executor front-end",
    .commands = agent_commands,
    .command_count = MAELYS_CLI_COUNT(agent_commands),
};

const maelys_cli_app_t maelys_git_cli_executor_app = {
    .program = "maelys-git-executor",
    .product = "Maelys Git Executor",
    .version = MAELYS_GIT_VERSION,
    .summary = "isolated, time-bounded Git command executor",
    .commands = executor_commands,
    .command_count = MAELYS_CLI_COUNT(executor_commands),
};
