/* maelys-git-agent and maelys-git-executor. The executor's `serve` and the
 * agent's `stdio` share one handler: the local JSONL protocol on stdio. */
#include "agent/agent_internal.h"
#include "policy/policy_grants.h"
#include "cli/json_support.h"
#include "maelys_git_agent.h"

#include <string.h>

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
    {MAELYS_CLI_ABSOLUTE_PATH("grants", "FILE",
     "Snapshot of Gitolite grants (maelys-git-grants/1 or /2) the audited Gitolite program reads; "
     "the agent keeps the bytes each executor reads in grants-store/ beside the journal.")},
    {MAELYS_CLI_ABSOLUTE_PATH("root", "DIR", "Repository root."), .required = 1},
    {MAELYS_CLI_ABSOLUTE_PATH("executor", "FILE", "Executor binary path."),
     .required = 1},
    {MAELYS_CLI_FLAG("apply", "Create the reviewed configuration.")},
};

static const maelys_cli_option_t run_options[] = {
    {MAELYS_CLI_PATH("config", "FILE", "Agent configuration file (v1, at most 64 KiB)."), .required = 1},
    {MAELYS_CLI_FLAG("once", "Run one synchronization cycle.")},
};

/* The defaults of a purge are the catalog's alone. */
static const maelys_cli_option_t prune_options[] = {
    {MAELYS_CLI_PATH("config", "FILE", "Agent configuration file (v1, at most 64 KiB)."), .required = 1},
    {MAELYS_CLI_UNSIGNED("keep", "N", "The most recently used snapshots to keep whatever their age.", 0u, 1000000u),
     .default_text = "16"},
    {MAELYS_CLI_DURATION("older-than", "DURATION",
     "Beyond the kept ones, a snapshot unused for longer expires.", 1u, UINT64_C(315360000000)),
     .default_text = "90d"},
    {MAELYS_CLI_FLAG("apply", "Remove the expired snapshots.")},
};

static const maelys_cli_option_t serve_options[] = {
    {MAELYS_CLI_PATH("manifest", "FILE", "Datalog manifest path."), .required = 1},
    {MAELYS_CLI_PATH("grants", "FILE",
     "Snapshot of Gitolite grants (maelys-git-grants/1 or /2) the audited Gitolite program reads; "
     "read again before each command.")},
    {MAELYS_CLI_HEX("expected-grants-fingerprint", "SHA256",
     "SHA-256 every reading of --grants must have; a reading with other bytes refuses the command. "
     "The reading at startup serves the first command, whatever it is; every later command reads again.", 64u),
     .depends_on = "grants"},
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
    const char *grants = maelys_cli_option(context, "grants");
    const char *root = maelys_cli_option(context, "root");
    const char *executor = maelys_cli_option(context, "executor");
    maelys_git_error_t error = {0};
    maelys_git_result_t result = maelys_git_agent_validate_provision_grants(
        config, agent, authority, ca, token, database, manifest, grants, root, executor, &error);
    if (result != MAELYS_GIT_OK) return maelys_git_cli_fail_result(context, result, &error);
    int apply = maelys_cli_flag(context, "apply");
    if (apply)
        result = maelys_git_agent_provision_grants(
            config, agent, authority, ca, token, database, manifest, grants, root, executor, &error);
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
    if (grants) mg_json_string(&data, "grants", grants);
    mg_json_object(&data, "precondition");
    mg_json_boolean(&data, "configAbsent", 1);
    mg_json_end_object(&data);
    mg_json_end_object(&data);
    return maelys_git_cli_succeed_document(context, &data,
        apply ? "Agent configuration created." :
                "Plan only; add --apply to create the agent configuration.",
        MAELYS_CLI_EXIT_OK);
}

/* The snapshots of grants the agent kept for its executors: the current
 * one, the most recently used and the recent ones stay; the others expire. */
static int command_grants_store_prune(maelys_cli_context_t *context) {
    uint64_t keep = 0u, older_than = 0u;
    (void)maelys_cli_option_unsigned(context, "keep", &keep);
    (void)maelys_cli_option_unsigned(context, "older-than", &older_than);
    int apply = maelys_cli_flag(context, "apply");
    maelys_git_error_t error = {0};
    maelys_git_agent_config_t *config = NULL;
    maelys_git_result_t result = mg_config_load(maelys_cli_option(context, "config"), &config, &error);
    mg_grants_store_prune_t prune;
    memset(&prune, 0, sizeof(prune));
    if (result == MAELYS_GIT_OK)
        result = mg_grants_store_prune(config, (size_t)keep, older_than, mg_now_ms(), 10000u, apply, &prune,
                                       &error);
    mg_config_free(config);
    if (result != MAELYS_GIT_OK) return maelys_git_cli_fail_result(context, result, &error);
    mg_json_t data;
    mg_json_begin(&data, MG_JSON_DATA);
    mg_json_object(&data, NULL);
    mg_json_string(&data, "mode", apply ? "apply" : "plan");
    mg_json_boolean(&data, "changed", apply && prune.removed > 0u);
    mg_json_string(&data, "store", prune.store);
    mg_json_i64(&data, "keep", (int64_t)keep);
    mg_json_i64(&data, "olderThanMs", (int64_t)older_than);
    mg_json_array(&data, "entries");
    for (size_t i = 0u; i < prune.count; ++i) {
        const mg_grants_store_entry_t *entry = &prune.entries[i];
        mg_json_object(&data, NULL);
        mg_json_string(&data, "sha256", entry->sha256);
        mg_json_i64(&data, "bytes", entry->bytes);
        mg_json_i64(&data, "lastUsedMs", entry->last_used_ms);
        mg_json_string(&data, "action", entry->keep ? "keep" : "remove");
        mg_json_string(&data, "reason", entry->reason);
        mg_json_end_object(&data);
    }
    mg_json_end_array(&data);
    mg_json_i64(&data, "removed", (int64_t)prune.removed);
    mg_json_i64(&data, "freedBytes", prune.freed_bytes);
    mg_json_end_object(&data);
    mg_grants_store_prune_clear(&prune);
    return maelys_git_cli_succeed_document(context, &data,
        apply ? "Expired snapshots of grants removed." :
                "Plan only; add --apply to remove the expired snapshots of grants.",
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
    const char *manifest = maelys_cli_option(context, "manifest");
    const char *grants = maelys_cli_option(context, "grants");
    maelys_git_policy_t *policy = NULL;
    maelys_git_result_t result = grants ? maelys_git_policy_open_grants(manifest, grants, &policy, &error)
                                        : maelys_git_policy_open(manifest, &policy, &error);
    const char *expected_grants = maelys_cli_option(context, "expected-grants-fingerprint");
    if (result == MAELYS_GIT_OK && expected_grants)
        result = mg_policy_expect_grants(policy, expected_grants, &error);
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
    {MAELYS_CLI_TRANSACTION("grants-store.prune", "grants-store prune",
     "Plan or remove the expired snapshots of grants the agent kept for its executors.",
     command_grants_store_prune),
     MAELYS_CLI_OPTIONS(prune_options),
     MAELYS_CLI_SCHEMA(maelys_git_schema_agent_grants_store_prune)},
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
