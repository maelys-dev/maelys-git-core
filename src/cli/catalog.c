#include "maelys_git_cli.h"

#include <string.h>

#define COUNT(array) (sizeof(array) / sizeof((array)[0]))
#define OBJECT_SCHEMA(description) "{\"type\":\"object\",\"description\":\"" description "\",\"additionalProperties\":true}"
#define VERSION_SCHEMA "{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"product\",\"version\",\"contract\"],\"properties\":{\"product\":{\"type\":\"string\"},\"version\":{\"type\":\"string\"},\"contract\":{\"const\":\"agent-cli/v2\"}}}"
#define VALIDATE_SCHEMA "{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"valid\",\"manifest\",\"diagnostics\"],\"properties\":{\"valid\":{\"type\":\"boolean\"},\"manifest\":{\"type\":\"string\"},\"diagnostics\":{\"type\":\"array\",\"items\":{\"type\":\"object\"}}}}"
#define AUTHORIZE_SCHEMA "{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"allowed\",\"explicitDeny\",\"matchedPolicy\",\"reason\"],\"properties\":{\"allowed\":{\"type\":\"boolean\"},\"explicitDeny\":{\"type\":\"boolean\"},\"matchedPolicy\":{\"type\":\"integer\",\"minimum\":0},\"reason\":{\"type\":\"string\"}}}"
#define PARSE_SSH_SCHEMA "{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"service\",\"repository\"],\"properties\":{\"service\":{\"enum\":[\"upload-pack\",\"receive-pack\"]},\"repository\":{\"type\":\"string\"}}}"
#define REPO_INIT_SCHEMA "{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"mode\",\"changed\",\"root\",\"repository\",\"git\",\"precondition\"],\"properties\":{\"mode\":{\"enum\":[\"plan\",\"apply\"]},\"changed\":{\"type\":\"boolean\"},\"root\":{\"type\":\"string\"},\"repository\":{\"type\":\"string\"},\"git\":{\"type\":\"string\"},\"precondition\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"targetAbsent\"],\"properties\":{\"targetAbsent\":{\"const\":true}}}}}"
#define REPO_DIFF_SCHEMA "{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"repository\",\"paths\",\"pathCount\"],\"properties\":{\"repository\":{\"type\":\"string\"},\"paths\":{\"type\":\"array\",\"maxItems\":64,\"items\":{\"type\":\"string\"}},\"pathCount\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":64}}}"
#define UPDATE_REF_SCHEMA "{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"mode\",\"changed\",\"repository\",\"ref\",\"newOid\",\"git\",\"precondition\"],\"properties\":{\"mode\":{\"enum\":[\"plan\",\"apply\"]},\"changed\":{\"type\":\"boolean\"},\"repository\":{\"type\":\"string\"},\"ref\":{\"type\":\"string\"},\"newOid\":{\"type\":\"string\"},\"git\":{\"type\":\"string\"},\"precondition\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"currentOid\"],\"properties\":{\"currentOid\":{\"type\":\"string\"}}}}}"
#define PROVISION_SCHEMA "{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"mode\",\"changed\",\"config\",\"agentId\",\"authority\",\"database\",\"precondition\"],\"properties\":{\"mode\":{\"enum\":[\"plan\",\"apply\"]},\"changed\":{\"type\":\"boolean\"},\"config\":{\"type\":\"string\"},\"agentId\":{\"type\":\"string\"},\"authority\":{\"type\":\"string\"},\"database\":{\"type\":\"string\"},\"precondition\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"configAbsent\"],\"properties\":{\"configAbsent\":{\"const\":true}}}}}"
#define RUN_SCHEMA "{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"completed\",\"mode\"],\"properties\":{\"completed\":{\"const\":true},\"mode\":{\"enum\":[\"once\",\"continuous\"]}}}"

static const maelys_cli_operand_descriptor_t describe_operands[] = {
    {"COMMAND_ID", 0, 0, "Stable command identifier returned by the catalog."},
};
static const maelys_cli_option_descriptor_t describe_options[] = {
    {"summary", MAELYS_CLI_VALUE_NONE, NULL, 0, 0, NULL, NULL,
     "Return the compact command inventory."},
};
static const maelys_cli_operand_descriptor_t validate_operands[] = {
    {"MANIFEST", 1, 0, "Versioned Maelys Datalog manifest."},
};
static const maelys_cli_operand_descriptor_t authorize_operands[] = {
    {"MANIFEST", 1, 0, "Versioned Maelys Datalog manifest."},
    {"PRINCIPAL", 1, 0, "Authenticated principal."},
    {"REPOSITORY", 1, 0, "Repository name below the configured root."},
    {"OPERATION", 1, 0, "Datalog operation atom."},
    {"REF", 0, 0, "Optional full Git reference, or '-' when omitted."},
    {"PATH", 0, 1, "Zero or more changed paths."},
};
static const maelys_cli_operand_descriptor_t parse_ssh_operands[] = {
    {"COMMAND", 1, 0, "Complete SSH_ORIGINAL_COMMAND value."},
};
static const maelys_cli_operand_descriptor_t repo_operands[] = {
    {"ROOT", 1, 0, "Absolute repository root."},
    {"REPOSITORY", 1, 0, "Repository name below ROOT."},
};
static const maelys_cli_operand_descriptor_t diff_operands[] = {
    {"ROOT", 1, 0, "Absolute repository root."},
    {"REPOSITORY", 1, 0, "Repository name below ROOT."},
    {"OLD_OID", 1, 0, "Expected old object identifier."},
    {"NEW_OID", 1, 0, "New object identifier."},
};
static const maelys_cli_operand_descriptor_t update_operands[] = {
    {"ROOT", 1, 0, "Absolute repository root."},
    {"REPOSITORY", 1, 0, "Repository name below ROOT."},
    {"REF", 1, 0, "Full Git reference."},
    {"NEW_OID", 1, 0, "New object identifier."},
    {"OLD_OID", 1, 0, "Expected current object identifier."},
};
static const maelys_cli_option_descriptor_t git_option[] = {
    {"git", MAELYS_CLI_VALUE_PATH, "FILE", 0, 0, NULL, NULL,
     "Absolute Git executable path."},
};
static const maelys_cli_option_descriptor_t git_apply_options[] = {
    {"git", MAELYS_CLI_VALUE_PATH, "FILE", 0, 0, NULL, NULL,
     "Absolute Git executable path."},
    {"apply", MAELYS_CLI_VALUE_NONE, NULL, 0, 0, NULL, NULL,
     "Apply the reviewed transaction; omission returns a read-only plan."},
};

static const maelys_cli_option_descriptor_t agent_provision_options[] = {
    {"config", MAELYS_CLI_VALUE_PATH, "FILE", 1, 0, NULL, NULL, "Configuration file to create."},
    {"agent-id", MAELYS_CLI_VALUE_STRING, "ID", 1, 0, NULL, NULL, "Stable agent identifier."},
    {"authority", MAELYS_CLI_VALUE_STRING, "HOST[:PORT]", 1, 0, NULL, NULL, "HTTPS authority without scheme."},
    {"ca", MAELYS_CLI_VALUE_PATH, "FILE", 1, 0, NULL, NULL, "Trusted CA bundle."},
    {"token", MAELYS_CLI_VALUE_PATH, "FILE", 1, 0, NULL, NULL, "Mode-0600 bearer token file."},
    {"database", MAELYS_CLI_VALUE_PATH, "FILE", 1, 0, NULL, NULL, "SQLite journal path."},
    {"manifest", MAELYS_CLI_VALUE_PATH, "FILE", 1, 0, NULL, NULL, "Datalog manifest path."},
    {"root", MAELYS_CLI_VALUE_PATH, "DIR", 1, 0, NULL, NULL, "Repository root."},
    {"executor", MAELYS_CLI_VALUE_PATH, "FILE", 1, 0, NULL, NULL, "Executor binary path."},
    {"apply", MAELYS_CLI_VALUE_NONE, NULL, 0, 0, NULL, NULL, "Create the reviewed configuration."},
};
static const maelys_cli_option_descriptor_t agent_run_options[] = {
    {"config", MAELYS_CLI_VALUE_PATH, "FILE", 1, 0, NULL, NULL, "Agent configuration file."},
    {"once", MAELYS_CLI_VALUE_NONE, NULL, 0, 0, NULL, NULL, "Run one synchronization cycle."},
};
static const maelys_cli_option_descriptor_t stream_options[] = {
    {"manifest", MAELYS_CLI_VALUE_PATH, "FILE", 1, 0, NULL, NULL, "Datalog manifest path."},
    {"root", MAELYS_CLI_VALUE_PATH, "DIR", 1, 0, NULL, NULL, "Repository root."},
    {"git", MAELYS_CLI_VALUE_PATH, "FILE", 0, 0, NULL, NULL, "Absolute Git executable path."},
};
static const maelys_cli_option_descriptor_t shell_options[] = {
    {"user", MAELYS_CLI_VALUE_STRING, "PRINCIPAL", 1, 0, NULL, NULL, "Authenticated SSH principal."},
    {"root", MAELYS_CLI_VALUE_PATH, "DIR", 1, 0, NULL, NULL, "Repository root."},
    {"manifest", MAELYS_CLI_VALUE_PATH, "FILE", 1, 0, NULL, NULL, "Datalog manifest path."},
    {"git", MAELYS_CLI_VALUE_PATH, "FILE", 0, 0, NULL, NULL, "Absolute Git executable path."},
};
static const maelys_cli_option_descriptor_t hook_pre_options[] = {
    {"repository", MAELYS_CLI_VALUE_STRING, "NAME", 1, 0, NULL, NULL, "Repository name."},
    {"manifest", MAELYS_CLI_VALUE_PATH, "FILE", 1, 0, NULL, NULL, "Datalog manifest path."},
    {"user", MAELYS_CLI_VALUE_STRING, "PRINCIPAL", 0, 0, NULL, NULL, "Authenticated principal; defaults to the environment."},
    {"git", MAELYS_CLI_VALUE_PATH, "FILE", 0, 0, NULL, NULL, "Absolute Git executable path."},
    {"git-dir", MAELYS_CLI_VALUE_PATH, "DIR", 0, 0, NULL, NULL, "Bare Git directory."},
};
static const maelys_cli_option_descriptor_t hook_post_options[] = {
    {"repository", MAELYS_CLI_VALUE_STRING, "NAME", 1, 0, NULL, NULL, "Repository name."},
    {"user", MAELYS_CLI_VALUE_STRING, "PRINCIPAL", 0, 0, NULL, NULL, "Authenticated principal; defaults to the environment."},
    {"events", MAELYS_CLI_VALUE_PATH, "FILE", 0, 0, NULL, NULL, "Append-only JSONL event file; stdout when omitted."},
};

static const maelys_cli_command_descriptor_t commands[] = {
    {"maelys-git", "help", "help", "help", "Show the generated CLI guide.", "read", NULL, "json-envelope", NULL, 0, NULL, 0, OBJECT_SCHEMA("CLI help text.")},
    {"maelys-git", "version", "version", "version | --version", "Return product identity.", "read", NULL, "json-envelope", NULL, 0, NULL, 0, VERSION_SCHEMA},
    {"maelys-git", "describe", "describe", "describe [COMMAND_ID] [--summary]", "Return executable command contracts.", "read", NULL, "json-envelope", describe_operands, COUNT(describe_operands), describe_options, COUNT(describe_options), OBJECT_SCHEMA("Versioned command catalog.")},
    {"maelys-git", "validate", "validate", "validate MANIFEST", "Validate a Datalog policy manifest.", "read", NULL, "json-envelope", validate_operands, COUNT(validate_operands), NULL, 0, VALIDATE_SCHEMA},
    {"maelys-git", "authorize", "authorize", "authorize MANIFEST PRINCIPAL REPOSITORY OPERATION [REF] [PATH...]", "Evaluate one authorization request.", "read", NULL, "json-envelope", authorize_operands, COUNT(authorize_operands), NULL, 0, AUTHORIZE_SCHEMA},
    {"maelys-git", "parse-ssh", "parse-ssh", "parse-ssh COMMAND", "Parse a forced SSH Git command.", "read", NULL, "json-envelope", parse_ssh_operands, COUNT(parse_ssh_operands), NULL, 0, PARSE_SSH_SCHEMA},
    {"maelys-git", "repo.init", "repo init", "repo init ROOT REPOSITORY [--git FILE] [--apply]", "Plan or create a bare repository.", "preview", "apply", "json-envelope", repo_operands, COUNT(repo_operands), git_apply_options, COUNT(git_apply_options), REPO_INIT_SCHEMA},
    {"maelys-git", "repo.diff", "repo diff", "repo diff ROOT REPOSITORY OLD_OID NEW_OID [--git FILE]", "List changed paths between Git objects.", "read", NULL, "json-envelope", diff_operands, COUNT(diff_operands), git_option, COUNT(git_option), REPO_DIFF_SCHEMA},
    {"maelys-git", "repo.update-ref", "repo update-ref", "repo update-ref ROOT REPOSITORY REF NEW_OID OLD_OID [--git FILE] [--apply]", "Plan or compare-and-swap a Git reference.", "preview", "apply", "json-envelope", update_operands, COUNT(update_operands), git_apply_options, COUNT(git_apply_options), UPDATE_REF_SCHEMA},

    {"maelys-git-agent", "help", "help", "help", "Show the generated CLI guide.", "read", NULL, "json-envelope", NULL, 0, NULL, 0, OBJECT_SCHEMA("CLI help text.")},
    {"maelys-git-agent", "version", "version", "version | --version", "Return product identity.", "read", NULL, "json-envelope", NULL, 0, NULL, 0, VERSION_SCHEMA},
    {"maelys-git-agent", "describe", "describe", "describe [COMMAND_ID] [--summary]", "Return executable command contracts.", "read", NULL, "json-envelope", describe_operands, COUNT(describe_operands), describe_options, COUNT(describe_options), OBJECT_SCHEMA("Versioned command catalog.")},
    {"maelys-git-agent", "provision", "provision", "provision --config FILE --agent-id ID --authority HOST[:PORT] --ca FILE --token FILE --database FILE --manifest FILE --root DIR --executor FILE [--apply]", "Plan or create an agent configuration.", "preview", "apply", "json-envelope", NULL, 0, agent_provision_options, COUNT(agent_provision_options), PROVISION_SCHEMA},
    {"maelys-git-agent", "run", "run", "run --config FILE [--once]", "Run the persistent Cloud synchronization loop.", "execute", NULL, "json-envelope", NULL, 0, agent_run_options, COUNT(agent_run_options), RUN_SCHEMA},
    {"maelys-git-agent", "stdio", "stdio", "stdio --manifest FILE --root DIR [--git FILE]", "Serve the executor JSONL protocol on stdio.", "stream", NULL, "maelys-git-agent-jsonl-stream", NULL, 0, stream_options, COUNT(stream_options), OBJECT_SCHEMA("Protocol stream; no CLI envelope.")},

    {"maelys-git-executor", "help", "help", "help", "Show the generated CLI guide.", "read", NULL, "json-envelope", NULL, 0, NULL, 0, OBJECT_SCHEMA("CLI help text.")},
    {"maelys-git-executor", "version", "version", "version | --version", "Return product identity.", "read", NULL, "json-envelope", NULL, 0, NULL, 0, VERSION_SCHEMA},
    {"maelys-git-executor", "describe", "describe", "describe [COMMAND_ID] [--summary]", "Return executable command contracts.", "read", NULL, "json-envelope", describe_operands, COUNT(describe_operands), describe_options, COUNT(describe_options), OBJECT_SCHEMA("Versioned command catalog.")},
    {"maelys-git-executor", "serve", "serve", "serve --manifest FILE --root DIR [--git FILE]", "Serve one-command-at-a-time JSONL execution.", "stream", NULL, "maelys-git-agent-jsonl-stream", NULL, 0, stream_options, COUNT(stream_options), OBJECT_SCHEMA("Protocol stream; no CLI envelope.")},

    {"maelys-git-shell", "help", "help", "help", "Show the generated CLI guide.", "read", NULL, "json-envelope", NULL, 0, NULL, 0, OBJECT_SCHEMA("CLI help text.")},
    {"maelys-git-shell", "version", "version", "version | --version", "Return product identity.", "read", NULL, "json-envelope", NULL, 0, NULL, 0, VERSION_SCHEMA},
    {"maelys-git-shell", "describe", "describe", "describe [COMMAND_ID] [--summary]", "Return executable command contracts.", "read", NULL, "json-envelope", describe_operands, COUNT(describe_operands), describe_options, COUNT(describe_options), OBJECT_SCHEMA("Versioned command catalog.")},
    {"maelys-git-shell", "serve", "serve", "serve --user PRINCIPAL --root DIR --manifest FILE [--git FILE]", "Authorize SSH_ORIGINAL_COMMAND then replace the process with Git.", "stream", NULL, "git-smart-protocol-stream", NULL, 0, shell_options, COUNT(shell_options), OBJECT_SCHEMA("Git smart-protocol stream; no CLI envelope.")},

    {"maelys-git-hook", "help", "help", "help", "Show the generated CLI guide.", "read", NULL, "json-envelope", NULL, 0, NULL, 0, OBJECT_SCHEMA("CLI help text.")},
    {"maelys-git-hook", "version", "version", "version | --version", "Return product identity.", "read", NULL, "json-envelope", NULL, 0, NULL, 0, VERSION_SCHEMA},
    {"maelys-git-hook", "describe", "describe", "describe [COMMAND_ID] [--summary]", "Return executable command contracts.", "read", NULL, "json-envelope", describe_operands, COUNT(describe_operands), describe_options, COUNT(describe_options), OBJECT_SCHEMA("Versioned command catalog.")},
    {"maelys-git-hook", "pre-receive", "pre-receive", "pre-receive --repository NAME --manifest FILE [--user PRINCIPAL] [--git FILE] [--git-dir DIR]", "Authorize a Git receive transaction from stdin.", "stream", NULL, "git-hook-stream", NULL, 0, hook_pre_options, COUNT(hook_pre_options), OBJECT_SCHEMA("Git hook diagnostics; no CLI envelope.")},
    {"maelys-git-hook", "post-receive", "post-receive", "post-receive --repository NAME [--user PRINCIPAL] [--events FILE]", "Convert received refs into JSONL events.", "stream", NULL, "maelys-git-events-jsonl-stream", NULL, 0, hook_post_options, COUNT(hook_post_options), OBJECT_SCHEMA("Versioned event stream; no CLI envelope.")},
};

const maelys_cli_command_descriptor_t *maelys_cli_commands(size_t *out_count) {
    if (out_count) *out_count = COUNT(commands);
    return commands;
}

const maelys_cli_command_descriptor_t *maelys_cli_find_command(
    const char *program, const char *id) {
    for (size_t i = 0u; i < COUNT(commands); ++i)
        if (!strcmp(commands[i].program, program) && !strcmp(commands[i].id, id)) return &commands[i];
    return NULL;
}
