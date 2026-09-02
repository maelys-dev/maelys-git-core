/* Contract tests of the five product catalogs on libmaelys_cli: catalog
 * validity, typed parsing and end-to-end envelopes through maelys_cli_run. */
#include "maelys_git_cli.h"
#include "test_support.h"

#include <jansson.h>

static const maelys_cli_app_t *const apps[] = {
    &maelys_git_cli_admin_app,
    &maelys_git_cli_agent_app,
    &maelys_git_cli_executor_app,
    &maelys_git_cli_shell_app,
    &maelys_git_cli_hook_app,
};
#define APP_COUNT (sizeof(apps) / sizeof(apps[0]))

static int test_catalogs(void) {
    CHECK(maelys_git_cli_admin_app.command_count >= 17u);
    for (size_t a = 0u; a < APP_COUNT; ++a) {
        const maelys_cli_app_t *app = apps[a];
        maelys_cli_error_t error;
        if (maelys_cli_catalog_validate(app, &error) != 0)
            (void)fprintf(stderr, "%s: %s\n", app->program, error.message);
        CHECK(maelys_cli_catalog_validate(app, &error) == 0);
        CHECK(app->version && !strcmp(app->version, MAELYS_GIT_VERSION));
        for (size_t i = 0u; i < app->command_count; ++i) {
            const maelys_cli_command_t *command = &app->commands[i];
            CHECK(command->output_schema_json != NULL);
            json_error_t json_error;
            json_t *schema = json_loads(command->output_schema_json,
                                        JSON_REJECT_DUPLICATES, &json_error);
            CHECK(schema != NULL && json_is_object(schema));
            if (command->output == MAELYS_CLI_OUTPUT_ENVELOPE) {
                CHECK(json_is_false(json_object_get(schema, "additionalProperties")));
                CHECK(json_array_size(json_object_get(schema, "required")) > 0u);
            } else {
                CHECK(command->output == MAELYS_CLI_OUTPUT_STREAM);
                CHECK(command->protocol && *command->protocol);
            }
            json_decref(schema);
            if (command->apply_effect != MAELYS_CLI_EFFECT_NONE)
                CHECK(command->effect == MAELYS_CLI_EFFECT_PREVIEW);
            CHECK((command->handler != NULL) != (command->unavailable != NULL));
        }
    }
    return 1;
}

/* The hook's catalog defaults must stay equal to the library defaults: the
 * typed accessors deliver the former, the library documents the latter. */
static const maelys_cli_option_t *find_option(const maelys_cli_command_t *command,
                                              const char *name) {
    for (size_t i = 0u; i < command->option_count; ++i)
        if (!strcmp(command->options[i].name, name)) return &command->options[i];
    return NULL;
}

static int test_hook_defaults(void) {
    const maelys_cli_command_t *pre_receive = NULL;
    for (size_t i = 0u; i < maelys_git_cli_hook_app.command_count; ++i)
        if (!strcmp(maelys_git_cli_hook_app.commands[i].id, "pre-receive"))
            pre_receive = &maelys_git_cli_hook_app.commands[i];
    CHECK(pre_receive != NULL);
    maelys_git_inspection_limits_t limits;
    maelys_git_inspection_limits_default(&limits);
    struct {
        const char *option;
        uint64_t expected;
    } defaults[] = {
        {"max-commits", limits.max_commits},
        {"max-changes", limits.max_changes},
        {"max-total-blob-bytes", limits.max_total_new_blob_size},
        {"max-inspected-blob-bytes", limits.max_inspected_blob_bytes},
    };
    for (size_t i = 0u; i < sizeof(defaults) / sizeof(defaults[0]); ++i) {
        const maelys_cli_option_t *option = find_option(pre_receive, defaults[i].option);
        CHECK(option && option->default_text);
        uint64_t declared = 0u;
        if (option->kind == MAELYS_CLI_VALUE_SIZE)
            CHECK(maelys_cli_parse_byte_size(option->default_text, 0u, UINT64_MAX, &declared) == 0);
        else
            CHECK(maelys_cli_parse_u64_decimal(option->default_text, 0u, UINT64_MAX, &declared) == 0);
        CHECK(declared == defaults[i].expected);
    }
    return 1;
}

static int parse(const maelys_cli_app_t *app, char **argv, int argc,
                 maelys_cli_invocation_t *invocation, maelys_cli_error_t *error) {
    return maelys_cli_parse(app, argc, argv, invocation, error) == 0;
}

#define ARGV(name, ...) char *name[] = {__VA_ARGS__}; \
    const int name##_count = (int)(sizeof(name) / sizeof(name[0]))

static int test_parser(void) {
    maelys_cli_invocation_t invocation;
    maelys_cli_error_t error;
    const maelys_cli_app_t *admin = &maelys_git_cli_admin_app;

    ARGV(plan, "repo", "init", "/tmp", "example.git", "--format", "json", "--compact");
    CHECK(parse(admin, plan, plan_count, &invocation, &error));
    CHECK(!strcmp(invocation.command->id, "repo.init"));
    CHECK(invocation.format == MAELYS_CLI_FORMAT_JSON && invocation.compact);
    CHECK(!maelys_cli_invocation_option(&invocation, "apply"));
    CHECK(!strcmp(maelys_cli_invocation_operand(&invocation, 1u), "example.git"));

    ARGV(booleans, "repo", "init", "/tmp", "example.git", "--apply=false", "--json=false");
    CHECK(parse(admin, booleans, booleans_count, &invocation, &error));
    CHECK(!maelys_cli_invocation_option(&invocation, "apply")->boolean_value);
    CHECK(invocation.format == MAELYS_CLI_FORMAT_TEXT);

    /* A value stays a value even when it starts with --. */
    ARGV(literal, "repo", "mirror", "/a", "x.git", "/b", "--as", "--literal");
    CHECK(parse(admin, literal, literal_count, &invocation, &error));
    CHECK(!strcmp(maelys_cli_invocation_option(&invocation, "as")->value, "--literal"));

    /* --git must be absolute: children are spawned without PATH lookup. */
    ARGV(relative_git, "repo", "init", "/tmp", "example.git", "--git", "git");
    CHECK(!parse(admin, relative_git, relative_git_count, &invocation, &error));
    CHECK(strstr(error.message, "--git"));

    ARGV(unknown, "repo", "init", "/tmp", "example.git", "--token", "x");
    CHECK(!parse(admin, unknown, unknown_count, &invocation, &error));
    CHECK(!strcmp(error.code, MAELYS_CLI_CODE_VALIDATION_FAILED) && strstr(error.message, "--token"));

    ARGV(legacy, "repo", "init", "/tmp", "example.git", "--dry-run");
    CHECK(!parse(admin, legacy, legacy_count, &invocation, &error));
    CHECK(strstr(error.hint, "--apply"));

    ARGV(stream, "serve", "--manifest", "/tmp/policy.json", "--root", "/tmp", "--format", "json");
    CHECK(!parse(&maelys_git_cli_executor_app, stream, stream_count, &invocation, &error));
    CHECK(!strcmp(error.code, MAELYS_CLI_CODE_VALIDATION_FAILED) && strstr(error.message, "stream"));

    ARGV(missing, "provision", "--config", "/tmp/config");
    CHECK(!parse(&maelys_git_cli_agent_app, missing, missing_count, &invocation, &error));
    CHECK(strstr(error.message, "--agent-id"));

    ARGV(bad_command, "repos", "init");
    CHECK(!parse(admin, bad_command, bad_command_count, &invocation, &error));
    CHECK(!strcmp(error.code, MAELYS_CLI_CODE_INVALID_COMMAND));

    /* Typed values: negative gate counts, unknown choices and malformed
     * fingerprints are refused before any handler runs. */
    ARGV(negative, "pr", "merge", "/tmp", "x.git", "refs/heads/main",
         "0000000000000000000000000000000000000000",
         "1111111111111111111111111111111111111111", "/tmp/m.json", "alice",
         "--style", "merge", "--approvals", "-1", "--required-approvals", "1");
    CHECK(!parse(admin, negative, negative_count, &invocation, &error));
    CHECK(!strcmp(error.code, MAELYS_CLI_CODE_VALIDATION_FAILED) && strstr(error.message, "--approvals"));

    ARGV(area, "repo", "restore", "/tmp", "arc-1", "--from", "nowhere");
    CHECK(!parse(admin, area, area_count, &invocation, &error));
    CHECK(strstr(error.message, "--from") && strstr(error.message, "archive"));

    ARGV(fingerprint, "repo", "mirror", "/a", "x.git", "/b",
         "--expected-source-identity", "1:2", "--expected-target-identity", "absent",
         "--expected-source-fingerprint", "xyz");
    CHECK(!parse(admin, fingerprint, fingerprint_count, &invocation, &error));
    CHECK(strstr(error.message, "--expected-source-fingerprint"));

    /* --apply and its reviewed preconditions form an all-or-none group. */
    ARGV(precondition, "repo", "rename", "/tmp", "a.git", "b.git", "--apply");
    CHECK(!parse(admin, precondition, precondition_count, &invocation, &error));
    CHECK(strstr(error.message, "--expected-source-identity"));

    ARGV(orphan, "repo", "mirror", "/a", "x.git", "/b", "--expected-source-identity", "1:2");
    CHECK(!parse(admin, orphan, orphan_count, &invocation, &error));
    CHECK(!strcmp(error.code, MAELYS_CLI_CODE_VALIDATION_FAILED));

    /* Typed operands: object identifiers are checked before any handler runs. */
    ARGV(bad_oid, "repo", "diff", "/tmp", "x.git", "123", "456");
    CHECK(!parse(admin, bad_oid, bad_oid_count, &invocation, &error));
    CHECK(!strcmp(error.code, MAELYS_CLI_CODE_VALIDATION_FAILED) && strstr(error.message, "OLD_OID"));

    ARGV(relative_shell, "keys", "compile", "/keys", "/out", "bin/shell", "/srv", "/m.json");
    CHECK(!parse(admin, relative_shell, relative_shell_count, &invocation, &error));
    CHECK(strstr(error.message, "SHELL"));

    ARGV(paths, "authorize", "/tmp/m.json", "alice", "x.git", "push", "-", "a", "b", "c");
    CHECK(parse(admin, paths, paths_count, &invocation, &error));
    CHECK(invocation.operand_count == 8u);
    return 1;
}

typedef struct {
    int code;
    char *out;
    char *err;
} run_result_t;

static int run(const maelys_cli_app_t *app, char **argv, int argc, run_result_t *result) {
    size_t out_size = 0u, err_size = 0u;
    memset(result, 0, sizeof(*result));
    FILE *out = open_memstream(&result->out, &out_size);
    FILE *err = open_memstream(&result->err, &err_size);
    if (!out || !err) return 0;
    result->code = maelys_cli_run(app, argc, argv, out, err);
    (void)fclose(out);
    (void)fclose(err);
    return result->out && result->err;
}

static void run_clear(run_result_t *result) {
    free(result->out);
    free(result->err);
    memset(result, 0, sizeof(*result));
}

static int test_envelopes(void) {
    run_result_t result;

    ARGV(describe, "describe", "repo.init", "--format", "json", "--compact");
    CHECK(run(&maelys_git_cli_admin_app, describe, describe_count, &result));
    CHECK(result.code == 0 && result.err[0] == '\0');
    CHECK(strstr(result.out, "\"contract\":\"agent-cli/v2\""));
    CHECK(strstr(result.out, "\"id\":\"repo.init\""));
    CHECK(strstr(result.out, "\"effect\":{\"plan\":\"preview\",\"apply\":\"apply\"}"));
    run_clear(&result);

    ARGV(shell, "describe", "serve", "--json", "--compact");
    CHECK(run(&maelys_git_cli_shell_app, shell, shell_count, &result));
    CHECK(result.code == 0);
    CHECK(strstr(result.out, "\"outputMode\":\"protocol-stream\""));
    CHECK(strstr(result.out, "\"protocol\":\"git-smart\""));
    run_clear(&result);

    ARGV(parsed, "parse-ssh", "git-upload-pack 'example.git'", "--json", "--compact");
    CHECK(run(&maelys_git_cli_admin_app, parsed, parsed_count, &result));
    CHECK(result.code == 0 && result.err[0] == '\0');
    CHECK(strstr(result.out, "\"command\":\"parse-ssh\",\"ok\":true,\"exitCode\":0"));
    CHECK(strstr(result.out, "\"service\":\"upload-pack\""));
    run_clear(&result);

    ARGV(refused, "parse-ssh", "sh -c id", "--json", "--compact");
    CHECK(run(&maelys_git_cli_admin_app, refused, refused_count, &result));
    CHECK(result.code == 1 && result.out[0] == '\0');
    CHECK(strstr(result.err, "\"ok\":false,\"exitCode\":1"));
    CHECK(strstr(result.err, "\"code\":\"VALIDATION_FAILED\""));
    run_clear(&result);

    ARGV(oid, "repo", "diff", "/tmp", "x.git", "123", "456", "--json", "--compact");
    CHECK(run(&maelys_git_cli_admin_app, oid, oid_count, &result));
    CHECK(result.code == 1 && strstr(result.err, "OLD_OID"));
    run_clear(&result);

    ARGV(version, "version", "--json", "--compact");
    CHECK(run(&maelys_git_cli_agent_app, version, version_count, &result));
    CHECK(result.code == 0 && strstr(result.out, "\"product\":\"Maelys Git Agent\""));
    CHECK(strstr(result.out, "\"version\":\"" MAELYS_GIT_VERSION "\""));
    run_clear(&result);

    ARGV(text_version, "--version");
    CHECK(run(&maelys_git_cli_hook_app, text_version, text_version_count, &result));
    CHECK(result.code == 0 && !strcmp(result.out, "maelys-git-hook " MAELYS_GIT_VERSION "\n"));
    run_clear(&result);
    return 1;
}

int main(void) {
    int passed = 0;
    passed += test_catalogs();
    passed += test_hook_defaults();
    passed += test_parser();
    passed += test_envelopes();
    if (passed != 4) return 1;
    (void)printf("ok: %d CLI contract test groups passed\n", passed);
    return 0;
}
