/* Contract tests of the five product catalogs on libmaelys_cli: catalog
 * validity, typed parsing and end-to-end envelopes through maelys_cli_run. */
#include "maelys_git_cli.h"
#include "test_support.h"

#include <jansson.h>
#include <maelys/cli/digest.h>
#include <regex.h>

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

/* ---- validate: the policy failure detail ----------------------------------- */

/* Checks a value against the subset of JSON Schema that the validate schema
 * uses; any other keyword fails, so that nothing is skipped unnoticed. */
static int conforms(const json_t *value, const json_t *schema) {
    const char *keyword;
    const json_t *rule;
    json_object_foreach((json_t *)schema, keyword, rule) {
        if (!strcmp(keyword, "type")) {
            const char *type = json_string_value(rule);
            int ok = !strcmp(type, "object") ? json_is_object(value)
                   : !strcmp(type, "array") ? json_is_array(value)
                   : !strcmp(type, "string") ? json_is_string(value)
                   : !strcmp(type, "boolean") ? json_is_boolean(value)
                   : !strcmp(type, "integer") ? json_is_integer(value) : 0;
            if (!ok) return 0;
        } else if (!strcmp(keyword, "required")) {
            size_t i;
            const json_t *name;
            json_array_foreach(rule, i, name)
                if (!json_object_get(value, json_string_value(name))) return 0;
        } else if (!strcmp(keyword, "properties")) {
            const char *name;
            const json_t *member;
            json_object_foreach((json_t *)value, name, member) {
                const json_t *property = json_object_get(rule, name);
                if (property ? !conforms(member, property)
                             : json_is_false(json_object_get(schema, "additionalProperties")))
                    return 0;
            }
        } else if (!strcmp(keyword, "items")) {
            size_t i;
            const json_t *item;
            json_array_foreach(value, i, item) if (!conforms(item, rule)) return 0;
        } else if (!strcmp(keyword, "enum")) {
            size_t i;
            const json_t *allowed;
            int found = 0;
            json_array_foreach(rule, i, allowed) found = found || json_equal(value, allowed);
            if (!found) return 0;
        } else if (!strcmp(keyword, "pattern")) {
            regex_t expression;
            if (regcomp(&expression, json_string_value(rule), REG_EXTENDED | REG_NOSUB) != 0) return 0;
            int matched = regexec(&expression, json_string_value(value), 0u, NULL, 0) == 0;
            regfree(&expression);
            if (!matched) return 0;
        } else if (!strcmp(keyword, "minimum")) {
            if (json_integer_value(value) < json_integer_value(rule)) return 0;
        } else if (!strcmp(keyword, "minLength")) {
            if (json_string_length(value) < (size_t)json_integer_value(rule)) return 0;
        } else if (strcmp(keyword, "additionalProperties") != 0) {
            (void)fprintf(stderr, "schema keyword not checked: %s\n", keyword);
            return 0;
        }
    }
    return 1;
}

static json_t *validate_schema(void) {
    const maelys_cli_app_t *admin = &maelys_git_cli_admin_app;
    for (size_t i = 0u; i < admin->command_count; ++i)
        if (!strcmp(admin->commands[i].id, "validate"))
            return json_loads(admin->commands[i].output_schema_json, 0, NULL);
    return NULL;
}

/* Writes DIRECTORY/policy.dl and DIRECTORY/manifest.json; returns the manifest. */
static const char *write_manifest(const char *directory, const char *source) {
    static char manifest_path[512];
    char policy_path[512], digest[MAELYS_CLI_SHA256_HEX_SIZE];
    if (mkdir(directory, 0700) != 0) return NULL;
    (void)snprintf(policy_path, sizeof(policy_path), "%s/policy.dl", directory);
    (void)snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.json", directory);
    FILE *file = fopen(policy_path, "w");
    if (!file || fputs(source, file) < 0 || fclose(file) != 0) return NULL;
    maelys_cli_sha256_hex(source, strlen(source), digest);
    file = fopen(manifest_path, "w");
    if (!file) return NULL;
    int ok = fprintf(file,
        "{\"policy_set_id\":\"cli\",\"policy_set_version\":\"1\",\"manifest_version\":\"1\","
        "\"default_profile\":\"enforce\",\"created_for\":\"tests\",\"strict_loading\":true,"
        "\"fail_closed\":true,\"capabilities\":[],\"policies\":[{\"policy_id\":\"cli.main\","
        "\"domain\":\"maelys_git\",\"file\":\"policy.dl\",\"sha256\":\"%s\",\"mode\":\"enforce\","
        "\"enabled\":true,\"description\":\"test\",\"queries\":[{\"name\":\"allow\",\"arity\":1},"
        "{\"name\":\"deny\",\"arity\":1}]}]}\n", digest) > 0;
    return fclose(file) == 0 && ok ? manifest_path : NULL;
}

/* Runs validate on a manifest and returns its data, checked against the schema. */
static json_t *validate(const char *manifest, int expected_exit, const json_t *schema) {
    run_result_t result;
    ARGV(argv, "validate", (char *)manifest, "--json", "--compact");
    if (!run(&maelys_git_cli_admin_app, argv, argv_count, &result)) return NULL;
    json_t *data = NULL;
    if (result.code == expected_exit && result.err[0] == '\0') {
        json_t *root = json_loads(result.out, 0, NULL);
        data = json_incref(json_object_get(root, "data"));
        json_decref(root);
        if (data && !conforms(data, schema)) {
            json_decref(data);
            data = NULL;
        }
    }
    run_clear(&result);
    return data;
}

/* Tests 12 and 19: a refused manifest reports its detail beside the code,
 * path and message it always had; a valid one reports what it did; the
 * reports of the baseline still conform to the schema. */
static int test_validate_detail(void) {
    json_t *schema = validate_schema();
    CHECK(schema != NULL);
    char template[] = "/tmp/maelys_git_cli_validate_XXXXXX";
    char *root = mkdtemp(template);
    CHECK(root != NULL);
    char directory[256], atom[65];
    memset(atom, 'a', 64u);
    atom[64] = '\0';
    char source[256];
    (void)snprintf(source, sizeof(source), "allow(R) :- request(R), user(\"%s\").\n", atom);
    (void)snprintf(directory, sizeof(directory), "%s/atom", root);
    const char *manifest = write_manifest(directory, source);
    CHECK(manifest != NULL);
    json_t *data = validate(manifest, 2, schema);
    CHECK(data != NULL && json_is_false(json_object_get(data, "valid")));
    json_t *item = json_array_get(json_object_get(data, "diagnostics"), 0u);
    CHECK(!strcmp(json_string_value(json_object_get(item, "code")), "POLICY_INVALID"));
    CHECK(!strcmp(json_string_value(json_object_get(item, "path")), manifest));
    CHECK(strstr(json_string_value(json_object_get(item, "message")), "(64 requested, limit 63)"));
    CHECK(!strcmp(json_string_value(json_object_get(item, "kind")), "capacity"));
    CHECK(!strcmp(json_string_value(json_object_get(item, "diagnostic")), "lexer_string_too_long"));
    CHECK(!strcmp(json_string_value(json_object_get(item, "budget")), "MAX_POLICY_ATOM_BYTES"));
    CHECK(json_integer_value(json_object_get(item, "requested")) == 64);
    CHECK(json_integer_value(json_object_get(item, "limit")) == 63);
    CHECK(!strcmp(json_string_value(json_object_get(item, "file")), "cli.main"));
    CHECK(json_integer_value(json_object_get(item, "line")) == 1);
    json_decref(data);

    (void)snprintf(directory, sizeof(directory), "%s/syntax", root);
    manifest = write_manifest(directory, "allow(R) :- request(R) $.\n");
    data = validate(manifest, 2, schema);
    CHECK(data != NULL);
    item = json_array_get(json_object_get(data, "diagnostics"), 0u);
    CHECK(!strcmp(json_string_value(json_object_get(item, "kind")), "syntax"));
    CHECK(json_object_get(item, "budget") == NULL && json_object_get(item, "requested") == NULL);
    json_decref(data);

    (void)snprintf(directory, sizeof(directory), "%s/missing.json", root);
    data = validate(directory, 2, schema);
    CHECK(data != NULL);
    item = json_array_get(json_object_get(data, "diagnostics"), 0u);
    CHECK(!strcmp(json_string_value(json_object_get(item, "kind")), "manifest"));
    CHECK(json_object_get(item, "line") == NULL);
    json_decref(data);

    data = validate(FIXTURE_DIR "/filters/manifest.json", 0, schema);
    CHECK(data != NULL && json_is_true(json_object_get(data, "valid")));
    CHECK(json_array_size(json_object_get(data, "diagnostics")) == 0u);
    json_decref(data);
    CHECK(test_remove_tree(root));

    FILE *baseline = fopen(FIXTURE_DIR "/validate-baseline.jsonl", "r");
    CHECK(baseline != NULL);
    char line[4096];
    size_t reports = 0u;
    while (fgets(line, sizeof(line), baseline)) {
        json_t *report = json_loads(line, 0, NULL);
        CHECK(report && conforms(json_object_get(report, "data"), schema));
        json_decref(report);
        ++reports;
    }
    (void)fclose(baseline);
    CHECK(reports == 5u);

    ARGV(describe, "describe", "validate", "--json", "--compact");
    run_result_t result;
    CHECK(run(&maelys_git_cli_admin_app, describe, describe_count, &result));
    CHECK(result.code == 0);
    CHECK(strstr(result.out, "\"budget\":{\"type\":\"string\",\"pattern\":\"^[A-Z][A-Z0-9_]*$\"}"));
    run_clear(&result);
    json_decref(schema);
    return 1;
}

int main(void) {
    int passed = 0;
    passed += test_catalogs();
    passed += test_parser();
    passed += test_envelopes();
    passed += test_validate_detail();
    if (passed != 4) return 1;
    (void)printf("ok: %d CLI contract test groups passed\n", passed);
    return 0;
}
