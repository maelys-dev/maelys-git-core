/* Contract tests of the five product catalogs on libmaelys_cli: catalog
 * validity, typed parsing and end-to-end envelopes through maelys_cli_run. */
#include "maelys_git_agent.h"
#include "maelys_git_cli.h"
#include "maelys_git_receipt.h"
#include "test_json.h"
#include "test_support.h"

#include <maelys/cli/digest.h>
#include <maelys/json.h>
#include <regex.h>
#include <time.h>

static const maelys_cli_app_t *const apps[] = {
    &maelys_git_cli_admin_app,
    &maelys_git_cli_agent_app,
    &maelys_git_cli_executor_app,
    &maelys_git_cli_shell_app,
    &maelys_git_cli_hook_app,
};
#define APP_COUNT (sizeof(apps) / sizeof(apps[0]))

/* A value of a parsed document. */
typedef struct {
    const maelys_json_document_t *document;
    maelys_json_value_t value;
} node_t;

static size_t schema_depth(node_t schema);

static int test_catalogs(void) {
    size_t deepest = 0u;
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
            /* maelys-json refuses duplicate keys. */
            maelys_json_document_t *schema = tj_parse(command->output_schema_json);
            CHECK(schema != NULL && tj_type(schema, "") == MAELYS_JSON_TYPE_OBJECT);
            /* The data writer's depth admits every value the schema describes. */
            node_t root = {schema, maelys_json_document_root(schema)};
            size_t depth = schema_depth(root);
            CHECK(depth > 0u && depth <= MG_JSON_DATA_DEPTH);
            if (depth > deepest) deepest = depth;
            if (command->output == MAELYS_CLI_OUTPUT_ENVELOPE) {
                CHECK(tj_boolean(schema, "additionalProperties") == 0);
                CHECK(tj_type(schema, "required") == MAELYS_JSON_TYPE_ARRAY && tj_size(schema, "required") > 0u);
            } else {
                CHECK(command->output == MAELYS_CLI_OUTPUT_STREAM);
                CHECK(command->protocol && *command->protocol);
            }
            tj_release(schema);
            if (command->apply_effect != MAELYS_CLI_EFFECT_NONE)
                CHECK(command->effect == MAELYS_CLI_EFFECT_PREVIEW);
            CHECK((command->handler != NULL) != (command->unavailable != NULL));
        }
    }
    CHECK(deepest == 4u);
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

/* Checks a value against the subset of JSON Schema that the output schemas of
 * validate and authorize use; any other keyword fails, so that nothing is
 * skipped unnoticed. As in JSON Schema, a keyword about strings, numbers,
 * objects or arrays constrains only values of that type. */
static maelys_json_type_t type_of(node_t node) {
    return node.value == MAELYS_JSON_VALUE_NONE ? MAELYS_JSON_TYPE_NONE
                                                : maelys_json_value_type(node.document, node.value);
}

/* The string of `node`, or NULL when it is not one. */
static const char *string_of(node_t node) {
    maelys_json_view_t view;
    return type_of(node) == MAELYS_JSON_TYPE_STRING &&
           maelys_json_value_string(node.document, node.value, &view) == MAELYS_JSON_OK ? view.data : NULL;
}

/* An integer is a number written without fraction or exponent. */
static int is_integer(node_t node, int64_t *out) {
    maelys_json_view_t lexeme;
    return type_of(node) == MAELYS_JSON_TYPE_NUMBER &&
           maelys_json_value_number_text(node.document, node.value, &lexeme) == MAELYS_JSON_OK &&
           !memchr(lexeme.data, '.', lexeme.size) && !memchr(lexeme.data, 'e', lexeme.size) &&
           !memchr(lexeme.data, 'E', lexeme.size) &&
           maelys_json_value_i64(node.document, node.value, out) == MAELYS_JSON_OK;
}

static int is_false(node_t node) {
    int flag = 1;
    return type_of(node) == MAELYS_JSON_TYPE_BOOLEAN &&
           maelys_json_value_boolean(node.document, node.value, &flag) == MAELYS_JSON_OK && !flag;
}

static node_t member(node_t object, const char *name) {
    node_t out = {object.document, MAELYS_JSON_VALUE_NONE};
    if (type_of(object) == MAELYS_JSON_TYPE_OBJECT &&
        maelys_json_object_get(object.document, object.value, name, &out.value) != MAELYS_JSON_OK)
        out.value = MAELYS_JSON_VALUE_NONE;
    return out;
}

static size_t count_of(node_t node) {
    size_t size = 0u;
    if (type_of(node) == MAELYS_JSON_TYPE_ARRAY) (void)maelys_json_array_size(node.document, node.value, &size);
    else if (type_of(node) == MAELYS_JSON_TYPE_OBJECT)
        (void)maelys_json_object_size(node.document, node.value, &size);
    return size;
}

static node_t element(node_t array, size_t index) {
    node_t out = {array.document, MAELYS_JSON_VALUE_NONE};
    if (maelys_json_array_get(array.document, array.value, index, &out.value) != MAELYS_JSON_OK)
        out.value = MAELYS_JSON_VALUE_NONE;
    return out;
}

/* The member at `index` of an object, and its name. */
static node_t member_at(node_t object, size_t index, const char **name) {
    node_t out = {object.document, MAELYS_JSON_VALUE_NONE};
    maelys_json_view_t key;
    *name = NULL;
    if (maelys_json_object_member_at(object.document, object.value, index, &key, &out.value) == MAELYS_JSON_OK)
        *name = key.data;
    else
        out.value = MAELYS_JSON_VALUE_NONE;
    return out;
}

static int equal(node_t a, node_t b) {
    return type_of(a) != MAELYS_JSON_TYPE_NONE && type_of(b) != MAELYS_JSON_TYPE_NONE &&
           tj_value_equal(a.document, a.value, b.document, b.value);
}

/* Checks a value against the subset of JSON Schema that the output schemas of
 * validate and authorize use; any other keyword fails, so that nothing is
 * skipped unnoticed. As in JSON Schema, a keyword about strings, numbers,
 * objects or arrays constrains only values of that type. */
static int of_type(node_t value, const char *type) {
    int64_t integer;
    maelys_json_type_t kind = type_of(value);
    return !type ? 0
         : !strcmp(type, "object") ? kind == MAELYS_JSON_TYPE_OBJECT
         : !strcmp(type, "array") ? kind == MAELYS_JSON_TYPE_ARRAY
         : !strcmp(type, "string") ? kind == MAELYS_JSON_TYPE_STRING
         : !strcmp(type, "boolean") ? kind == MAELYS_JSON_TYPE_BOOLEAN
         : !strcmp(type, "integer") ? is_integer(value, &integer)
         : !strcmp(type, "null") ? kind == MAELYS_JSON_TYPE_NULL : 0;
}

static int of_type_name(node_t rule, const char *type) {
    if (string_of(rule)) return !strcmp(string_of(rule), type);
    for (size_t i = 0u; i < count_of(rule) && type_of(rule) == MAELYS_JSON_TYPE_ARRAY; ++i)
        if (string_of(element(rule, i)) && !strcmp(string_of(element(rule, i)), type)) return 1;
    return 0;
}

static int conforms(node_t value, node_t schema) {
    for (size_t k = 0u; k < count_of(schema); ++k) {
        const char *keyword;
        node_t rule = member_at(schema, k, &keyword);
        if (!keyword) return 0;
        if (!strcmp(keyword, "type")) {
            int ok = string_of(rule) ? of_type(value, string_of(rule)) : 0;
            if (type_of(rule) == MAELYS_JSON_TYPE_ARRAY)
                for (size_t i = 0u; i < count_of(rule); ++i)
                    ok = ok || of_type(value, string_of(element(rule, i)));
            if (!ok) return 0;
        } else if (!strcmp(keyword, "required")) {
            if (type_of(value) == MAELYS_JSON_TYPE_OBJECT)
                for (size_t i = 0u; i < count_of(rule); ++i) {
                    const char *name = string_of(element(rule, i));
                    if (!name || type_of(member(value, name)) == MAELYS_JSON_TYPE_NONE) return 0;
                }
        } else if (!strcmp(keyword, "properties")) {
            if (type_of(value) == MAELYS_JSON_TYPE_OBJECT)
                for (size_t i = 0u; i < count_of(value); ++i) {
                    const char *name;
                    node_t item = member_at(value, i, &name);
                    node_t property = member(rule, name ? name : "");
                    int allowed = !is_false(member(schema, "additionalProperties"));
                    if (type_of(property) != MAELYS_JSON_TYPE_NONE ? !conforms(item, property) : !allowed)
                        return 0;
                }
        } else if (!strcmp(keyword, "items")) {
            if (type_of(value) == MAELYS_JSON_TYPE_ARRAY)
                for (size_t i = 0u; i < count_of(value); ++i)
                    if (!conforms(element(value, i), rule)) return 0;
        } else if (!strcmp(keyword, "enum")) {
            int found = 0;
            for (size_t i = 0u; i < count_of(rule); ++i) found = found || equal(value, element(rule, i));
            if (!found) return 0;
        } else if (!strcmp(keyword, "const")) {
            if (!equal(value, rule)) return 0;
        } else if (!strcmp(keyword, "oneOf")) {
            size_t matches = 0u;
            for (size_t i = 0u; i < count_of(rule); ++i) matches += (size_t)conforms(value, element(rule, i));
            if (matches != 1u) return 0;
        } else if (!strcmp(keyword, "pattern")) {
            if (type_of(value) != MAELYS_JSON_TYPE_STRING) continue;
            regex_t expression;
            if (!string_of(rule) || regcomp(&expression, string_of(rule), REG_EXTENDED | REG_NOSUB) != 0) return 0;
            int matched = regexec(&expression, string_of(value), 0u, NULL, 0) == 0;
            regfree(&expression);
            if (!matched) return 0;
        } else if (!strcmp(keyword, "minimum")) {
            int64_t number, minimum;
            if (!is_integer(rule, &minimum)) return 0;
            if (is_integer(value, &number) && number < minimum) return 0;
        } else if (!strcmp(keyword, "minLength")) {
            int64_t minimum;
            maelys_json_view_t view;
            if (!is_integer(rule, &minimum)) return 0;
            /* A length in bytes. */
            if (type_of(value) == MAELYS_JSON_TYPE_STRING &&
                maelys_json_value_string(value.document, value.value, &view) == MAELYS_JSON_OK &&
                view.size < (size_t)minimum)
                return 0;
        } else if (strcmp(keyword, "additionalProperties") != 0 && strcmp(keyword, "description") != 0) {
            (void)fprintf(stderr, "schema keyword not checked: %s\n", keyword);
            return 0;
        }
    }
    return 1;
}

static node_t root_of(const maelys_json_document_t *document) {
    node_t node = {document, document ? maelys_json_document_root(document) : MAELYS_JSON_VALUE_NONE};
    return node;
}

/* `data` of an envelope conforms to `schema`. */
static int data_conforms(const maelys_json_document_t *envelope, const maelys_json_document_t *schema) {
    return conforms(member(root_of(envelope), "data"), root_of(schema));
}

/* The containers nested in the deepest value `schema` describes: an object
 * or an array counts one, around its deepest member or element; oneOf takes
 * its deepest option. */
static size_t schema_depth(node_t schema) {
    size_t inner = 0u, own = 0u, option = 0u;
    for (size_t k = 0u; k < count_of(schema); ++k) {
        const char *keyword;
        node_t rule = member_at(schema, k, &keyword);
        size_t depth;
        if (!keyword) continue;
        if (!strcmp(keyword, "type")) {
            if (of_type_name(rule, "object") || of_type_name(rule, "array")) own = 1u;
        } else if (!strcmp(keyword, "properties")) {
            own = 1u;
            for (size_t i = 0u; i < count_of(rule); ++i) {
                const char *name;
                if ((depth = schema_depth(member_at(rule, i, &name))) > inner) inner = depth;
            }
        } else if (!strcmp(keyword, "items")) {
            own = 1u;
            if ((depth = schema_depth(rule)) > inner) inner = depth;
        } else if (!strcmp(keyword, "oneOf")) {
            for (size_t i = 0u; i < count_of(rule); ++i)
                if ((depth = schema_depth(element(rule, i))) > option) option = depth;
        }
    }
    return own + inner > option ? own + inner : option;
}

static maelys_json_document_t *output_schema(const char *id) {
    const maelys_cli_app_t *admin = &maelys_git_cli_admin_app;
    for (size_t i = 0u; i < admin->command_count; ++i)
        if (!strcmp(admin->commands[i].id, id))
            return tj_parse(admin->commands[i].output_schema_json);
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

/* Runs validate on a manifest and returns its envelope, the data checked
 * against the schema. */
static maelys_json_document_t *validate(const char *manifest, int expected_exit,
                                        const maelys_json_document_t *schema) {
    run_result_t result;
    ARGV(argv, "validate", (char *)manifest, "--json", "--compact");
    if (!run(&maelys_git_cli_admin_app, argv, argv_count, &result)) return NULL;
    maelys_json_document_t *envelope = NULL;
    if (result.code == expected_exit && result.err[0] == '\0') {
        envelope = tj_parse(result.out);
        if (envelope && !data_conforms(envelope, schema)) {
            tj_release(envelope);
            envelope = NULL;
        }
    }
    run_clear(&result);
    return envelope;
}

/* Tests 12 and 19: a refused manifest reports its detail beside the code,
 * path and message it always had; a valid one reports what it did; the
 * reports of the baseline still conform to the schema. */
static int test_validate_detail(void) {
    maelys_json_document_t *schema = output_schema("validate");
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
    maelys_json_document_t *data = validate(manifest, 2, schema);
    CHECK(data != NULL && tj_boolean(data, "data.valid") == 0);
    CHECK(tj_string_is(data, "data.diagnostics.0.code", "POLICY_INVALID"));
    CHECK(tj_string_is(data, "data.diagnostics.0.path", manifest));
    CHECK(tj_string(data, "data.diagnostics.0.message") &&
          strstr(tj_string(data, "data.diagnostics.0.message"), "(64 requested, limit 63)"));
    CHECK(tj_string_is(data, "data.diagnostics.0.kind", "capacity"));
    CHECK(tj_string_is(data, "data.diagnostics.0.diagnostic", "lexer_string_too_long"));
    CHECK(tj_string_is(data, "data.diagnostics.0.budget", "MAX_POLICY_ATOM_BYTES"));
    CHECK(tj_i64(data, "data.diagnostics.0.requested", 0) == 64);
    CHECK(tj_i64(data, "data.diagnostics.0.limit", 0) == 63);
    CHECK(tj_string_is(data, "data.diagnostics.0.file", "cli.main"));
    CHECK(tj_i64(data, "data.diagnostics.0.line", 0) == 1);
    tj_release(data);

    (void)snprintf(directory, sizeof(directory), "%s/syntax", root);
    manifest = write_manifest(directory, "allow(R) :- request(R) $.\n");
    data = validate(manifest, 2, schema);
    CHECK(data != NULL);
    CHECK(tj_string_is(data, "data.diagnostics.0.kind", "syntax"));
    CHECK(!tj_has(data, "data.diagnostics.0.budget") && !tj_has(data, "data.diagnostics.0.requested"));
    tj_release(data);

    (void)snprintf(directory, sizeof(directory), "%s/missing.json", root);
    data = validate(directory, 2, schema);
    CHECK(data != NULL);
    CHECK(tj_string_is(data, "data.diagnostics.0.kind", "manifest"));
    CHECK(tj_has(data, "data.diagnostics.0.code") && !tj_has(data, "data.diagnostics.0.line"));
    tj_release(data);

    data = validate(FIXTURE_DIR "/filters/manifest.json", 0, schema);
    CHECK(data != NULL && tj_boolean(data, "data.valid") == 1);
    CHECK(tj_type(data, "data.diagnostics") == MAELYS_JSON_TYPE_ARRAY && tj_size(data, "data.diagnostics") == 0u);
    tj_release(data);
    CHECK(test_remove_tree(root));

    FILE *baseline = fopen(FIXTURE_DIR "/validate-baseline.jsonl", "r");
    CHECK(baseline != NULL);
    char line[4096];
    size_t reports = 0u;
    while (fgets(line, sizeof(line), baseline)) {
        maelys_json_document_t *report = tj_parse(line);
        CHECK(report && data_conforms(report, schema));
        tj_release(report);
        ++reports;
    }
    (void)fclose(baseline);
    CHECK(reports == 5u);
    /* The checker refuses what each keyword forbids, and accepts the same
     * diagnostic within its rules. */
#define DIAGNOSTIC(extra) "[{\"code\":\"c\",\"path\":\"p\",\"message\":\"m\"" extra "}]"
    static const char *const refused[][2] = {
        {"valid", "\"yes\""}, {"surprise", "true"}, {"diagnostics", NULL},
        {"diagnostics", DIAGNOSTIC(",\"requested\":1.0")}, {"diagnostics", DIAGNOSTIC(",\"requested\":-1")},
        {"diagnostics", DIAGNOSTIC(",\"kind\":\"other\"")}, {"diagnostics", DIAGNOSTIC(",\"budget\":\"bad\"")},
        {"diagnostics", DIAGNOSTIC(",\"diagnostic\":\"\"")}, {"diagnostics", DIAGNOSTIC(",\"other\":1")},
        {"diagnostics", "[{\"code\":\"c\",\"path\":\"p\"}]"},
        {"diagnostics", DIAGNOSTIC(",\"requested\":1,\"kind\":\"capacity\",\"budget\":\"MAX_X\",\"diagnostic\":\"d\"")}};
    for (size_t i = 0u; i < sizeof(refused) / sizeof(refused[0]); ++i) {
        int accepted = i + 1u == sizeof(refused) / sizeof(refused[0]);
        char *original = tj_extract(line, "data");
        char *changed = tj_with(original, refused[i][0], refused[i][1]);
        char *envelope = tj_with(line, "data", changed);
        maelys_json_document_t *report = tj_parse(envelope);
        CHECK(report && data_conforms(report, schema) == accepted);
        tj_release(report);
        free(envelope); free(changed); free(original);
    }
#undef DIAGNOSTIC
    maelys_json_document_t *last = tj_parse(line);
    CHECK(last && data_conforms(last, schema));
    tj_release(last);

    ARGV(describe, "describe", "validate", "--json", "--compact");
    run_result_t result;
    CHECK(run(&maelys_git_cli_admin_app, describe, describe_count, &result));
    CHECK(result.code == 0);
    CHECK(strstr(result.out, "\"budget\":{\"type\":\"string\",\"pattern\":\"^[A-Z][A-Z0-9_]*$\"}"));
    run_clear(&result);
    tj_release(schema);
    return 1;
}

/* ---- authorize: receipts ------------------------------------------------------- */

/* The digest of the receipt at `path` in an envelope: rewritten to its
 * canonical bytes by maelys-json, then verified. */
static int receipt_digest(const maelys_json_document_t *envelope, const char *path, char out[65]) {
    /* The bounds of a receipt: the verifier refuses anything larger. */
    const maelys_json_limits_t limits = {.maximum_bytes = MAELYS_GIT_RECEIPT_MAX_BYTES,
                                         .maximum_depth = 4u, .maximum_tokens = 512u};
    maelys_json_value_t receipt = tj_root_at(envelope, path);
    maelys_json_writer_t *writer = NULL;
    char *bytes = NULL;
    size_t size = 0u;
    int ok = receipt != MAELYS_JSON_VALUE_NONE &&
        maelys_json_writer_create(MAELYS_JSON_PROFILE_RFC8259, &limits, 0u, &writer) == MAELYS_JSON_OK &&
        maelys_json_writer_value(writer, envelope, receipt) == MAELYS_JSON_OK &&
        maelys_json_writer_finish(writer, &bytes, &size) == MAELYS_JSON_OK;
    maelys_git_error_t error;
    ok = ok && maelys_git_receipt_verify(bytes, size, out, &error) == MAELYS_GIT_OK;
    free(bytes);
    maelys_json_writer_release(writer);
    return ok;
}

/* Runs authorize and returns its envelope, the data checked against `schema`
 * when one is given. */
static maelys_json_document_t *authorize_data(char **argv, int argc, int expected_exit,
                                              const maelys_json_document_t *schema) {
    run_result_t result;
    if (!run(&maelys_git_cli_admin_app, argv, argc, &result)) return NULL;
    maelys_json_document_t *envelope = NULL;
    if (result.code == expected_exit && result.err[0] == '\0') {
        envelope = tj_parse(result.out);
        if (envelope && schema && !data_conforms(envelope, schema)) {
            tj_release(envelope);
            envelope = NULL;
        }
    }
    run_clear(&result);
    return envelope;
}

/* Test 11: the four members of authorize are unchanged; the receipt and its
 * digest are added; --explain adds the text, before -- only. */
static int test_authorize_receipt(void) {
    maelys_json_document_t *schema = output_schema("authorize");
    CHECK(schema != NULL);
    char manifest[] = FIXTURE_DIR "/../../../policies/manifest.json";
    ARGV(plain, "authorize", manifest, "mallory", "example.git", "push", "refs/heads/main",
         "--json", "--compact");
    maelys_json_document_t *data = authorize_data(plain, plain_count, 0, schema);
    CHECK(data != NULL);
    CHECK(tj_boolean(data, "data.allowed") == 0);
    CHECK(tj_boolean(data, "data.explicitDeny") == 1);
    CHECK(tj_i64(data, "data.matchedPolicy", -1) == 0);
    CHECK(tj_string_is(data, "data.reason", "explicit deny from policy maelys-git.example.authorization"));
    CHECK(!tj_has(data, "data.explanationText"));
    char digest[65];
    CHECK(receipt_digest(data, "data.receipt", digest));
    CHECK(tj_string_is(data, "data.receiptSha256", digest));
    tj_release(data);

    ARGV(explained, "authorize", manifest, "mallory", "example.git", "push", "refs/heads/main",
         "--explain", "--json", "--compact");
    data = authorize_data(explained, explained_count, 0, schema);
    CHECK(data != NULL);
    const char *text = tj_string(data, "data.explanationText");
    CHECK(text && !strncmp(text, "MAELYS-DATALOG-v2\n", 18u));
    char text_sha256[MAELYS_CLI_SHA256_HEX_SIZE];
    maelys_cli_sha256_hex(text, strlen(text), text_sha256);
    CHECK(tj_string_is(data, "data.receipt.explanation.textSha256", text_sha256));
    CHECK(tj_i64(data, "data.receipt.explanation.textBytes", -1) == (int64_t)strlen(text));
    tj_release(data);

    /* After --, --explain is a path like any other word. */
    ARGV(after, "authorize", manifest, "mallory", "example.git", "push", "refs/heads/main",
         "--json", "--compact", "--", "--explain");
    data = authorize_data(after, after_count, 0, schema);
    CHECK(data != NULL && !tj_has(data, "data.explanationText"));
    CHECK(tj_i64(data, "data.receipt.request.pathCount", 0) == 1);
    tj_release(data);

    run_result_t result;
    ARGV(unknown, "authorize", manifest, "mallory", "example.git", "push", "--explained", "--json",
         "--compact");
    CHECK(run(&maelys_git_cli_admin_app, unknown, unknown_count, &result));
    CHECK(result.code == 1 && strstr(result.err, "\"code\":\"VALIDATION_FAILED\""));
    run_clear(&result);

    ARGV(describe, "describe", "authorize", "--json", "--compact");
    CHECK(run(&maelys_git_cli_admin_app, describe, describe_count, &result));
    CHECK(result.code == 0 && strstr(result.out, "\"long\":\"--explain\"") &&
          strstr(result.out, "\"receiptSha256\""));
    run_clear(&result);
    tj_release(schema);
    return 1;
}

/* ---- the pinned engine: variable identity and strata ----------------------------- */

/* authorize of alice on example.git, pushing refs/heads/main with one path,
 * under the single policy SOURCE written in DIRECTORY: its data. */
static maelys_json_document_t *decide(const char *directory, const char *source,
                                      const maelys_json_document_t *schema) {
    const char *manifest = write_manifest(directory, source);
    if (!manifest) return NULL;
    ARGV(argv, "authorize", (char *)manifest, "alice", "example.git", "push", "refs/heads/main",
         "--json", "--compact", "--", "notes.txt");
    return authorize_data(argv, argv_count, 0, schema);
}

/* Tests 1 to 3 of GIT-C07: the engine identifies a variable by its complete
 * name. Under 0.23.1, Ab and Ac were one variable, so these rules required a
 * user equal to the path and derived nothing: the allow failed and the deny
 * did not hold. One-letter names decide as they always did. */
static int test_variable_identity(void) {
    maelys_json_document_t *schema = output_schema("authorize");
    char template[] = "/tmp/maelys_git_cli_variables_XXXXXX";
    char *root = mkdtemp(template);
    CHECK(schema && root);
    static const struct {
        const char *name, *source;
        int allowed, explicit_deny;
    } cases[] = {
        {"allow-long", "allow(R) :- request(R), user(Ab), path(Ac).\n", 1, 0},
        {"deny-long", "allow(R) :- request(R).\ndeny(R) :- request(R), user(Ab), path(Ac).\n", 0, 1},
        {"allow-short", "allow(R) :- request(R), user(A), path(B).\n", 1, 0},
        {"deny-short", "allow(R) :- request(R).\ndeny(R) :- request(R), user(A), path(B).\n", 0, 1},
    };
    for (size_t i = 0u; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        char directory[256];
        (void)snprintf(directory, sizeof(directory), "%s/%s", root, cases[i].name);
        maelys_json_document_t *data = decide(directory, cases[i].source, schema);
        if (!data) (void)fprintf(stderr, "%s: no decision\n", cases[i].name);
        CHECK(data != NULL);
        CHECK(tj_boolean(data, "data.allowed") == cases[i].allowed);
        CHECK(tj_boolean(data, "data.explicitDeny") == cases[i].explicit_deny);
        if (cases[i].explicit_deny) CHECK(tj_i64(data, "data.matchedPolicy", -1) == 0);
        tj_release(data);
    }
    CHECK(test_remove_tree(root));
    tj_release(schema);
    return 1;
}

/* The first diagnostic of validate on SOURCE, checked against the schema. */
static maelys_json_document_t *refused(const char *directory, const char *source,
                                       const maelys_json_document_t *schema) {
    const char *manifest = write_manifest(directory, source);
    return manifest ? validate(manifest, 2, schema) : NULL;
}

/* Tests 4 and 5 of GIT-C07: the engine's capacities as validate reports
 * them. A 27th variable name is refused (MAX_RULE_VARIABLES); four stacked
 * negations need five strata and are refused as a capacity (MAX_STRATA),
 * three are accepted; a negation cycle stays a semantic failure, without a
 * budget. */
static int test_engine_capacities(void) {
    maelys_json_document_t *schema = output_schema("validate");
    char template[] = "/tmp/maelys_git_cli_capacities_XXXXXX";
    char *root = mkdtemp(template);
    CHECK(schema && root);
    char directory[256], source[2048];

    /* R and 25 names, then R and 26: 26 and 27 distinct names, packed four
     * to a literal to stay within the eight literals of a rule body. */
    for (int names = 26; names <= 27; ++names) {
        size_t used = (size_t)snprintf(source, sizeof(source), "allow(R) :- request(R)");
        for (int v = 1; v <= 24; v += 4)
            used += (size_t)snprintf(source + used, sizeof(source) - used,
                                     ", push_request(V%02d, V%02d, V%02d, V%02d)", v, v + 1, v + 2, v + 3);
        (void)snprintf(source + used, sizeof(source) - used, ", effective_access(V25, V%02d, V25).\n",
                       names == 27 ? 26 : 25);
        (void)snprintf(directory, sizeof(directory), "%s/variables-%d", root, names);
        if (names == 26) {
            const char *manifest = write_manifest(directory, source);
            maelys_json_document_t *data = manifest ? validate(manifest, 0, schema) : NULL;
            CHECK(data && tj_boolean(data, "data.valid") == 1);
            tj_release(data);
            continue;
        }
        maelys_json_document_t *data = refused(directory, source, schema);
        CHECK(data && tj_boolean(data, "data.valid") == 0);
        CHECK(tj_string_is(data, "data.diagnostics.0.kind", "capacity"));
        CHECK(tj_string_is(data, "data.diagnostics.0.budget", "MAX_RULE_VARIABLES"));
        CHECK(tj_i64(data, "data.diagnostics.0.requested", 0) == 27);
        CHECK(tj_i64(data, "data.diagnostics.0.limit", 0) == 26);
        tj_release(data);
    }

    /* Each derived predicate negates the previous one. */
    static const char chain[] =
        "has_ref_write(R, R) :- request(R).\n"
        "has_push_access(R, R) :- request(R), not(has_ref_write(R, R)).\n"
        "vref_count_exceeded(R, R) :- request(R), not(has_push_access(R, R)).\n"
        "vref_new_count_exceeded(R, R) :- request(R), not(vref_count_exceeded(R, R)).\n";
    (void)snprintf(source, sizeof(source), "%sallow(R) :- request(R), vref_new_count_exceeded(R, R).\n",
                   chain);
    (void)snprintf(directory, sizeof(directory), "%s/negations-3", root);
    const char *manifest = write_manifest(directory, source);
    maelys_json_document_t *data = manifest ? validate(manifest, 0, schema) : NULL;
    CHECK(data && tj_boolean(data, "data.valid") == 1);
    tj_release(data);

    (void)snprintf(source, sizeof(source),
                   "%svref_new_binary_exceeded(R, R) :- request(R), not(vref_new_count_exceeded(R, R)).\n"
                   "allow(R) :- request(R), vref_new_binary_exceeded(R, R).\n", chain);
    (void)snprintf(directory, sizeof(directory), "%s/negations-4", root);
    data = refused(directory, source, schema);
    CHECK(data && tj_boolean(data, "data.valid") == 0);
    CHECK(tj_string_is(data, "data.diagnostics.0.kind", "capacity"));
    CHECK(tj_string_is(data, "data.diagnostics.0.diagnostic", "policy_not_stratifiable"));
    CHECK(tj_string_is(data, "data.diagnostics.0.budget", "MAX_STRATA"));
    CHECK(tj_i64(data, "data.diagnostics.0.requested", 0) == 5);
    CHECK(tj_i64(data, "data.diagnostics.0.limit", 0) == 4);
    tj_release(data);

    (void)snprintf(directory, sizeof(directory), "%s/negation-cycle", root);
    data = refused(directory,
                   "has_ref_write(R, R) :- request(R), not(has_push_access(R, R)).\n"
                   "has_push_access(R, R) :- request(R), not(has_ref_write(R, R)).\n"
                   "allow(R) :- request(R), has_ref_write(R, R).\n", schema);
    CHECK(data && tj_boolean(data, "data.valid") == 0);
    CHECK(tj_string_is(data, "data.diagnostics.0.kind", "semantics"));
    CHECK(tj_string_is(data, "data.diagnostics.0.diagnostic", "policy_not_stratifiable"));
    CHECK(!tj_has(data, "data.diagnostics.0.budget") && !tj_has(data, "data.diagnostics.0.requested") &&
          !tj_has(data, "data.diagnostics.0.limit"));
    tj_release(data);

    CHECK(test_remove_tree(root));
    tj_release(schema);
    return 1;
}

/* Test 15: one request through the command line, the agent and the API gives
 * one receipt; the request id is set alike on the three. */
static int test_same_receipt(void) {
    char manifest[] = FIXTURE_DIR "/../../../policies/manifest.json";
    ARGV(cli, "authorize", manifest, "mallory", "example.git", "push", "refs/heads/main",
         "--json", "--compact");
    maelys_json_document_t *data = authorize_data(cli, cli_count, 0, NULL);
    CHECK(data != NULL && tj_string(data, "data.receiptSha256"));
    char from_cli[65];
    (void)snprintf(from_cli, sizeof(from_cli), "%s", tj_string(data, "data.receiptSha256"));
    tj_release(data);

    maelys_git_policy_t *policy = NULL;
    maelys_git_error_t error;
    CHECK(maelys_git_policy_open(manifest, &policy, &error) == MAELYS_GIT_OK);
    int64_t now = (int64_t)time(NULL) * 1000;
    mg_json_t command;
    mg_json_begin(&command, MG_JSON_DATA);
    mg_json_object(&command, NULL);
    mg_json_string(&command, "protocol", "maelys-git-agent/1");
    mg_json_string(&command, "message_id", "cli");
    mg_json_string(&command, "agent_id", "agent-1");
    mg_json_string(&command, "type", "command");
    mg_json_string(&command, "command", "authorize");
    mg_json_string(&command, "principal", "mallory");
    mg_json_string(&command, "repository", "example.git");
    mg_json_i64(&command, "issued_at_ms", now);
    mg_json_i64(&command, "expires_at_ms", now + 60000);
    mg_json_object(&command, "payload");
    mg_json_string(&command, "operation", "push");
    mg_json_string(&command, "ref", "refs/heads/main");
    mg_json_end_object(&command);
    mg_json_end_object(&command);
    char *line = NULL;
    CHECK(mg_json_finish(&command, &line, NULL) == MAELYS_JSON_OK);
    size_t length = strlen(line);
    char *input_text = malloc(length + 2u);
    CHECK(input_text != NULL);
    (void)snprintf(input_text, length + 2u, "%s\n", line);
    free(line);
    FILE *input = fmemopen(input_text, length + 1u, "r");
    char *output_text = NULL;
    size_t output_size = 0u;
    FILE *output = open_memstream(&output_text, &output_size);
    CHECK(input && output);
    CHECK(maelys_git_agent_serve(policy, "/usr/bin/git", "/tmp", input, output, stderr, &error) == MAELYS_GIT_OK);
    (void)fclose(input);
    (void)fclose(output);
    free(input_text);
    maelys_json_document_t *agent = tj_parse(output_text);
    free(output_text);
    CHECK(tj_string_is(agent, "status", "denied"));
    CHECK(tj_i64(agent, "payload.matched_policy", -1) == 0);
    CHECK(!tj_has(agent, "payload.explanation_text"));
    char from_agent[65];
    CHECK(receipt_digest(agent, "payload.receipt", from_agent));
    CHECK(tj_string_is(agent, "payload.receipt_sha256", from_agent));
    tj_release(agent);

    maelys_git_policy_request_t request = {.request_id = "cli", .principal = "mallory",
        .repository = "example.git", .operation = "push", .ref_name = "refs/heads/main"};
    maelys_git_policy_decision_t decision;
    maelys_git_receipt_t receipt;
    CHECK(maelys_git_policy_authorize_receipt(policy, &request, MAELYS_GIT_EXPLAIN_NEVER, NULL, 0u,
                                              &decision, &receipt, &error) == MAELYS_GIT_OK);
    char *bytes = NULL;
    size_t size = 0u;
    char from_api[65];
    CHECK(maelys_git_receipt_serialize(&receipt, &bytes, &size, from_api, &error) == MAELYS_GIT_OK);
    free(bytes);
    maelys_git_policy_close(policy);
    CHECK(!strcmp(from_cli, from_agent) && !strcmp(from_cli, from_api));
    return 1;
}

int main(void) {
    int passed = 0;
    passed += test_catalogs();
    passed += test_parser();
    passed += test_envelopes();
    passed += test_validate_detail();
    passed += test_authorize_receipt();
    passed += test_same_receipt();
    passed += test_variable_identity();
    passed += test_engine_capacities();
    if (passed != 8) return 1;
    (void)printf("ok: %d CLI contract test groups passed\n", passed);
    return 0;
}
