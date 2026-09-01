#include "maelys_git_cli.h"

#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        return 0; \
    } \
} while (0)

static int test_catalog(void) {
    size_t count = 0u;
    const maelys_cli_command_descriptor_t *commands = maelys_cli_commands(&count);
    CHECK(commands != NULL && count >= 20u);
    for (size_t i = 0u; i < count; ++i) {
        const maelys_cli_command_descriptor_t *command = &commands[i];
        CHECK(command->program && *command->program);
        CHECK(command->id && *command->id);
        CHECK(command->pattern && *command->pattern);
        CHECK(command->synopsis && *command->synopsis);
        CHECK(command->purpose && *command->purpose);
        CHECK(command->effect && *command->effect);
        CHECK(command->output_mode && *command->output_mode);
        json_error_t json_error;
        json_t *schema = json_loads(command->output_schema_json, JSON_REJECT_DUPLICATES, &json_error);
        CHECK(schema != NULL && json_is_object(schema));
        if (!strcmp(command->output_mode, "json-envelope") &&
            strcmp(command->id, "help") && strcmp(command->id, "describe")) {
            CHECK(json_is_false(json_object_get(schema, "additionalProperties")));
            CHECK(json_is_array(json_object_get(schema, "required")));
            CHECK(json_array_size(json_object_get(schema, "required")) > 0u);
        }
        json_decref(schema);
        for (size_t j = i + 1u; j < count; ++j)
            CHECK(strcmp(command->program, commands[j].program) || strcmp(command->id, commands[j].id));
        if (command->apply_effect) {
            int has_apply = 0;
            CHECK(!strcmp(command->effect, "preview"));
            for (size_t j = 0u; j < command->option_count; ++j)
                if (!strcmp(command->options[j].name, "apply")) has_apply = 1;
            CHECK(has_apply);
        }
        for (size_t j = 0u; j < command->option_count; ++j) {
            CHECK(command->options[j].name && *command->options[j].name);
            CHECK(command->options[j].summary && *command->options[j].summary);
            for (size_t k = j + 1u; k < command->option_count; ++k)
                CHECK(strcmp(command->options[j].name, command->options[k].name));
        }
    }
    return 1;
}

static int parse(const char *program, int argc, char **argv,
                 maelys_cli_invocation_t *invocation, maelys_cli_error_t *error) {
    memset(invocation, 0, sizeof(*invocation));
    memset(error, 0, sizeof(*error));
    return maelys_cli_parse(program, argc, argv, invocation, error);
}

static int test_parser(void) {
    maelys_cli_invocation_t invocation;
    maelys_cli_error_t error;
    char *plan[] = {"repo", "init", "/tmp", "example.git", "--format", "json", "--compact"};
    CHECK(parse("maelys-git", 7, plan, &invocation, &error));
    CHECK(!strcmp(invocation.command->id, "repo.init"));
    CHECK(invocation.json && invocation.compact && !maelys_cli_flag(&invocation, "apply"));
    CHECK(!strcmp(maelys_cli_operand(&invocation, 1u), "example.git"));

    char *apply[] = {"repo", "init", "/tmp", "example.git", "--apply=false", "--json=false"};
    CHECK(parse("maelys-git", 6, apply, &invocation, &error));
    CHECK(!maelys_cli_flag(&invocation, "apply") && !invocation.json);

    char *literal[] = {"repo", "init", "/tmp", "example.git", "--git", "--literal"};
    CHECK(parse("maelys-git", 6, literal, &invocation, &error));
    CHECK(!strcmp(maelys_cli_option(&invocation, "git"), "--literal"));

    char *unknown[] = {"repo", "init", "/tmp", "example.git", "--token", "x"};
    CHECK(!parse("maelys-git", 6, unknown, &invocation, &error));
    CHECK(!strcmp(error.code, "VALIDATION_FAILED") && strstr(error.message, "--token"));

    char *legacy[] = {"repo", "init", "/tmp", "example.git", "--dry-run"};
    CHECK(!parse("maelys-git", 5, legacy, &invocation, &error));
    CHECK(strstr(error.hint, "--apply"));

    char *stream[] = {"serve", "--manifest", "/tmp/policy.json", "--root", "/tmp", "--format", "json"};
    CHECK(!parse("maelys-git-executor", 7, stream, &invocation, &error));
    CHECK(!strcmp(error.code, "VALIDATION_FAILED") && strstr(error.message, "stream"));

    char *missing[] = {"provision", "--config", "/tmp/config"};
    CHECK(!parse("maelys-git-agent", 3, missing, &invocation, &error));
    CHECK(strstr(error.message, "--agent-id"));

    char *bad_command[] = {"repos", "init"};
    CHECK(!parse("maelys-git", 2, bad_command, &invocation, &error));
    CHECK(!strcmp(error.code, "INVALID_COMMAND"));
    return 1;
}

int main(void) {
    int passed = 0;
    passed += test_catalog();
    passed += test_parser();
    if (passed != 2) return 1;
    (void)printf("ok: %d CLI contract test groups passed\n", passed);
    return 0;
}
