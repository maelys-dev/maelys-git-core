#ifndef MAELYS_GIT_CLI_H
#define MAELYS_GIT_CLI_H

#include "maelys_git.h"

#include <jansson.h>
#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAELYS_CLI_CONTRACT "agent-cli/v2"
#define MAELYS_CLI_SCHEMA_VERSION 2
#define MAELYS_CLI_MAX_OPERANDS 72u
#define MAELYS_CLI_MAX_OPTIONS 32u

typedef enum {
    MAELYS_CLI_VALUE_NONE = 0,
    MAELYS_CLI_VALUE_STRING,
    MAELYS_CLI_VALUE_INTEGER,
    MAELYS_CLI_VALUE_PATH,
    MAELYS_CLI_VALUE_OID,
    MAELYS_CLI_VALUE_SHA256
} maelys_cli_value_kind_t;

typedef struct {
    const char *name;
    int required;
    int variadic;
    const char *summary;
} maelys_cli_operand_descriptor_t;

typedef struct {
    const char *name;
    maelys_cli_value_kind_t value_kind;
    const char *value_name;
    int required;
    int repeatable;
    const char *requires;
    const char *conflicts_with;
    const char *summary;
} maelys_cli_option_descriptor_t;

typedef struct {
    const char *program;
    const char *id;
    const char *pattern;
    const char *synopsis;
    const char *purpose;
    const char *effect;
    const char *apply_effect;
    const char *output_mode;
    const maelys_cli_operand_descriptor_t *operands;
    size_t operand_count;
    const maelys_cli_option_descriptor_t *options;
    size_t option_count;
    const char *output_schema_json;
} maelys_cli_command_descriptor_t;

typedef struct {
    const char *name;
    const char *value;
    int boolean_value;
} maelys_cli_parsed_option_t;

typedef struct {
    const maelys_cli_command_descriptor_t *command;
    const char *operands[MAELYS_CLI_MAX_OPERANDS];
    size_t operand_count;
    maelys_cli_parsed_option_t options[MAELYS_CLI_MAX_OPTIONS];
    size_t option_count;
    int json;
    int compact;
    int non_interactive;
} maelys_cli_invocation_t;

typedef struct {
    char code[64];
    char message[MAELYS_GIT_MAX_ERROR];
    char hint[MAELYS_GIT_MAX_ERROR];
} maelys_cli_error_t;

const maelys_cli_command_descriptor_t *maelys_cli_commands(size_t *out_count);
const maelys_cli_command_descriptor_t *maelys_cli_find_command(
    const char *program, const char *id);

int maelys_cli_parse(const char *program,
                     int argc,
                     char **argv,
                     maelys_cli_invocation_t *out,
                     maelys_cli_error_t *error);
const char *maelys_cli_operand(const maelys_cli_invocation_t *invocation, size_t index);
const char *maelys_cli_option(const maelys_cli_invocation_t *invocation, const char *name);
int maelys_cli_flag(const maelys_cli_invocation_t *invocation, const char *name);

int maelys_cli_emit_success(const maelys_cli_invocation_t *invocation,
                            json_t *data,
                            const char *human,
                            int exit_code);
int maelys_cli_emit_error(const maelys_cli_invocation_t *invocation,
                          const maelys_cli_error_t *error,
                          int exit_code);
int maelys_cli_emit_maelys_error(const maelys_cli_invocation_t *invocation,
                                 maelys_git_result_t result,
                                 const maelys_git_error_t *error);
int maelys_cli_emit_describe(const maelys_cli_invocation_t *invocation);
int maelys_cli_emit_help(const maelys_cli_invocation_t *invocation);

#ifdef __cplusplus
}
#endif

#endif
