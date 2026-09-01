#include "maelys_git_cli.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

static void cli_error(maelys_cli_error_t *error,
                      const char *code,
                      const char *hint,
                      const char *format,
                      ...) {
    if (!error) return;
    memset(error, 0, sizeof(*error));
    (void)snprintf(error->code, sizeof(error->code), "%s", code);
    if (hint) (void)snprintf(error->hint, sizeof(error->hint), "%s", hint);
    va_list arguments;
    va_start(arguments, format);
    (void)vsnprintf(error->message, sizeof(error->message), format, arguments);
    va_end(arguments);
}

static size_t pattern_words(const char *pattern) {
    size_t count = 0u;
    int in_word = 0;
    for (const char *p = pattern; *p; ++p) {
        if (*p == ' ') in_word = 0;
        else if (!in_word) { ++count; in_word = 1; }
    }
    return count;
}

static int pattern_matches(const char *pattern, int argc, char **argv) {
    const char *cursor = pattern;
    int index = 0;
    while (*cursor) {
        const char *end = strchr(cursor, ' ');
        size_t length = end ? (size_t)(end - cursor) : strlen(cursor);
        if (index >= argc || strlen(argv[index]) != length || memcmp(argv[index], cursor, length))
            return 0;
        ++index;
        if (!end) break;
        cursor = end + 1;
    }
    return 1;
}

static const maelys_cli_command_descriptor_t *resolve_command(
    const char *program, int argc, char **argv) {
    if (argc == 0 || !strcmp(argv[0], "--help")) return maelys_cli_find_command(program, "help");
    if (!strcmp(argv[0], "--version")) return maelys_cli_find_command(program, "version");
    size_t count = 0u;
    const maelys_cli_command_descriptor_t *commands = maelys_cli_commands(&count);
    const maelys_cli_command_descriptor_t *best = NULL;
    size_t best_words = 0u;
    for (size_t i = 0u; i < count; ++i) {
        if (strcmp(commands[i].program, program)) continue;
        size_t words = pattern_words(commands[i].pattern);
        if (words > best_words && pattern_matches(commands[i].pattern, argc, argv)) {
            best = &commands[i];
            best_words = words;
        }
    }
    return best;
}

static const maelys_cli_option_descriptor_t *command_option(
    const maelys_cli_command_descriptor_t *command, const char *name) {
    for (size_t i = 0u; i < command->option_count; ++i)
        if (!strcmp(command->options[i].name, name)) return &command->options[i];
    return NULL;
}

static int global_option(const char *name, maelys_cli_value_kind_t *kind) {
    if (!strcmp(name, "format")) { *kind = MAELYS_CLI_VALUE_STRING; return 1; }
    if (!strcmp(name, "json") || !strcmp(name, "compact") ||
        !strcmp(name, "pretty") || !strcmp(name, "non-interactive") ||
        !strcmp(name, "help") || !strcmp(name, "version")) {
        *kind = MAELYS_CLI_VALUE_NONE;
        return 1;
    }
    return 0;
}

static int parse_boolean(const char *value, int *out) {
    if (!value || !strcmp(value, "true")) { *out = 1; return 1; }
    if (!strcmp(value, "false")) { *out = 0; return 1; }
    return 0;
}

static maelys_cli_parsed_option_t *parsed_option(
    maelys_cli_invocation_t *invocation, const char *name) {
    for (size_t i = 0u; i < invocation->option_count; ++i)
        if (!strcmp(invocation->options[i].name, name)) return &invocation->options[i];
    return NULL;
}

static int value_matches_kind(maelys_cli_value_kind_t kind, const char *value) {
    if (!value || !*value) return 0;
    if (kind == MAELYS_CLI_VALUE_PATH) return value[0] != '\0';
    if (kind == MAELYS_CLI_VALUE_INTEGER) {
        const char *p = value;
        if (*p == '-') ++p;
        if (!*p) return 0;
        for (; *p; ++p) if (!isdigit((unsigned char)*p)) return 0;
    }
    if (kind == MAELYS_CLI_VALUE_OID) {
        size_t length = strlen(value);
        if (length != 40u && length != 64u) return 0;
        for (const char *p = value; *p; ++p) if (!isxdigit((unsigned char)*p)) return 0;
    }
    if (kind == MAELYS_CLI_VALUE_SHA256) {
        if (strlen(value) != 64u) return 0;
        for (const char *p = value; *p; ++p)
            if (!isdigit((unsigned char)*p) && (*p < 'a' || *p > 'f')) return 0;
    }
    return 1;
}

static int option_present(const maelys_cli_invocation_t *invocation, const char *name) {
    for (size_t i = 0u; i < invocation->option_count; ++i)
        if (!strcmp(invocation->options[i].name, name) && invocation->options[i].boolean_value)
            return 1;
    return 0;
}

int maelys_cli_parse(const char *program,
                     int argc,
                     char **argv,
                     maelys_cli_invocation_t *out,
                     maelys_cli_error_t *error) {
    if (!program || argc < 0 || !out) return 0;
    memset(out, 0, sizeof(*out));
    if (error) memset(error, 0, sizeof(*error));
    for (int i = 0; i < argc; ++i) {
        if (!strcmp(argv[i], "--json") || !strcmp(argv[i], "--format=json") ||
            (i + 1 < argc && !strcmp(argv[i], "--format") && !strcmp(argv[i + 1], "json")))
            out->json = 1;
        if (!strcmp(argv[i], "--compact") || !strcmp(argv[i], "--pretty=false")) out->compact = 1;
    }
    out->command = resolve_command(program, argc, argv);
    if (!out->command) {
        cli_error(error, "INVALID_COMMAND",
                  "Run describe --summary --format json to discover valid command identifiers and usage.",
                  "Unknown %s command: %s.", program, argc ? argv[0] : "");
        return 0;
    }
    size_t prefix = pattern_words(out->command->pattern);
    if (argc && (!strcmp(argv[0], "--help") || !strcmp(argv[0], "--version"))) prefix = 1u;
    for (int i = (int)prefix; i < argc; ++i) {
        const char *argument = argv[i];
        if (strncmp(argument, "--", 2) != 0) {
            if (out->operand_count >= MAELYS_CLI_MAX_OPERANDS) {
                cli_error(error, "VALIDATION_FAILED", "Reduce the number of operands and retry.",
                          "Too many operands for '%s'.", out->command->id);
                return 0;
            }
            out->operands[out->operand_count++] = argument;
            continue;
        }
        const char *name = argument + 2;
        const char *equals = strchr(name, '=');
        char option_name[64];
        size_t name_length = equals ? (size_t)(equals - name) : strlen(name);
        if (name_length == 0u || name_length >= sizeof(option_name)) {
            cli_error(error, "VALIDATION_FAILED", "Correct the stated option and retry.",
                      "Invalid option spelling: %s.", argument);
            return 0;
        }
        memcpy(option_name, name, name_length);
        option_name[name_length] = '\0';
        if (!strcmp(option_name, "dry-run") || !strcmp(option_name, "plan")) {
            cli_error(error, "VALIDATION_FAILED",
                      "Remove the legacy flag for a plan. Add --apply only after reviewing that plan.",
                      "--%s is not supported; planning is the default for transactional commands.", option_name);
            return 0;
        }
        maelys_cli_value_kind_t kind = MAELYS_CLI_VALUE_NONE;
        const maelys_cli_option_descriptor_t *descriptor = command_option(out->command, option_name);
        int is_global = global_option(option_name, &kind);
        if (descriptor) kind = descriptor->value_kind;
        else if (!is_global) {
            cli_error(error, "VALIDATION_FAILED",
                      "Run describe for this command and use only its declared options.",
                      "Option --%s is not supported by '%s'. Use '%s'.",
                      option_name, out->command->id, out->command->synopsis);
            return 0;
        }
        if (out->option_count >= MAELYS_CLI_MAX_OPTIONS) {
            cli_error(error, "VALIDATION_FAILED", "Reduce the number of options and retry.",
                      "Too many options for '%s'.", out->command->id);
            return 0;
        }
        if (parsed_option(out, option_name) && !(descriptor && descriptor->repeatable)) {
            cli_error(error, "VALIDATION_FAILED", "Remove the duplicate option and retry.",
                      "Option --%s may be supplied only once.", option_name);
            return 0;
        }
        const char *value = equals ? equals + 1 : NULL;
        int boolean_value = 1;
        if (kind == MAELYS_CLI_VALUE_NONE) {
            if (!parse_boolean(value, &boolean_value)) {
                cli_error(error, "VALIDATION_FAILED", "Use true or false for an explicit boolean.",
                          "Option --%s expects a boolean.", option_name);
                return 0;
            }
        } else {
            if (!value) {
                if (i + 1 >= argc) {
                    cli_error(error, "VALIDATION_FAILED", "Supply the documented option value and retry.",
                              "Option --%s requires a value.", option_name);
                    return 0;
                }
                value = argv[++i];
            }
            if (!value_matches_kind(kind, value)) {
                cli_error(error, "VALIDATION_FAILED", "Correct the stated option value and retry.",
                          "Option --%s has an invalid value.", option_name);
                return 0;
            }
        }
        out->options[out->option_count++] = (maelys_cli_parsed_option_t){
            .name = descriptor ? descriptor->name :
                    !strcmp(option_name, "format") ? "format" :
                    !strcmp(option_name, "json") ? "json" :
                    !strcmp(option_name, "compact") ? "compact" :
                    !strcmp(option_name, "pretty") ? "pretty" :
                    !strcmp(option_name, "non-interactive") ? "non-interactive" :
                    !strcmp(option_name, "help") ? "help" : "version",
            .value = value,
            .boolean_value = boolean_value,
        };
        if (!strcmp(option_name, "format")) {
            if (strcmp(value, "json") && strcmp(value, "text")) {
                cli_error(error, "VALIDATION_FAILED", "Use --format text or --format json.",
                          "Unsupported output format: %s.", value);
                return 0;
            }
            out->json = !strcmp(value, "json");
        } else if (!strcmp(option_name, "json")) out->json = boolean_value;
        else if (!strcmp(option_name, "compact")) out->compact = boolean_value;
        else if (!strcmp(option_name, "pretty")) out->compact = !boolean_value;
        else if (!strcmp(option_name, "non-interactive")) out->non_interactive = boolean_value;
    }
    size_t required = 0u;
    int variadic = 0;
    for (size_t i = 0u; i < out->command->operand_count; ++i) {
        if (out->command->operands[i].required) ++required;
        if (out->command->operands[i].variadic) variadic = 1;
    }
    if (out->operand_count < required || (!variadic && out->operand_count > out->command->operand_count)) {
        cli_error(error, "VALIDATION_FAILED", "Use the synopsis returned by describe and retry.",
                  "Operands do not match '%s'. Use '%s'.", out->command->id, out->command->synopsis);
        return 0;
    }
    for (size_t i = 0u; i < out->command->option_count; ++i) {
        const maelys_cli_option_descriptor_t *option = &out->command->options[i];
        if (option->required && !parsed_option(out, option->name)) {
            cli_error(error, "VALIDATION_FAILED", "Supply the required option and retry.",
                      "--%s is required by '%s'. Use '%s'.",
                      option->name, out->command->id, out->command->synopsis);
            return 0;
        }
        if (option->requires && option_present(out, option->name) && !option_present(out, option->requires)) {
            cli_error(error, "VALIDATION_FAILED", "Supply the dependent option and retry.",
                      "--%s requires --%s.", option->name, option->requires);
            return 0;
        }
        if (option->conflicts_with && option_present(out, option->name) &&
            option_present(out, option->conflicts_with)) {
            cli_error(error, "VALIDATION_FAILED", "Remove one of the conflicting options and retry.",
                      "--%s conflicts with --%s.", option->name, option->conflicts_with);
            return 0;
        }
    }
    if (strcmp(out->command->output_mode, "json-envelope") &&
        (out->json || out->compact || parsed_option(out, "pretty"))) {
        cli_error(error, "VALIDATION_FAILED",
                  "Remove rendering flags; stdout is reserved for the declared protocol stream.",
                  "'%s' is a stream command and does not support CLI output rendering.", out->command->id);
        return 0;
    }
    return 1;
}

const char *maelys_cli_operand(const maelys_cli_invocation_t *invocation, size_t index) {
    return invocation && index < invocation->operand_count ? invocation->operands[index] : NULL;
}

const char *maelys_cli_option(const maelys_cli_invocation_t *invocation, const char *name) {
    if (!invocation || !name) return NULL;
    for (size_t i = 0u; i < invocation->option_count; ++i)
        if (!strcmp(invocation->options[i].name, name)) return invocation->options[i].value;
    return NULL;
}

int maelys_cli_flag(const maelys_cli_invocation_t *invocation, const char *name) {
    if (!invocation || !name) return 0;
    for (size_t i = 0u; i < invocation->option_count; ++i)
        if (!strcmp(invocation->options[i].name, name)) return invocation->options[i].boolean_value;
    return 0;
}

static json_t *effect_json(const maelys_cli_command_descriptor_t *command) {
    if (!command->apply_effect) return json_string(command->effect);
    return json_pack("{s:s,s:s}", "plan", command->effect, "apply", command->apply_effect);
}

static const char *kind_name(maelys_cli_value_kind_t kind) {
    switch (kind) {
        case MAELYS_CLI_VALUE_INTEGER: return "integer";
        case MAELYS_CLI_VALUE_PATH: return "path";
        case MAELYS_CLI_VALUE_OID: return "oid";
        case MAELYS_CLI_VALUE_SHA256: return "sha256";
        case MAELYS_CLI_VALUE_STRING: return "string";
        default: return "boolean";
    }
}

static json_t *descriptor_json(const maelys_cli_command_descriptor_t *command, int summary) {
    json_t *operands = json_array();
    json_t *options = json_array();
    json_t *constraints = json_array();
    json_t *pattern = json_array();
    const char *pattern_cursor = command->pattern;
    while (*pattern_cursor) {
        const char *end = strchr(pattern_cursor, ' ');
        size_t length = end ? (size_t)(end - pattern_cursor) : strlen(pattern_cursor);
        json_array_append_new(pattern, json_stringn(pattern_cursor, length));
        if (!end) break;
        pattern_cursor = end + 1;
    }
    for (size_t i = 0u; operands && i < command->operand_count; ++i) {
        const maelys_cli_operand_descriptor_t *operand = &command->operands[i];
        json_array_append_new(operands, json_pack("{s:s,s:b,s:b,s:s}",
            "name", operand->name, "required", operand->required,
            "variadic", operand->variadic, "summary", operand->summary));
    }
    for (size_t i = 0u; options && i < command->option_count; ++i) {
        const maelys_cli_option_descriptor_t *option = &command->options[i];
        char long_name[68];
        (void)snprintf(long_name, sizeof(long_name), "--%s", option->name);
        json_t *item = json_pack("{s:s,s:b,s:b,s:s,s:[],s:[]}",
            "long", long_name, "required", option->required,
            "repeatable", option->repeatable, "summary", option->summary,
            "requires", "conflictsWith");
        if (option->value_kind != MAELYS_CLI_VALUE_NONE) {
            json_object_set_new(item, "argument", json_pack("{s:s,s:s}",
                "name", option->value_name ? option->value_name : "VALUE",
                "type", kind_name(option->value_kind)));
        }
        if (option->requires) {
            char required[68];
            (void)snprintf(required, sizeof(required), "--%s", option->requires);
            json_array_append_new(json_object_get(item, "requires"), json_string(required));
            json_array_append_new(constraints, json_pack("{s:s,s:[s,s]}",
                "kind", "requires", "options", long_name, required));
        }
        if (option->conflicts_with) {
            char conflict[68];
            (void)snprintf(conflict, sizeof(conflict), "--%s", option->conflicts_with);
            json_array_append_new(json_object_get(item, "conflictsWith"), json_string(conflict));
            json_array_append_new(constraints, json_pack("{s:s,s:[s,s]}",
                "kind", "at-most-one", "options", long_name, conflict));
        }
        json_array_append_new(options, item);
    }
    json_t *input = json_pack("{s:s,s:o,s:o,s:o}", "synopsis", command->synopsis,
                              "operands", operands, "options", options, "constraints", constraints);
    json_t *descriptor = json_pack("{s:s,s:o,s:s,s:s,s:o,s:s,s:o}",
        "id", command->id, "pattern", pattern, "usage", command->synopsis,
        "purpose", command->purpose, "effect", effect_json(command),
        "outputMode", command->output_mode, "input", input);
    if (!summary) {
        json_error_t parse_error;
        json_t *schema = json_loads(command->output_schema_json, 0, &parse_error);
        json_object_set_new(descriptor, "outputSchema", schema ? schema : json_object());
        json_object_set_new(descriptor, "exitCodes",
                            json_pack("{s:s,s:s,s:s}", "0", "command completed",
                                      "1", "execution failed", "2", "valid report with violations"));
    }
    return descriptor;
}

static json_t *describe_data(const maelys_cli_invocation_t *invocation) {
    const char *query = maelys_cli_operand(invocation, 0u);
    int summary = maelys_cli_flag(invocation, "summary");
    json_t *commands_json = json_array();
    size_t count = 0u;
    const maelys_cli_command_descriptor_t *commands = maelys_cli_commands(&count);
    for (size_t i = 0u; i < count; ++i) {
        if (strcmp(commands[i].program, invocation->command->program)) continue;
        if (query && strcmp(query, commands[i].id)) continue;
        json_array_append_new(commands_json, descriptor_json(&commands[i], summary));
    }
    if (query && json_array_size(commands_json) == 0u) {
        json_decref(commands_json);
        return NULL;
    }
    json_t *data = json_pack("{s:i,s:s,s:s,s:s,s:o,s:o}",
        "schemaVersion", 1, "kind", query ? "command" : summary ? "summary" : "catalog",
        "product", "Maelys Git Core", "version", MAELYS_GIT_VERSION,
        "commands", commands_json,
        "globalOptions", json_pack("{s:s,s:s,s:s,s:s,s:s}",
            "format", "text|json", "json", "alias of --format json",
            "compact", "single-line JSON", "pretty", "--pretty=false selects compact JSON",
            "non-interactive", "never prompt"));
    if (!summary) {
        json_object_set_new(data, "output", json_pack("{s:s,s:i,s:s}",
            "contract", MAELYS_CLI_CONTRACT, "schemaVersion", MAELYS_CLI_SCHEMA_VERSION,
            "stdout", "success data only; protocol streams are explicit exceptions"));
        json_object_set_new(data, "invariants", json_pack("[s,s,s,s,s]",
            "usage and agent discovery share one catalog",
            "transactional commands plan by default and require --apply",
            "stdout carries success data; stderr carries failures",
            "--json and --format json are identical",
            "stream commands reject envelope rendering flags"));
    }
    return data;
}

int maelys_cli_emit_success(const maelys_cli_invocation_t *invocation,
                            json_t *data,
                            const char *human,
                            int exit_code) {
    if (!invocation || !invocation->command || !data) return 1;
    if (invocation->json) {
        json_t *envelope = json_pack("{s:i,s:s,s:s,s:b,s:i,s:o}",
            "schemaVersion", MAELYS_CLI_SCHEMA_VERSION, "contract", MAELYS_CLI_CONTRACT,
            "command", invocation->command->id, "ok", 1, "exitCode", exit_code,
            "data", json_incref(data));
        int failed = !envelope || json_dumpf(envelope, stdout,
            JSON_ENSURE_ASCII | JSON_SORT_KEYS | (invocation->compact ? JSON_COMPACT : JSON_INDENT(2))) != 0 ||
            fputc('\n', stdout) == EOF;
        json_decref(envelope);
        return failed ? 1 : exit_code;
    }
    if (human) (void)fprintf(stdout, "%s%s", human, human[0] && human[strlen(human) - 1u] == '\n' ? "" : "\n");
    else { (void)json_dumpf(data, stdout, JSON_INDENT(2) | JSON_ENSURE_ASCII | JSON_SORT_KEYS); (void)fputc('\n', stdout); }
    return exit_code;
}

int maelys_cli_emit_error(const maelys_cli_invocation_t *invocation,
                          const maelys_cli_error_t *error,
                          int exit_code) {
    const char *command = invocation && invocation->command ? invocation->command->id : "unresolved";
    if (invocation && invocation->json) {
        json_t *details = json_pack("{s:s,s:s}", "code", error->code, "message", error->message);
        if (error->hint[0]) json_object_set_new(details, "hint", json_string(error->hint));
        json_t *envelope = json_pack("{s:i,s:s,s:s,s:b,s:i,s:o}",
            "schemaVersion", MAELYS_CLI_SCHEMA_VERSION, "contract", MAELYS_CLI_CONTRACT,
            "command", command, "ok", 0, "exitCode", exit_code, "error", details);
        (void)json_dumpf(envelope, stderr,
            JSON_ENSURE_ASCII | JSON_SORT_KEYS | (invocation->compact ? JSON_COMPACT : JSON_INDENT(2)));
        (void)fputc('\n', stderr);
        json_decref(envelope);
    } else {
        (void)fprintf(stderr, "Maelys error [%s] (%s): %s\n", error->code, command, error->message);
        if (error->hint[0]) (void)fprintf(stderr, "\nHint: %s\n", error->hint);
    }
    return exit_code;
}

int maelys_cli_emit_maelys_error(const maelys_cli_invocation_t *invocation,
                                 maelys_git_result_t result,
                                 const maelys_git_error_t *error) {
    const char *code = "UNEXPECTED";
    const char *hint = "Inspect the diagnostic and retry only after correcting its cause.";
    switch (result) {
        case MAELYS_GIT_ERR_INVALID_ARGUMENT:
        case MAELYS_GIT_ERR_INVALID_COMMAND:
        case MAELYS_GIT_ERR_INVALID_REPOSITORY:
        case MAELYS_GIT_ERR_LIMIT: code = "VALIDATION_FAILED"; hint = "Correct the stated input, then retry the same command."; break;
        case MAELYS_GIT_ERR_POLICY: code = "POLICY_FAILED"; hint = "Validate the current policy manifest before retrying."; break;
        case MAELYS_GIT_ERR_DENIED: code = "ACCESS_DENIED"; hint = "Inspect the matching policy decision; do not bypass the denial."; break;
        case MAELYS_GIT_ERR_IO: code = "IO_FAILED"; break;
        case MAELYS_GIT_ERR_PROCESS: code = "PROCESS_FAILED"; break;
        case MAELYS_GIT_ERR_PROTOCOL: code = "PROTOCOL_FAILED"; break;
        case MAELYS_GIT_ERR_NOT_FOUND: code = "NOT_FOUND"; break;
        default: break;
    }
    maelys_cli_error_t cli_error_value;
    cli_error(&cli_error_value, code, hint, "%s",
              error && error->message[0] ? error->message : maelys_git_result_name(result));
    return maelys_cli_emit_error(invocation, &cli_error_value, 1);
}

int maelys_cli_emit_describe(const maelys_cli_invocation_t *invocation) {
    json_t *data = describe_data(invocation);
    if (!data) {
        maelys_cli_error_t error;
        cli_error(&error, "INVALID_COMMAND",
                  "Run describe --summary --format json and select a returned command identifier.",
                  "Unknown command identifier: %s.", maelys_cli_operand(invocation, 0u));
        return maelys_cli_emit_error(invocation, &error, 1);
    }
    int result = maelys_cli_emit_success(invocation, data, NULL, 0);
    json_decref(data);
    return result;
}

int maelys_cli_emit_help(const maelys_cli_invocation_t *invocation) {
    size_t count = 0u;
    const maelys_cli_command_descriptor_t *commands = maelys_cli_commands(&count);
    char *human = calloc(1u, 16384u);
    if (!human) return 1;
    size_t used = (size_t)snprintf(human, 16384u,
        "%s %s — normalized CLI for humans and agents\n\nCOMMANDS\n",
        invocation->command->program, MAELYS_GIT_VERSION);
    json_t *items = json_array();
    for (size_t i = 0u; i < count; ++i) {
        if (strcmp(commands[i].program, invocation->command->program)) continue;
        int written = snprintf(human + used, 16384u - used, "  %-72s %s\n",
                               commands[i].synopsis, commands[i].purpose);
        if (written > 0 && (size_t)written < 16384u - used) used += (size_t)written;
        json_array_append_new(items, descriptor_json(&commands[i], 1));
    }
    (void)snprintf(human + used, 16384u - used,
        "\nAGENT CONTRACT\n  Use --format json --non-interactive. Run 'describe --summary --format json' first.\n"
        "  Exit 0 is success, 1 is execution failure, and 2 is a completed validation report with violations.\n"
        "  Mutations plan by default and require --apply. Stream commands reserve stdout for their protocol.\n");
    json_t *data = json_pack("{s:s,s:o}", "text", human, "commands", items);
    int result = maelys_cli_emit_success(invocation, data, human, 0);
    json_decref(data);
    free(human);
    return result;
}
