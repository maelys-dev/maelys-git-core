#include "agent_internal.h"

#include <stdlib.h>
#include <string.h>

static void write_protocol_error(FILE *output,
                                 maelys_git_result_t result,
                                 const char *message) {
    mg_json_t json;
    mg_json_begin(&json, MG_JSON_PROTOCOL_LINE);
    mg_json_object(&json, NULL);
    mg_json_string(&json, "protocol", MAELYS_GIT_AGENT_PROTOCOL);
    mg_json_string(&json, "type", "error");
    mg_json_string(&json, "code", maelys_git_result_name(result));
    mg_json_string(&json, "message", message && *message ? message : "operation failed");
    mg_json_end_object(&json);
    char *line = NULL;
    size_t size = 0u;
    if (mg_json_finish(&json, &line, &size) == MAELYS_JSON_OK) {
        (void)fwrite(line, 1u, size, output);
        (void)fputc('\n', output);
        (void)fflush(output);
    }
    free(line);
}

/* 1 = complete line, 0 = EOF, -1 = framing/I/O failure. Count bytes rather
 * than C-string length so embedded NULs reach the JSON parser unchanged.
 * The 64 KiB budget excludes one LF or CRLF framing delimiter. */
static int read_protocol_line(FILE *input, char *line, size_t *out_length,
                              maelys_git_error_t *error) {
    size_t length = 0u;
    int byte;
    while ((byte = fgetc(input)) != EOF && byte != '\n') {
        if (length >= MAELYS_GIT_MAX_PROTOCOL_LINE + 1u) goto oversized;
        line[length++] = (char)byte;
        if (length > MAELYS_GIT_MAX_PROTOCOL_LINE && byte != '\r') goto oversized;
    }
    if (ferror(input)) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, 0, "failed to read executor input");
        return -1;
    }
    if (byte == EOF) {
        if (length == 0u) return 0;
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "protocol line requires a final newline");
        return -1;
    }
    if (length > 0u && line[length - 1u] == '\r') --length;
    line[length] = '\0';
    *out_length = length;
    return 1;
oversized:
    mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0, "protocol line exceeds 64 KiB");
    return -1;
}

maelys_git_result_t mg_agent_serve(maelys_git_policy_t *policy,
                                   const char *git_executable,
                                   const char *repository_root,
                                   FILE *input,
                                   FILE *output,
                                   FILE *diagnostics,
                                   maelys_git_explain_mode_t denial_mode,
                                   maelys_git_error_t *error) {
    if (!policy || !git_executable || !repository_root || !input || !output || !diagnostics)
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    char *line = malloc(MAELYS_GIT_MAX_PROTOCOL_LINE + 2u);
    if (!line) return MAELYS_GIT_ERR_IO;
    while (1) {
        size_t length = 0u;
        maelys_git_error_t local_error = {0};
        int read_result = read_protocol_line(input, line, &length, &local_error);
        if (read_result == 0) break;
        if (read_result < 0) {
            write_protocol_error(output, local_error.code, local_error.message);
            if (error) *error = local_error;
            free(line);
            return local_error.code;
        }
        mg_agent_message_t message;
        maelys_git_result_t result = mg_protocol_parse(line, length, &message, &local_error);
        if (result != MAELYS_GIT_OK) {
            write_protocol_error(output, result, local_error.message);
            continue;
        }
        char *encoded = NULL;
        result = mg_executor_execute(policy, git_executable, repository_root,
                                     &message, denial_mode, &encoded, &local_error);
        if (result == MAELYS_GIT_OK) {
            if (fprintf(output, "%s\n", encoded) < 0 || fflush(output) != 0) {
                free(encoded);
                mg_protocol_message_clear(&message);
                free(line);
                mg_error_set(error, MAELYS_GIT_ERR_IO, 0, "failed to write executor output");
                return MAELYS_GIT_ERR_IO;
            }
            free(encoded);
        } else {
            write_protocol_error(output, result, local_error.message);
        }
        mg_protocol_message_clear(&message);
    }
    free(line);
    if (ferror(input)) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, 0, "failed to read executor input");
        return MAELYS_GIT_ERR_IO;
    }
    return MAELYS_GIT_OK;
}

/* A local front-end publishes what it executes and keeps no audit: a denial
 * carries no explanation text. */
maelys_git_result_t maelys_git_agent_serve(maelys_git_policy_t *policy,
                                            const char *git_executable,
                                            const char *repository_root,
                                            FILE *input,
                                            FILE *output,
                                            FILE *diagnostics,
                                            maelys_git_error_t *error) {
    return mg_agent_serve(policy, git_executable, repository_root, input, output, diagnostics,
                          MAELYS_GIT_EXPLAIN_NEVER, error);
}
