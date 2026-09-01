#include "agent_internal.h"

#include <stdlib.h>
#include <string.h>

static void write_protocol_error(FILE *output,
                                 maelys_git_result_t result,
                                 const char *message) {
    json_t *root = json_pack("{s:s,s:s,s:s,s:s}",
        "protocol", MAELYS_GIT_AGENT_PROTOCOL, "type", "error",
        "code", maelys_git_result_name(result),
        "message", message && *message ? message : "operation failed");
    if (root) {
        (void)json_dumpf(root, output, JSON_COMPACT | JSON_ENSURE_ASCII);
        (void)fputc('\n', output);
        (void)fflush(output);
        json_decref(root);
    }
}

maelys_git_result_t maelys_git_agent_serve(maelys_git_policy_t *policy,
                                            const char *git_executable,
                                            const char *repository_root,
                                            FILE *input,
                                            FILE *output,
                                            FILE *diagnostics,
                                            maelys_git_error_t *error) {
    if (!policy || !git_executable || !repository_root || !input || !output || !diagnostics)
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    char *line = malloc(MAELYS_GIT_MAX_PROTOCOL_LINE + 2u);
    if (!line) return MAELYS_GIT_ERR_IO;
    while (fgets(line, (int)MAELYS_GIT_MAX_PROTOCOL_LINE + 2, input)) {
        size_t length = strlen(line);
        if (length == 0u || line[length - 1u] != '\n') {
            write_protocol_error(output, MAELYS_GIT_ERR_LIMIT, "protocol line exceeds 64 KiB");
            free(line);
            return MAELYS_GIT_ERR_LIMIT;
        }
        while (length > 0u && (line[length - 1u] == '\n' || line[length - 1u] == '\r'))
            line[--length] = '\0';
        mg_agent_message_t message;
        maelys_git_error_t local_error = {0};
        maelys_git_result_t result = mg_protocol_parse(line, length, &message, &local_error);
        if (result != MAELYS_GIT_OK) {
            write_protocol_error(output, result, local_error.message);
            continue;
        }
        char *encoded = NULL;
        result = mg_executor_execute(policy, git_executable, repository_root,
                                     &message, &encoded, &local_error);
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
