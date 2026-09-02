#include "cli/json_support.h"

#include <stdlib.h>

int maelys_git_cli_succeed_json(
    maelys_cli_context_t *context, json_t *data, const char *human, int exit_code) {
    if (!data) {
        return maelys_cli_fail(context, MAELYS_CLI_CODE_UNEXPECTED,
            "Report this defect to the command implementation.",
            "Command '%s' could not build its result document.",
            context && context->invocation && context->invocation->command ?
                context->invocation->command->id : "unresolved");
    }
    /* Sorted keys keep the data deterministic across Jansson versions;
     * JSON_ENSURE_ASCII satisfies the framework writer's UTF-8 strictness.
     * Jansson guarantees validity, so the trusted reply writes the text
     * verbatim in compact mode instead of validating and reformatting it. */
    char *text = json_dumps(data, JSON_COMPACT | JSON_SORT_KEYS | JSON_ENSURE_ASCII);
    json_decref(data);
    if (!text) {
        return maelys_cli_fail(context, MAELYS_CLI_CODE_UNEXPECTED,
            "Report this defect to the command implementation.",
            "Result document could not be serialized.");
    }
    int result = maelys_cli_succeed_trusted(context, text, human, exit_code);
    free(text);
    return result;
}

json_t *maelys_git_cli_change_summary_json(const maelys_git_change_summary_t *summary) {
    return json_pack("{s:I,s:I,s:I,s:I,s:I,s:I,s:I,s:I,s:b}",
        "changed", (json_int_t)summary->changed_count,
        "added", (json_int_t)summary->added_count,
        "modified", (json_int_t)summary->modified_count,
        "deleted", (json_int_t)summary->deleted_count,
        "renamed", (json_int_t)summary->renamed_count,
        "maxNewBlobSize", (json_int_t)summary->max_new_blob_size,
        "totalNewBlobSize", (json_int_t)summary->total_new_blob_size,
        "inspectedBlobBytes", (json_int_t)summary->inspected_blob_bytes,
        "hasBinary", summary->has_binary);
}
