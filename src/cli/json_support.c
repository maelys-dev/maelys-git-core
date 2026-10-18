#include "cli/json_support.h"

#include <stdlib.h>

int maelys_git_cli_succeed_document(
    maelys_cli_context_t *context, mg_json_t *data, const char *human, int exit_code) {
    /* Keys are sorted and every code point above U+007F is escaped, so the
     * data is deterministic and printable ASCII. maelys-json guarantees its
     * validity: the trusted reply writes it verbatim in compact mode. */
    char *text = NULL;
    if (mg_json_finish(data, &text, NULL) != MAELYS_JSON_OK) {
        return maelys_cli_fail(context, MAELYS_CLI_CODE_UNEXPECTED,
            "Report this defect to the command implementation.",
            "Command '%s' could not build its result document.",
            context && context->invocation && context->invocation->command ?
                context->invocation->command->id : "unresolved");
    }
    int result = maelys_cli_succeed_trusted(context, text, human, exit_code);
    free(text);
    return result;
}

void maelys_git_cli_change_summary(mg_json_t *data, const char *key,
                                   const maelys_git_change_summary_t *summary) {
    mg_json_object(data, key);
    mg_json_i64(data, "changed", (int64_t)summary->changed_count);
    mg_json_i64(data, "added", (int64_t)summary->added_count);
    mg_json_i64(data, "modified", (int64_t)summary->modified_count);
    mg_json_i64(data, "deleted", (int64_t)summary->deleted_count);
    mg_json_i64(data, "renamed", (int64_t)summary->renamed_count);
    mg_json_i64(data, "maxNewBlobSize", (int64_t)summary->max_new_blob_size);
    mg_json_i64(data, "totalNewBlobSize", (int64_t)summary->total_new_blob_size);
    mg_json_i64(data, "inspectedBlobBytes", (int64_t)summary->inspected_blob_bytes);
    mg_json_boolean(data, "hasBinary", summary->has_binary);
    mg_json_end_object(data);
}
