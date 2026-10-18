#include "common/json_write.h"

#include <stdlib.h>

/* The ceilings maelys-json accepts: a data reply is bounded by the memory
 * available, as it was before, and by nothing the product adds. */
#define MG_JSON_UNBOUNDED_BYTES (SIZE_MAX / 2u - 1u)
#define MG_JSON_UNBOUNDED_NODES (SIZE_MAX / 256u)

/* The deepest output schema nests four containers; 32 leaves room and is
 * the protocol's depth. */
#define MG_JSON_DATA_DEPTH 32u

/* The agent protocol: 65 536 bytes of JSON on one line, the separator
 * excluded, nested 32 deep, of at most 32 768 values (a JSON text of T
 * values needs at least 2T - 1 bytes). */
#define MG_JSON_LINE_BYTES 65536u
#define MG_JSON_LINE_DEPTH 32u
#define MG_JSON_LINE_NODES 32768u

/* The configuration reader's own limits (src/agent/config.c). */
#define MG_JSON_CONFIGURATION_BYTES 65536u
#define MG_JSON_CONFIGURATION_DEPTH 1u
#define MG_JSON_CONFIGURATION_NODES 29u

void mg_json_begin(mg_json_t *json, mg_json_use_t use) {
    json->writer = NULL;
    json->status = MAELYS_JSON_ERR_ARGUMENT;
    maelys_json_limits_t limits;
    unsigned int flags;
    switch (use) {
        case MG_JSON_DATA:
            limits = (maelys_json_limits_t){MG_JSON_UNBOUNDED_BYTES, MG_JSON_DATA_DEPTH,
                                            MG_JSON_UNBOUNDED_NODES};
            flags = MAELYS_JSON_WRITER_ASCII;
            break;
        case MG_JSON_PROTOCOL_LINE:
        case MG_JSON_DEDUPLICATION:
            limits = (maelys_json_limits_t){MG_JSON_LINE_BYTES, MG_JSON_LINE_DEPTH,
                                            MG_JSON_LINE_NODES};
            flags = MAELYS_JSON_WRITER_ASCII;
            break;
        case MG_JSON_CONFIGURATION:
            limits = (maelys_json_limits_t){MG_JSON_CONFIGURATION_BYTES,
                                            MG_JSON_CONFIGURATION_DEPTH,
                                            MG_JSON_CONFIGURATION_NODES};
            flags = MAELYS_JSON_WRITER_INDENT;
            break;
        default:
            return;
    }
    json->status = maelys_json_writer_create(MAELYS_JSON_PROFILE_RFC8259, &limits, flags,
                                             &json->writer);
}

/* Keeps the first error; a later call on a failed document does nothing. */
static int keep(mg_json_t *json, maelys_json_result_t result) {
    if (json->status == MAELYS_JSON_OK && result != MAELYS_JSON_OK) json->status = result;
    return json->status == MAELYS_JSON_OK;
}

static int keyed(mg_json_t *json, const char *key) {
    if (json->status != MAELYS_JSON_OK) return 0;
    return !key || keep(json, maelys_json_writer_key_cstr(json->writer, key));
}

void mg_json_object(mg_json_t *json, const char *key) {
    if (keyed(json, key)) (void)keep(json, maelys_json_writer_object_begin(json->writer));
}

void mg_json_end_object(mg_json_t *json) {
    if (json->status == MAELYS_JSON_OK) (void)keep(json, maelys_json_writer_object_end(json->writer));
}

void mg_json_array(mg_json_t *json, const char *key) {
    if (keyed(json, key)) (void)keep(json, maelys_json_writer_array_begin(json->writer));
}

void mg_json_end_array(mg_json_t *json) {
    if (json->status == MAELYS_JSON_OK) (void)keep(json, maelys_json_writer_array_end(json->writer));
}

void mg_json_string(mg_json_t *json, const char *key, const char *value) {
    if (keyed(json, key))
        (void)keep(json, value ? maelys_json_writer_string_cstr(json->writer, value)
                               : MAELYS_JSON_ERR_ARGUMENT);
}

void mg_json_i64(mg_json_t *json, const char *key, int64_t value) {
    if (keyed(json, key)) (void)keep(json, maelys_json_writer_i64(json->writer, value));
}

void mg_json_boolean(mg_json_t *json, const char *key, int value) {
    if (keyed(json, key)) (void)keep(json, maelys_json_writer_boolean(json->writer, value != 0));
}

void mg_json_null(mg_json_t *json, const char *key) {
    if (keyed(json, key)) (void)keep(json, maelys_json_writer_null(json->writer));
}

void mg_json_copy(mg_json_t *json, const char *key,
                  const maelys_json_document_t *document, maelys_json_value_t value) {
    if (keyed(json, key)) (void)keep(json, maelys_json_writer_value(json->writer, document, value));
}

void mg_json_failure_detail(mg_json_t *json, const maelys_git_failure_detail_t *detail) {
    if (detail->kind == MAELYS_GIT_FAILURE_NONE) return;
    mg_json_string(json, "kind", maelys_git_failure_kind_name(detail->kind));
    if (detail->diagnostic[0]) mg_json_string(json, "diagnostic", detail->diagnostic);
    if (detail->budget[0]) mg_json_string(json, "budget", detail->budget);
    if (detail->kind == MAELYS_GIT_FAILURE_CAPACITY) {
        /* Written as the signed integers they always were. */
        mg_json_i64(json, "requested", (int64_t)detail->requested);
        mg_json_i64(json, "limit", (int64_t)detail->limit);
    }
    if (detail->file[0]) mg_json_string(json, "file", detail->file);
    if (detail->line > 0u) {
        mg_json_i64(json, "line", (int64_t)detail->line);
        mg_json_i64(json, "column", (int64_t)detail->column);
    }
}

maelys_json_result_t mg_json_finish(mg_json_t *json, char **out_bytes, size_t *out_size) {
    *out_bytes = NULL;
    if (out_size) *out_size = 0u;
    size_t size = 0u;
    if (json->status == MAELYS_JSON_OK)
        (void)keep(json, maelys_json_writer_finish(json->writer, out_bytes, &size));
    mg_json_discard(json);
    if (json->status != MAELYS_JSON_OK) {
        free(*out_bytes);
        *out_bytes = NULL;
        return json->status;
    }
    if (out_size) *out_size = size;
    return MAELYS_JSON_OK;
}

void mg_json_discard(mg_json_t *json) {
    maelys_json_writer_release(json->writer);
    json->writer = NULL;
}
