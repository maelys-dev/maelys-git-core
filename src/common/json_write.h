#ifndef MAELYS_GIT_COMMON_JSON_WRITE_H
#define MAELYS_GIT_COMMON_JSON_WRITE_H

/* The one way Maelys Git Core writes JSON: a maelys-json writer created for
 * its use, with limits that are always explicit, and the first error of any
 * call kept. maelys-json leaves a writer usable after an invalid argument (a
 * string that is not UTF-8, a NULL value); here every error fails the whole
 * document, as a failed construction always did.
 *
 * The member helpers take the key of the member to write, or NULL for an
 * array element, and do nothing once the document has failed. Keys are
 * sorted at serialization, so members may be written in any order. */

#include "maelys_git.h"

#include <maelys/json.h>

#include <stddef.h>
#include <stdint.h>

typedef enum {
    /* Data of a command line reply: printable ASCII, compact, no limit but
     * the library's ceilings and the memory available. */
    MG_JSON_DATA = 1,
    /* One line of the agent protocol: 65 536 bytes of JSON at most, the
     * line separator excluded, printable ASCII, compact. */
    MG_JSON_PROTOCOL_LINE,
    /* The deduplication form of a received command, v2: as a protocol line. */
    MG_JSON_DEDUPLICATION,
    /* A configuration the agent writes for its own reader: indented, one flat
     * object of at most 29 values in 65 536 bytes. */
    MG_JSON_CONFIGURATION
} mg_json_use_t;

typedef struct {
    maelys_json_writer_t *writer;
    maelys_json_result_t status; /* the first error, or MAELYS_JSON_OK */
} mg_json_t;

/* Starts a document for `use`; a failed allocation is its first error. */
void mg_json_begin(mg_json_t *json, mg_json_use_t use);

void mg_json_object(mg_json_t *json, const char *key);
void mg_json_end_object(mg_json_t *json);
void mg_json_array(mg_json_t *json, const char *key);
void mg_json_end_array(mg_json_t *json);
void mg_json_string(mg_json_t *json, const char *key, const char *value);
void mg_json_i64(mg_json_t *json, const char *key, int64_t value);
void mg_json_boolean(mg_json_t *json, const char *key, int value);
void mg_json_null(mg_json_t *json, const char *key);
/* A copy of `value` of a parsed document, its subtree included. */
void mg_json_copy(mg_json_t *json, const char *key,
                  const maelys_json_document_t *document, maelys_json_value_t value);

/* The members of a policy failure detail that are known, into the object
 * being written: kind, then diagnostic, budget, requested and limit for a
 * capacity, file, line and column. An unknown member is left out, never
 * written empty; a detail of kind NONE writes nothing. The command line
 * and the agent report a failure with these same members. */
void mg_json_failure_detail(mg_json_t *json, const maelys_git_failure_detail_t *detail);

/* Serializes the document and releases its writer. On success *out_bytes is
 * the JSON (NUL-terminated, without a final newline, owned by the caller).
 * Otherwise it is NULL and the result is the document's first error:
 * MAELYS_JSON_ERR_LIMIT when a limit of its use was reached. */
maelys_json_result_t mg_json_finish(mg_json_t *json, char **out_bytes, size_t *out_size);

/* Releases the writer of a document that is not finished. */
void mg_json_discard(mg_json_t *json);

#endif
