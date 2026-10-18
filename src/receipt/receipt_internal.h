#ifndef MAELYS_GIT_RECEIPT_INTERNAL_H
#define MAELYS_GIT_RECEIPT_INTERNAL_H

#include "maelys_git_receipt.h"

#include <maelys/json.h>

#include <stdio.h>

/* maelys_git_receipt_serialize with a smaller byte bound, for tests. */
maelys_git_result_t mg_receipt_serialize_within(const maelys_git_receipt_t *receipt,
                                                size_t maximum_bytes,
                                                char **out_bytes,
                                                size_t *out_size,
                                                char out_sha256[65],
                                                maelys_git_error_t *error);

/* Appends one JSONL line to `stream`: the receipt, its SHA-256 and, when
 * `text` is not NULL, the explanation text, as
 * {"explanationText":…,"receipt":{…},"receiptSha256":"…"}. */
maelys_git_result_t mg_receipt_write_line(FILE *stream,
                                          const maelys_git_receipt_t *receipt,
                                          const char *text,
                                          maelys_git_error_t *error);

/* The explanation text a verified receipt vouches for. */
typedef struct {
    int has_text;
    size_t text_bytes;
    char text_sha256[65];
} mg_receipt_text_t;

/* Rewrites a receipt read inside another document (a value of `document`)
 * into canonical bytes, then verifies those bytes as maelys_git_receipt_verify
 * does: a rewrite copies a non-integer number by its lexeme, so it proves
 * nothing by itself. Returns the bytes (freed by the caller), their SHA-256
 * and the text the receipt vouches for; nothing on failure. */
maelys_git_result_t mg_receipt_rewrite(const maelys_json_document_t *document,
                                       maelys_json_value_t value,
                                       char **out_bytes,
                                       size_t *out_size,
                                       char out_sha256[65],
                                       mg_receipt_text_t *out_text,
                                       maelys_git_error_t *error);

#endif
