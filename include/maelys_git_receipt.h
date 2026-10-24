#ifndef MAELYS_GIT_RECEIPT_H
#define MAELYS_GIT_RECEIPT_H

/* Authorization receipts as bytes: Maelys Canonical JSON v1 written by
 * maelys-json, and their SHA-256. Versions 1 and 2 of the receipt contract:
 * version 2 is version 1 with the member grants, written only when a policy
 * of the set read a snapshot of grants. */

#include "maelys_git.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The largest canonical receipt; a larger one is MAELYS_GIT_ERR_LIMIT. */
#define MAELYS_GIT_RECEIPT_MAX_BYTES 8192u
/* The largest explanation document a surface exposes beside a receipt. A
 * longer one is not exposed; the receipt keeps its size and SHA-256. */
#define MAELYS_GIT_RECEIPT_MAX_EXPLANATION_TEXT 32768u

/* Writes the canonical bytes of a receipt, without a final newline, into a
 * buffer the caller releases with free(), and the lowercase hex SHA-256 of
 * those bytes. On failure nothing is returned. */
maelys_git_result_t maelys_git_receipt_serialize(
    const maelys_git_receipt_t *receipt,
    char **out_bytes,
    size_t *out_size,
    char out_sha256[65],
    maelys_git_error_t *error);

/* Accepts bytes only if they are a canonical receipt of version 1 or 2:
 * closed keys, types, enumerations and digest lengths, unsigned integers
 * only; grants in version 2 and only there. On success, out_sha256 (which
 * may be NULL) receives the SHA-256 of the bytes as given. Anything else is
 * MAELYS_GIT_ERR_PROTOCOL. */
maelys_git_result_t maelys_git_receipt_verify(
    const void *bytes,
    size_t size,
    char out_sha256[65],
    maelys_git_error_t *error);

#ifdef __cplusplus
}
#endif

#endif
