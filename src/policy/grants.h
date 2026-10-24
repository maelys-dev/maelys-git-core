#ifndef MAELYS_GIT_POLICY_GRANTS_H
#define MAELYS_GIT_POLICY_GRANTS_H

/* A snapshot of Gitolite grants, format maelys-git-grants/1: the data a
 * generated policy reads as input facts, one slice per request, instead of
 * compiling it into its text.
 *
 * The file is one JSON object, closed, of nine members:
 *
 *   "format"             "maelys-git-grants/1"
 *   "members"            [[user, group], ...]            direct membership
 *   "nested"             [[group, parent], ...]          group in a group
 *   "access"             [[kind, subject, repository, level], ...]
 *                        level: "C", "R", "RW" or "RW+"
 *   "refs"               [[kind, subject, repository, form, pattern, level], ...]
 *                        form: "exact" or "prefix"; level: "RW", "RW+" or "-";
 *                        a prefix ends with '/', except a deny's bare
 *                        literal, which Gitolite denies as a prefix
 *   "namespace_creators" [[kind, subject, namespace], ...]
 *   "owner_access"       [[namespace, level], ...]       level: "R", "RW" or "RW+"
 *   "vref_names"         [[kind, subject, repository, path], ...]
 *   "vref_limits"        [[kind, subject, repository, limit, value], ...]
 *                        limit: "count", "new_count" or "max_new_binary";
 *                        value: an integer in [0, INT64_MAX]
 *
 * kind is "user" or "group". The file is in Canonical JSON v1 (members in
 * key order, no whitespace, minimal escapes, integers only, no final
 * newline) and every array is strictly increasing, element by element:
 * one set of grants has one byte form, and so one fingerprint, whoever
 * wrote it. Names, repositories, namespaces, refs and paths follow the
 * generator's rules (mg_gitolite_name_is_valid,
 * maelys_git_repository_name_is_valid, mg_gitolite_pattern_is_valid), with
 * Git Core's string bound below instead of the policy atom bound.
 *
 * The snapshot is immutable once loaded: every decision made with it uses
 * this one generation of grants. */

#include "maelys_git.h"

#include <stddef.h>
#include <stdint.h>

#define MG_GRANTS_FORMAT "maelys-git-grants/1"

/* The bounds of D7. */
#define MG_GRANTS_MAX_BYTES (4u * 1024u * 1024u)
#define MG_GRANTS_MAX_TUPLES 65536u
#define MG_GRANTS_MAX_GROUPS 4096u
#define MG_GRANTS_MAX_DIRECT_GROUPS 64u
/* One name, repository, namespace, ref or path: Git Core's bound, chosen
 * equal to the bytes an engine symbol may hold (1 024, NUL excluded), so
 * that every string of the snapshot can be a fact of a slice. */
#define MG_GRANTS_MAX_STRING 1024u

typedef enum { MG_SUBJECT_USER = 0, MG_SUBJECT_GROUP = 1 } mg_subject_kind_t;

typedef struct {
    const char *user, *group;
} mg_grant_member_t;

typedef struct {
    const char *group, *parent;
} mg_grant_nested_t;

typedef struct {
    mg_subject_kind_t kind;
    const char *subject, *repository, *level;
} mg_grant_access_t;

typedef struct {
    mg_subject_kind_t kind;
    const char *subject, *repository;
    int prefix;               /* 1 for a prefix, 0 for an exact ref */
    const char *pattern, *level;
} mg_grant_ref_t;

typedef struct {
    mg_subject_kind_t kind;
    const char *subject, *namespace_name;
} mg_grant_creator_t;

typedef struct {
    const char *namespace_name, *level;
} mg_grant_owner_t;

typedef struct {
    mg_subject_kind_t kind;
    const char *subject, *repository, *path;
} mg_grant_vref_name_t;

typedef struct {
    mg_subject_kind_t kind;
    const char *subject, *repository, *limit;
    int64_t value;
} mg_grant_vref_limit_t;

/* The sections of a loaded snapshot, each sorted and without duplicates.
 * The strings belong to the snapshot: one arena, the parsed document is
 * released once they are copied. */
typedef struct {
    const mg_grant_member_t *members;
    size_t member_count;
    const mg_grant_nested_t *nested;
    size_t nested_count;
    const mg_grant_access_t *access;
    size_t access_count;
    const mg_grant_ref_t *refs;
    size_t ref_count;
    const mg_grant_creator_t *creators;
    size_t creator_count;
    const mg_grant_owner_t *owners;
    size_t owner_count;
    const mg_grant_vref_name_t *vref_names;
    size_t vref_name_count;
    const mg_grant_vref_limit_t *vref_limits;
    size_t vref_limit_count;
    size_t group_count;       /* distinct groups named anywhere */
    size_t index_bytes;       /* memory held: the tuples and the arena of strings */
} mg_grants_view_t;

typedef struct mg_grants mg_grants_t;

/* Validates and indexes SIZE bytes of a snapshot; *out on success only. */
maelys_git_result_t mg_grants_parse(const void *bytes, size_t size, mg_grants_t **out,
                                    maelys_git_error_t *error);
/* Reads the file at PATH as a trusted file, owned by root or the caller,
 * not writable by others, in a directory only root or the caller may change
 * (links are followed and their target's directory is judged), then parses
 * it. A refused file is MAELYS_GIT_ERR_DENIED, _NOT_FOUND, _LIMIT or _IO,
 * by the errno of the check; a file that changed while it was read (its
 * descriptor observed before and after) is MAELYS_GIT_ERR_IO. */
maelys_git_result_t mg_grants_load(const char *path, mg_grants_t **out, maelys_git_error_t *error);
/* The bytes of the file at PATH, read as mg_grants_load reads them and not
 * parsed: a trusted reading of at most MG_GRANTS_MAX_BYTES, refused when the
 * file changes while it is read. The caller frees them. */
maelys_git_result_t mg_grants_read(const char *path, unsigned char **out_bytes, size_t *out_size,
                                   maelys_git_error_t *error);
/* Reads the file at PATH again, as mg_grants_load reads it, and hashes its
 * bytes: *out is NULL when they are those of CURRENT, the new snapshot
 * otherwise. A failure leaves *out NULL and says nothing of CURRENT, which
 * the caller must not use again (directive GIT-C06, D4). */
maelys_git_result_t mg_grants_reload(const char *path, const mg_grants_t *current, mg_grants_t **out,
                                     maelys_git_error_t *error);
void mg_grants_free(mg_grants_t *grants);

/* Tests only: called between the read of a snapshot and the second
 * observation of its descriptor, to change the file there. */
extern void (*mg_grants_test_between_reads)(const char *path);

/* The SHA-256 of the bytes the snapshot was parsed from, in hex. */
const char *mg_grants_sha256(const mg_grants_t *grants);
void mg_grants_view(const mg_grants_t *grants, mg_grants_view_t *out);

#endif
