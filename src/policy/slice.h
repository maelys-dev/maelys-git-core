#ifndef MAELYS_GIT_POLICY_SLICE_H
#define MAELYS_GIT_POLICY_SLICE_H

/* The slice of a grants snapshot one request needs, format
 * maelys-git-slice/1: the input facts the audited Gitolite program reads,
 * and no other.
 *
 * For a user U, a repository P, a ref F (or none) and the paths of a push,
 * the slice holds, without duplicates:
 *   slice_member(U, G)          each direct group of U
 *   slice_nested(C, G)          each nesting edge from a group C of U, so that
 *                               the program closes the groups of U itself
 *   slice_access / slice_group_access (S, P, L)
 *                               the access of U and of its groups on P
 *   slice_ref_match / slice_group_ref_match (S, P, L)
 *                               the level of each ref grant of U or a group
 *                               on P whose pattern matches F
 *   slice_ref_level / slice_group_ref_level (S, P, L)
 *                               each write level (RW, RW+) U or a group holds
 *                               on some ref of P, whatever F: has_ref_write
 *                               reads a grant on any ref
 *   slice_namespace_creator / slice_group_namespace_creator (S, N)
 *   slice_owner_access(N, L)    for the namespace N of P that U owns, when
 *                               the request gives repository_owner_namespace(N, U)
 *   slice_vref_name / slice_group_vref_name (S, P, F)
 *                               the VREF names of U and its groups on P that
 *                               are paths of the request
 *   slice_vref_count, _new_count, _max_new_binary and their group forms
 *   (S, P, N)                   every VREF limit of U and its groups on P
 *
 * Every fact a rule of the audited program can use is in the slice: each of
 * its rules binds the subject to U or a group of U, the repository to P or
 * a namespace of P, and the ref or the path to the request's before it reads
 * a slice predicate (see the directive GIT-C06, section 5). */

#include "policy/grants.h"

#include <stddef.h>
#include <stdint.h>

#define MG_SLICE_FORMAT "maelys-git-slice/1"

typedef enum {
    MG_SLICE_MEMBER,
    MG_SLICE_NESTED,
    MG_SLICE_ACCESS,
    MG_SLICE_GROUP_ACCESS,
    MG_SLICE_REF_MATCH,
    MG_SLICE_GROUP_REF_MATCH,
    MG_SLICE_REF_LEVEL,
    MG_SLICE_GROUP_REF_LEVEL,
    MG_SLICE_NAMESPACE_CREATOR,
    MG_SLICE_GROUP_NAMESPACE_CREATOR,
    MG_SLICE_OWNER_ACCESS,
    MG_SLICE_VREF_NAME,
    MG_SLICE_GROUP_VREF_NAME,
    MG_SLICE_VREF_COUNT,
    MG_SLICE_GROUP_VREF_COUNT,
    MG_SLICE_VREF_NEW_COUNT,
    MG_SLICE_GROUP_VREF_NEW_COUNT,
    MG_SLICE_VREF_MAX_NEW_BINARY,
    MG_SLICE_GROUP_VREF_MAX_NEW_BINARY,
    MG_SLICE_PREDICATE_COUNT
} mg_slice_predicate_t;

/* One fact: its predicate, its strings in order, and for a VREF limit the
 * integer that ends it. Strings belong to the snapshot or to the request. */
typedef struct {
    mg_slice_predicate_t predicate;
    const char *text[3];
    int64_t number;
} mg_slice_fact_t;

typedef struct {
    mg_slice_fact_t *facts;
    size_t count, capacity;
} mg_slice_t;

typedef struct {
    const char *user;
    const char *repository;
    const char *ref;                  /* NULL when the request has none */
    const char *const *paths;
    size_t path_count;
} mg_slice_request_t;

/* The name and arity of a slice predicate, as the audited program reads it. */
const char *mg_slice_predicate_name(mg_slice_predicate_t predicate);
size_t mg_slice_predicate_arity(mg_slice_predicate_t predicate);

/* Whether a ref grant's pattern applies to REF: an exact pattern is the ref;
 * a prefix (and a deny's bare literal) begins it, byte for byte. */
int mg_slice_pattern_matches(int prefix, const char *pattern, const char *ref);

/* The namespace N such that the request gives repository_owner_namespace(N,
 * USER) for REPOSITORY: the first of at least three segments, when the
 * second is the user. NULL otherwise; the result points into OUT. */
const char *mg_slice_owner_namespace(const char *repository, const char *user, char *out, size_t size);

/* The slice of GRANTS for REQUEST, sorted and without duplicates. It is
 * never truncated: the caller compares it with the engine's bounds. */
maelys_git_result_t mg_slice_extract(const mg_grants_t *grants, const mg_slice_request_t *request,
                                     mg_slice_t *out, maelys_git_error_t *error);
void mg_slice_clear(mg_slice_t *slice);

/* Total order of facts: predicate, then strings, then the number. */
int mg_slice_fact_compare(const mg_slice_fact_t *a, const mg_slice_fact_t *b);
/* Sorts the facts and drops duplicates. */
void mg_slice_normalize(mg_slice_t *slice);
/* Appends a fact; 0 when memory runs out. */
int mg_slice_add(mg_slice_t *slice, mg_slice_predicate_t predicate, const char *a, const char *b,
                 const char *c, int64_t number);

#endif
