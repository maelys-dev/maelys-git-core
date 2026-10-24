#include "policy/program.h"

#include <maelys/cli/digest.h>

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

/* Each rule that reads a slice_* fact first binds its subject to the
 * request's user or to one of its groups, its repository to the request's
 * or to a namespace the request gives, and a path to one of the request's:
 * the slice holds every fact such a rule can use (see policy/slice.h).
 * Two readings have no ref: has_ref_write reads slice_ref_level, the write
 * levels held on any ref of the repository, and the VREF limits are all in
 * the slice. Ref patterns are matched by Git Core: slice_ref_match holds the
 * level of each grant whose pattern matches the request's ref. */
static const char *const k_program[] = {
    "% " MG_GITOLITE_PROGRAM_FORMAT ": the audited Gitolite program of Maelys Git Core.\n",
    "% Its grants are input facts, the slice of a snapshot for one request.\n",
    "\n",
    "effective_group_member(U, G) :- user(U), slice_member(U, G).\n",
    "effective_group_member(U, G) :- user(U), effective_group_member(U, C), slice_nested(C, G).\n",
    "can_create_namespace(U, N) :- user(U), repository_owner_namespace(N, U), slice_namespace_creator(U, N).\n",
    "can_create_namespace(U, N) :- user(U), repository_owner_namespace(N, U), effective_group_member(U, G), slice_group_namespace_creator(G, N).\n",
    "effective_access(U, P, L) :- user(U), repository(P), slice_access(U, P, L).\n",
    "effective_access(U, P, L) :- user(U), repository(P), effective_group_member(U, G), slice_group_access(G, P, L).\n",
    "effective_access(U, P, L) :- user(U), repository(P), repository_owner_namespace(N, U), slice_owner_access(N, L).\n",
    "push_request(R, U, P, F) :- request(R), user(U), repository(P), operation(\"push\"), ref(F).\n",
    "effective_ref_grant_push(U, P, F) :- user(U), repository(P), ref(F), slice_ref_match(U, P, \"RW\").\n",
    "effective_ref_grant_push(U, P, F) :- user(U), repository(P), ref(F), slice_ref_match(U, P, \"RW+\").\n",
    "effective_ref_grant_push(U, P, F) :- user(U), repository(P), ref(F), effective_group_member(U, G), slice_group_ref_match(G, P, \"RW\").\n",
    "effective_ref_grant_push(U, P, F) :- user(U), repository(P), ref(F), effective_group_member(U, G), slice_group_ref_match(G, P, \"RW+\").\n",
    "effective_ref_grant_force(U, P, F) :- user(U), repository(P), ref(F), slice_ref_match(U, P, \"RW+\").\n",
    "effective_ref_grant_force(U, P, F) :- user(U), repository(P), ref(F), effective_group_member(U, G), slice_group_ref_match(G, P, \"RW+\").\n",
    "effective_ref_deny(U, P, F) :- user(U), repository(P), ref(F), slice_ref_match(U, P, \"-\").\n",
    "effective_ref_deny(U, P, F) :- user(U), repository(P), ref(F), effective_group_member(U, G), slice_group_ref_match(G, P, \"-\").\n",
    "has_ref_write(U, P) :- user(U), repository(P), slice_ref_level(U, P, \"RW\").\n",
    "has_ref_write(U, P) :- user(U), repository(P), slice_ref_level(U, P, \"RW+\").\n",
    "has_ref_write(U, P) :- user(U), repository(P), effective_group_member(U, G), slice_group_ref_level(G, P, \"RW\").\n",
    "has_ref_write(U, P) :- user(U), repository(P), effective_group_member(U, G), slice_group_ref_level(G, P, \"RW+\").\n",
    "has_push_access(U, P) :- effective_access(U, P, \"RW\").\n",
    "has_push_access(U, P) :- effective_access(U, P, \"RW+\").\n",
    "has_push_access(U, P) :- has_ref_write(U, P).\n",
    "\n",
    "allow(R) :- request(R), user(U), repository(P), operation(\"read\"), effective_access(U, P, \"R\").\n",
    "allow(R) :- request(R), user(U), repository(P), operation(\"read\"), effective_access(U, P, \"RW\").\n",
    "allow(R) :- request(R), user(U), repository(P), operation(\"read\"), effective_access(U, P, \"RW+\").\n",
    "allow(R) :- request(R), user(U), repository(P), operation(\"write\"), effective_access(U, P, \"RW\").\n",
    "allow(R) :- request(R), user(U), repository(P), operation(\"write\"), effective_access(U, P, \"RW+\").\n",
    "allow(R) :- request(R), user(U), repository(P), operation(\"write\"), has_ref_write(U, P).\n",
    "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), update_kind(\"create\"), effective_access(U, P, \"RW\").\n",
    "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), update_kind(\"create\"), effective_access(U, P, \"RW+\").\n",
    "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), update_kind(\"fast_forward\"), effective_access(U, P, \"RW\").\n",
    "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), update_kind(\"fast_forward\"), effective_access(U, P, \"RW+\").\n",
    "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), update_kind(\"force\"), effective_access(U, P, \"RW+\").\n",
    "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), update_kind(\"delete\"), effective_access(U, P, \"RW+\").\n",
    "allow(R) :- request(R), user(U), repository(P), operation(\"merge\"), effective_access(U, P, \"RW\").\n",
    "allow(R) :- request(R), user(U), repository(P), operation(\"merge\"), effective_access(U, P, \"RW+\").\n",
    "allow(R) :- request(R), user(U), repository(P), operation(\"update-ref\"), effective_access(U, P, \"RW+\").\n",
    "allow(R) :- request(R), user(U), repository(P), operation(\"create\"), effective_access(U, P, \"C\").\n",
    "allow(R) :- push_request(R, U, P, F), update_kind(\"create\"), effective_ref_grant_push(U, P, F).\n",
    "allow(R) :- push_request(R, U, P, F), update_kind(\"fast_forward\"), effective_ref_grant_push(U, P, F).\n",
    "allow(R) :- push_request(R, U, P, F), update_kind(\"force\"), effective_ref_grant_force(U, P, F).\n",
    "allow(R) :- push_request(R, U, P, F), update_kind(\"delete\"), effective_ref_grant_force(U, P, F).\n",
    "deny(R) :- push_request(R, U, P, F), effective_ref_deny(U, P, F).\n",
    "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), changed_count(_), has_push_access(U, P).\n",
    "allow(R) :- request(R), user(U), repository(P), operation(\"merge\"), ref(F), effective_ref_grant_push(U, P, F).\n",
    "allow(R) :- request(R), user(U), repository(P), operation(\"update-ref\"), ref(F), effective_ref_grant_force(U, P, F).\n",
    "allow(R) :- request(R), user(U), operation(\"create\"), repository_owner_namespace(N, U), can_create_namespace(U, N).\n",
    "\n",
    "vref_count_exceeded(U, P) :- user(U), repository(P), changed_count(C), slice_vref_count(U, P, N), C > N.\n",
    "vref_count_exceeded(U, P) :- user(U), repository(P), changed_count(C), effective_group_member(U, G), slice_group_vref_count(G, P, N), C > N.\n",
    "vref_new_count_exceeded(U, P) :- user(U), repository(P), added_count(C), slice_vref_new_count(U, P, N), C > N.\n",
    "vref_new_count_exceeded(U, P) :- user(U), repository(P), added_count(C), effective_group_member(U, G), slice_group_vref_new_count(G, P, N), C > N.\n",
    "vref_new_binary_exceeded(U, P) :- user(U), repository(P), change_binary(true), change_blob_size(S), slice_vref_max_new_binary(U, P, N), S > N.\n",
    "vref_new_binary_exceeded(U, P) :- user(U), repository(P), change_binary(true), change_blob_size(S), effective_group_member(U, G), slice_group_vref_max_new_binary(G, P, N), S > N.\n",
    "deny(R) :- request(R), user(U), repository(P), operation(\"push\"), path(F), slice_vref_name(U, P, F).\n",
    "deny(R) :- request(R), user(U), repository(P), operation(\"push\"), path(F), effective_group_member(U, G), slice_group_vref_name(G, P, F).\n",
    "deny(R) :- request(R), user(U), repository(P), operation(\"push\"), vref_count_exceeded(U, P).\n",
    "deny(R) :- request(R), user(U), repository(P), operation(\"push\"), vref_new_count_exceeded(U, P).\n",
    "deny(R) :- request(R), user(U), repository(P), operation(\"push\"), vref_new_binary_exceeded(U, P).\n",
};

/* The text is held in pieces, each within the length a compiler must
 * accept for a literal, and joined once. */
static pthread_once_t s_once = PTHREAD_ONCE_INIT;
static char s_text[8192];
static size_t s_length;
static char s_sha256[MAELYS_CLI_SHA256_HEX_SIZE];

static void join_program(void) {
    for (size_t i = 0u; i < sizeof(k_program) / sizeof(k_program[0]); ++i) {
        size_t piece = strlen(k_program[i]);
        if (s_length + piece >= sizeof(s_text)) abort(); /* a text beyond its buffer is a build defect */
        memcpy(s_text + s_length, k_program[i], piece);
        s_length += piece;
    }
    s_text[s_length] = '\0';
    maelys_cli_sha256_hex(s_text, s_length, s_sha256);
}

const char *mg_gitolite_program_text(size_t *length) {
    (void)pthread_once(&s_once, join_program);
    if (length) *length = s_length;
    return s_text;
}

const char *mg_gitolite_program_sha256(void) {
    (void)pthread_once(&s_once, join_program);
    return s_sha256;
}
