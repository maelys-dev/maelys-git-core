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
 * level of each grant whose pattern matches the request's ref.
 *
 * Each version is the pieces marked for it, in order. Version 2 reads a
 * repository by a ref grant too, as Gitolite answers R any whatever the
 * refex; and it applies the denies of a ref and the VREF denies to merge
 * and update-ref as to push, since Gitolite writes a ref only by the push
 * its update hook judges, a merge being the push W of its result and an
 * update-ref the forced update +. Version 1, which did neither, stays byte
 * for byte what it was. */
#define IN_1 1u
#define IN_2 2u
#define IN_ALL (IN_1 | IN_2)

static const struct {
    unsigned versions; /* IN_1, IN_2 or both */
    const char *text;
} k_program[] = {
    {IN_1, "% " MG_GITOLITE_PROGRAM_FORMAT_1 ": the audited Gitolite program of Maelys Git Core.\n"},
    {IN_2, "% " MG_GITOLITE_PROGRAM_FORMAT_2 ": the audited Gitolite program of Maelys Git Core.\n"},
    {IN_ALL, "% Its grants are input facts, the slice of a snapshot for one request.\n"},
    {IN_ALL, "\n"},
    {IN_ALL, "effective_group_member(U, G) :- user(U), slice_member(U, G).\n"},
    {IN_ALL, "effective_group_member(U, G) :- user(U), effective_group_member(U, C), slice_nested(C, G).\n"},
    {IN_ALL, "can_create_namespace(U, N) :- user(U), repository_owner_namespace(N, U), slice_namespace_creator(U, N).\n"},
    {IN_ALL, "can_create_namespace(U, N) :- user(U), repository_owner_namespace(N, U), effective_group_member(U, G), slice_group_namespace_creator(G, N).\n"},
    {IN_ALL, "effective_access(U, P, L) :- user(U), repository(P), slice_access(U, P, L).\n"},
    {IN_ALL, "effective_access(U, P, L) :- user(U), repository(P), effective_group_member(U, G), slice_group_access(G, P, L).\n"},
    {IN_ALL, "effective_access(U, P, L) :- user(U), repository(P), repository_owner_namespace(N, U), slice_owner_access(N, L).\n"},
    {IN_ALL, "push_request(R, U, P, F) :- request(R), user(U), repository(P), operation(\"push\"), ref(F).\n"},
    {IN_ALL, "effective_ref_grant_push(U, P, F) :- user(U), repository(P), ref(F), slice_ref_match(U, P, \"RW\").\n"},
    {IN_ALL, "effective_ref_grant_push(U, P, F) :- user(U), repository(P), ref(F), slice_ref_match(U, P, \"RW+\").\n"},
    {IN_ALL, "effective_ref_grant_push(U, P, F) :- user(U), repository(P), ref(F), effective_group_member(U, G), slice_group_ref_match(G, P, \"RW\").\n"},
    {IN_ALL, "effective_ref_grant_push(U, P, F) :- user(U), repository(P), ref(F), effective_group_member(U, G), slice_group_ref_match(G, P, \"RW+\").\n"},
    {IN_ALL, "effective_ref_grant_force(U, P, F) :- user(U), repository(P), ref(F), slice_ref_match(U, P, \"RW+\").\n"},
    {IN_ALL, "effective_ref_grant_force(U, P, F) :- user(U), repository(P), ref(F), effective_group_member(U, G), slice_group_ref_match(G, P, \"RW+\").\n"},
    {IN_ALL, "effective_ref_deny(U, P, F) :- user(U), repository(P), ref(F), slice_ref_match(U, P, \"-\").\n"},
    {IN_ALL, "effective_ref_deny(U, P, F) :- user(U), repository(P), ref(F), effective_group_member(U, G), slice_group_ref_match(G, P, \"-\").\n"},
    {IN_ALL, "has_ref_write(U, P) :- user(U), repository(P), slice_ref_level(U, P, \"RW\").\n"},
    {IN_ALL, "has_ref_write(U, P) :- user(U), repository(P), slice_ref_level(U, P, \"RW+\").\n"},
    {IN_ALL, "has_ref_write(U, P) :- user(U), repository(P), effective_group_member(U, G), slice_group_ref_level(G, P, \"RW\").\n"},
    {IN_ALL, "has_ref_write(U, P) :- user(U), repository(P), effective_group_member(U, G), slice_group_ref_level(G, P, \"RW+\").\n"},
    {IN_ALL, "has_push_access(U, P) :- effective_access(U, P, \"RW\").\n"},
    {IN_ALL, "has_push_access(U, P) :- effective_access(U, P, \"RW+\").\n"},
    {IN_ALL, "has_push_access(U, P) :- has_ref_write(U, P).\n"},
    {IN_ALL, "\n"},
    {IN_ALL, "allow(R) :- request(R), user(U), repository(P), operation(\"read\"), effective_access(U, P, \"R\").\n"},
    {IN_ALL, "allow(R) :- request(R), user(U), repository(P), operation(\"read\"), effective_access(U, P, \"RW\").\n"},
    {IN_ALL, "allow(R) :- request(R), user(U), repository(P), operation(\"read\"), effective_access(U, P, \"RW+\").\n"},
    {IN_2, "allow(R) :- request(R), user(U), repository(P), operation(\"read\"), has_ref_write(U, P).\n"},
    {IN_ALL, "allow(R) :- request(R), user(U), repository(P), operation(\"write\"), effective_access(U, P, \"RW\").\n"},
    {IN_ALL, "allow(R) :- request(R), user(U), repository(P), operation(\"write\"), effective_access(U, P, \"RW+\").\n"},
    {IN_ALL, "allow(R) :- request(R), user(U), repository(P), operation(\"write\"), has_ref_write(U, P).\n"},
    {IN_ALL, "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), update_kind(\"create\"), effective_access(U, P, \"RW\").\n"},
    {IN_ALL, "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), update_kind(\"create\"), effective_access(U, P, \"RW+\").\n"},
    {IN_ALL, "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), update_kind(\"fast_forward\"), effective_access(U, P, \"RW\").\n"},
    {IN_ALL, "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), update_kind(\"fast_forward\"), effective_access(U, P, \"RW+\").\n"},
    {IN_ALL, "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), update_kind(\"force\"), effective_access(U, P, \"RW+\").\n"},
    {IN_ALL, "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), update_kind(\"delete\"), effective_access(U, P, \"RW+\").\n"},
    {IN_ALL, "allow(R) :- request(R), user(U), repository(P), operation(\"merge\"), effective_access(U, P, \"RW\").\n"},
    {IN_ALL, "allow(R) :- request(R), user(U), repository(P), operation(\"merge\"), effective_access(U, P, \"RW+\").\n"},
    {IN_ALL, "allow(R) :- request(R), user(U), repository(P), operation(\"update-ref\"), effective_access(U, P, \"RW+\").\n"},
    {IN_ALL, "allow(R) :- request(R), user(U), repository(P), operation(\"create\"), effective_access(U, P, \"C\").\n"},
    {IN_ALL, "allow(R) :- push_request(R, U, P, F), update_kind(\"create\"), effective_ref_grant_push(U, P, F).\n"},
    {IN_ALL, "allow(R) :- push_request(R, U, P, F), update_kind(\"fast_forward\"), effective_ref_grant_push(U, P, F).\n"},
    {IN_ALL, "allow(R) :- push_request(R, U, P, F), update_kind(\"force\"), effective_ref_grant_force(U, P, F).\n"},
    {IN_ALL, "allow(R) :- push_request(R, U, P, F), update_kind(\"delete\"), effective_ref_grant_force(U, P, F).\n"},
    {IN_ALL, "deny(R) :- push_request(R, U, P, F), effective_ref_deny(U, P, F).\n"},
    {IN_2, "deny(R) :- request(R), user(U), repository(P), operation(\"merge\"), ref(F), effective_ref_deny(U, P, F).\n"},
    {IN_2, "deny(R) :- request(R), user(U), repository(P), operation(\"update-ref\"), ref(F), effective_ref_deny(U, P, F).\n"},
    {IN_ALL, "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), changed_count(_), has_push_access(U, P).\n"},
    {IN_ALL, "allow(R) :- request(R), user(U), repository(P), operation(\"merge\"), ref(F), effective_ref_grant_push(U, P, F).\n"},
    {IN_ALL, "allow(R) :- request(R), user(U), repository(P), operation(\"update-ref\"), ref(F), effective_ref_grant_force(U, P, F).\n"},
    {IN_ALL, "allow(R) :- request(R), user(U), operation(\"create\"), repository_owner_namespace(N, U), can_create_namespace(U, N).\n"},
    {IN_ALL, "\n"},
    {IN_ALL, "vref_count_exceeded(U, P) :- user(U), repository(P), changed_count(C), slice_vref_count(U, P, N), C > N.\n"},
    {IN_ALL, "vref_count_exceeded(U, P) :- user(U), repository(P), changed_count(C), effective_group_member(U, G), slice_group_vref_count(G, P, N), C > N.\n"},
    {IN_ALL, "vref_new_count_exceeded(U, P) :- user(U), repository(P), added_count(C), slice_vref_new_count(U, P, N), C > N.\n"},
    {IN_ALL, "vref_new_count_exceeded(U, P) :- user(U), repository(P), added_count(C), effective_group_member(U, G), slice_group_vref_new_count(G, P, N), C > N.\n"},
    {IN_ALL, "vref_new_binary_exceeded(U, P) :- user(U), repository(P), change_binary(true), change_blob_size(S), slice_vref_max_new_binary(U, P, N), S > N.\n"},
    {IN_ALL, "vref_new_binary_exceeded(U, P) :- user(U), repository(P), change_binary(true), change_blob_size(S), effective_group_member(U, G), slice_group_vref_max_new_binary(G, P, N), S > N.\n"},
    {IN_ALL, "deny(R) :- request(R), user(U), repository(P), operation(\"push\"), path(F), slice_vref_name(U, P, F).\n"},
    {IN_ALL, "deny(R) :- request(R), user(U), repository(P), operation(\"push\"), path(F), effective_group_member(U, G), slice_group_vref_name(G, P, F).\n"},
    {IN_ALL, "deny(R) :- request(R), user(U), repository(P), operation(\"push\"), vref_count_exceeded(U, P).\n"},
    {IN_ALL, "deny(R) :- request(R), user(U), repository(P), operation(\"push\"), vref_new_count_exceeded(U, P).\n"},
    {IN_ALL, "deny(R) :- request(R), user(U), repository(P), operation(\"push\"), vref_new_binary_exceeded(U, P).\n"},
    {IN_2, "deny(R) :- request(R), user(U), repository(P), operation(\"merge\"), path(F), slice_vref_name(U, P, F).\n"},
    {IN_2, "deny(R) :- request(R), user(U), repository(P), operation(\"merge\"), path(F), effective_group_member(U, G), slice_group_vref_name(G, P, F).\n"},
    {IN_2, "deny(R) :- request(R), user(U), repository(P), operation(\"merge\"), vref_count_exceeded(U, P).\n"},
    {IN_2, "deny(R) :- request(R), user(U), repository(P), operation(\"merge\"), vref_new_count_exceeded(U, P).\n"},
    {IN_2, "deny(R) :- request(R), user(U), repository(P), operation(\"merge\"), vref_new_binary_exceeded(U, P).\n"},
    {IN_2, "deny(R) :- request(R), user(U), repository(P), operation(\"update-ref\"), path(F), slice_vref_name(U, P, F).\n"},
    {IN_2, "deny(R) :- request(R), user(U), repository(P), operation(\"update-ref\"), path(F), effective_group_member(U, G), slice_group_vref_name(G, P, F).\n"},
    {IN_2, "deny(R) :- request(R), user(U), repository(P), operation(\"update-ref\"), vref_count_exceeded(U, P).\n"},
    {IN_2, "deny(R) :- request(R), user(U), repository(P), operation(\"update-ref\"), vref_new_count_exceeded(U, P).\n"},
    {IN_2, "deny(R) :- request(R), user(U), repository(P), operation(\"update-ref\"), vref_new_binary_exceeded(U, P).\n"},
};

/* Each text is held in pieces, each within the length a compiler must
 * accept for a literal, and joined once. */
static pthread_once_t s_once = PTHREAD_ONCE_INIT;
static struct {
    char text[8192];
    size_t length;
    char sha256[MAELYS_CLI_SHA256_HEX_SIZE];
} s_versions[MG_GITOLITE_PROGRAM_VERSIONS];

static void join_programs(void) {
    for (unsigned v = 0u; v < MG_GITOLITE_PROGRAM_VERSIONS; ++v) {
        char *text = s_versions[v].text;
        size_t length = 0u;
        for (size_t i = 0u; i < sizeof(k_program) / sizeof(k_program[0]); ++i) {
            if (!(k_program[i].versions & (1u << v))) continue;
            size_t piece = strlen(k_program[i].text);
            if (length + piece >= sizeof(s_versions[v].text)) abort(); /* a text beyond its buffer is a build defect */
            memcpy(text + length, k_program[i].text, piece);
            length += piece;
        }
        text[length] = '\0';
        s_versions[v].length = length;
        maelys_cli_sha256_hex(text, length, s_versions[v].sha256);
    }
}

const char *mg_gitolite_program_text_of(unsigned version, size_t *length) {
    if (version < 1u || version > MG_GITOLITE_PROGRAM_VERSIONS) return NULL;
    (void)pthread_once(&s_once, join_programs);
    if (length) *length = s_versions[version - 1u].length;
    return s_versions[version - 1u].text;
}

const char *mg_gitolite_program_sha256_of(unsigned version) {
    if (version < 1u || version > MG_GITOLITE_PROGRAM_VERSIONS) return NULL;
    (void)pthread_once(&s_once, join_programs);
    return s_versions[version - 1u].sha256;
}

const char *mg_gitolite_program_format_of(unsigned version) {
    static const char *const formats[MG_GITOLITE_PROGRAM_VERSIONS] = {MG_GITOLITE_PROGRAM_FORMAT_1,
                                                                      MG_GITOLITE_PROGRAM_FORMAT_2};
    return version >= 1u && version <= MG_GITOLITE_PROGRAM_VERSIONS ? formats[version - 1u] : NULL;
}

unsigned mg_gitolite_program_version(const char *sha256) {
    if (!sha256) return 0u;
    for (unsigned version = 1u; version <= MG_GITOLITE_PROGRAM_VERSIONS; ++version)
        if (!strcmp(sha256, mg_gitolite_program_sha256_of(version))) return version;
    return 0u;
}

const char *mg_gitolite_program_text(size_t *length) {
    return mg_gitolite_program_text_of(MG_GITOLITE_PROGRAM_VERSION, length);
}

const char *mg_gitolite_program_sha256(void) {
    return mg_gitolite_program_sha256_of(MG_GITOLITE_PROGRAM_VERSION);
}
