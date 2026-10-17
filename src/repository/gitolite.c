#include "internal.h"

#include <maelys/cli/digest.h>

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MG_GITOLITE_MAX_CURRENT_REPOSITORIES 64u

typedef struct {
    char *data;
    size_t length;
    size_t capacity;
} text_buffer_t;

typedef enum {
    REPOSITORY_EXACT = 1,
    REPOSITORY_CREATOR_NAMESPACE = 2
} repository_spec_kind_t;

typedef struct {
    repository_spec_kind_t kind;
    char value[512];
} repository_spec_t;

static int append_text(text_buffer_t *buffer, const char *format, ...) MG_PRINTF(2, 3);

static int append_text(text_buffer_t *buffer, const char *format, ...) {
    va_list args;
    va_start(args, format);
    va_list copy;
    va_copy(copy, args);
    int required = vsnprintf(NULL, 0u, format, copy);
    va_end(copy);
    if (required < 0) { va_end(args); return 0; }
    size_t wanted = buffer->length + (size_t)required + 1u;
    if (wanted > buffer->capacity) {
        size_t next = buffer->capacity ? buffer->capacity : 4096u;
        while (next < wanted) {
            if (next > SIZE_MAX / 2u) { va_end(args); return 0; }
            next *= 2u;
        }
        char *grown = realloc(buffer->data, next);
        if (!grown) { va_end(args); return 0; }
        buffer->data = grown;
        buffer->capacity = next;
    }
    (void)vsnprintf(buffer->data + buffer->length,
                    buffer->capacity - buffer->length, format, args);
    va_end(args);
    buffer->length += (size_t)required;
    return 1;
}

static char *trim(char *value) {
    while (isspace((unsigned char)*value)) ++value;
    char *end = value + strlen(value);
    while (end > value && isspace((unsigned char)end[-1])) --end;
    *end = '\0';
    return value;
}

static int safe_atom(const char *value) {
    if (!value || !*value) return 0;
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p)
        if (!(isalnum(*p) || *p == '.' || *p == '_' || *p == '-')) return 0;
    return 1;
}

static int safe_exact_path(const char *value) {
    if (!value || !*value || value[0] == '/' || value[strlen(value) - 1u] == '/')
        return 0;
    const char *component = value;
    for (const unsigned char *p = (const unsigned char *)value;; ++p) {
        if (*p == '/' || *p == '\0') {
            size_t length = (size_t)((const char *)p - component);
            if (!length || (length == 1u && component[0] == '.') ||
                (length == 2u && component[0] == '.' && component[1] == '.'))
                return 0;
            if (*p == '\0') break;
            component = (const char *)p + 1u;
        } else if (!(isalnum(*p) || *p == '.' || *p == '_' || *p == '-')) {
            return 0;
        }
    }
    return strlen(value) < 64u;
}

static int parse_limit(const char *value, unsigned long long *out) {
    if (!value || !*value || !out) return 0;
    errno = 0;
    char *end = NULL;
    unsigned long long parsed = strtoull(value, &end, 10);
    if (errno || !end || *end || parsed > INT64_MAX) return 0;
    *out = parsed;
    return 1;
}

static int normalize_repository(const char *input, repository_spec_t *output) {
    static const char creator_suffix[] = "/CREATOR/..*";
    size_t input_length = input ? strlen(input) : 0u;
    size_t suffix_length = sizeof(creator_suffix) - 1u;
    if (input_length > suffix_length &&
        !strcmp(input + input_length - suffix_length, creator_suffix)) {
        size_t namespace_length = input_length - suffix_length;
        if (namespace_length >= sizeof(output->value)) return 0;
        memcpy(output->value, input, namespace_length);
        output->value[namespace_length] = '\0';
        if (!safe_atom(output->value)) return 0;
        output->kind = REPOSITORY_CREATOR_NAMESPACE;
        return 1;
    }
    if (!input || !*input || strchr(input, '*') || strchr(input, '?') ||
        strchr(input, '[') || strchr(input, ']') || strchr(input, '^') ||
        strchr(input, '$') || strchr(input, '(') || strchr(input, ')') ||
        strchr(input, '|') || strchr(input, '+')) return 0;
    size_t length = strlen(input);
    int has_suffix = length >= 4u && strcmp(input + length - 4u, ".git") == 0;
    int written = snprintf(output->value, sizeof(output->value), "%s%s",
                           input, has_suffix ? "" : ".git");
    output->kind = REPOSITORY_EXACT;
    return written > 0 && (size_t)written < sizeof(output->value) &&
           maelys_git_repository_name_is_valid(output->value);
}

static int add_unsupported(maelys_git_gitolite_migration_result_t *result,
                           size_t line_number,
                           const char *reason,
                           const char *source) {
    if (result->unsupported_count >= 1024u) return 0;
    char message[4608];
    int length = snprintf(message, sizeof(message), "line %zu: %s: %s",
                          line_number, reason, source);
    if (length < 0 || (size_t)length >= sizeof(message)) return 0;
    char **grown = realloc(result->unsupported,
                           (result->unsupported_count + 1u) * sizeof(*grown));
    if (!grown) return 0;
    result->unsupported = grown;
    grown[result->unsupported_count] = strdup(message);
    if (!grown[result->unsupported_count]) return 0;
    ++result->unsupported_count;
    return 1;
}

void maelys_git_gitolite_migration_result_clear(
    maelys_git_gitolite_migration_result_t *result) {
    if (!result) return;
    for (size_t i = 0u; i < result->unsupported_count; ++i)
        free(result->unsupported[i]);
    free(result->unsupported);
    memset(result, 0, sizeof(*result));
}

static int append_direct_grant(text_buffer_t *policy,
                               const char *right,
                               const char *subject,
                               const char *repository) {
    const char *prefix = subject[0] == '@' ? "group_" : "";
    const char *name = subject[0] == '@' ? subject + 1u : subject;
    if (!safe_atom(name)) return 0;
    if (!strcmp(right, "C"))
        return append_text(policy, "%sgrant_create(\"%s\", \"%s\").\n",
                           prefix, name, repository);
    if (!strcmp(right, "R"))
        return append_text(policy, "%sgrant_read(\"%s\", \"%s\").\n",
                           prefix, name, repository);
    if (!strcmp(right, "RW") || !strcmp(right, "RW+")) {
        if (!append_text(policy, "%sgrant_read(\"%s\", \"%s\").\n",
                         prefix, name, repository) ||
            !append_text(policy, "%sgrant_write(\"%s\", \"%s\").\n",
                         prefix, name, repository) ||
            !append_text(policy, "%sgrant_push(\"%s\", \"%s\").\n",
                         prefix, name, repository)) return 0;
        if (!strcmp(right, "RW+"))
            return append_text(policy, "%sgrant_force(\"%s\", \"%s\").\n",
                               prefix, name, repository);
        return 1;
    }
    return 0;
}

static int append_creator_namespace_grant(text_buffer_t *policy,
                                          const char *right,
                                          const char *subject,
                                          const char *namespace_name) {
    if (!strcmp(right, "C")) {
        if (!strcmp(subject, "CREATOR")) return 0;
        const char *prefix = subject[0] == '@' ? "group_" : "";
        const char *name = subject[0] == '@' ? subject + 1u : subject;
        if (!safe_atom(name)) return 0;
        return append_text(policy, "%snamespace_creator(\"%s\", \"%s\").\n",
                           prefix, name, namespace_name);
    }
    if (strcmp(subject, "CREATOR")) return 0;
    if (!strcmp(right, "R"))
        return append_text(policy, "owner_namespace_grant_read(\"%s\").\n",
                           namespace_name);
    if (!strcmp(right, "RW") || !strcmp(right, "RW+")) {
        if (!append_text(policy, "owner_namespace_grant_read(\"%s\").\n",
                         namespace_name) ||
            !append_text(policy, "owner_namespace_grant_write(\"%s\").\n",
                         namespace_name) ||
            !append_text(policy, "owner_namespace_grant_push(\"%s\").\n",
                         namespace_name)) return 0;
        return strcmp(right, "RW+") ||
               append_text(policy, "owner_namespace_grant_force(\"%s\").\n",
                           namespace_name);
    }
    return 0;
}

static int append_vref_fact(text_buffer_t *policy,
                            const char *predicate,
                            const char *subject,
                            const char *repository,
                            const char *symbol_value,
                            const unsigned long long *integer_value) {
    const char *prefix = subject[0] == '@' ? "group_" : "";
    const char *name = subject[0] == '@' ? subject + 1u : subject;
    if (!safe_atom(name)) return 0;
    if (symbol_value)
        return append_text(policy, "%s%s(\"%s\", \"%s\", \"%s\").\n",
                           prefix, predicate, name, repository, symbol_value);
    return integer_value &&
           append_text(policy, "%s%s(\"%s\", \"%s\", %llu).\n",
                       prefix, predicate, name, repository, *integer_value);
}

static int append_ref_fact(text_buffer_t *policy,
                           const char *predicate,
                           const char *subject,
                           const char *repository,
                           const char *ref_name) {
    const char *prefix = subject[0] == '@' ? "group_" : "";
    const char *name = subject[0] == '@' ? subject + 1u : subject;
    return safe_atom(name) && maelys_git_ref_name_is_valid(ref_name) &&
           strlen(ref_name) < 64u &&
           append_text(policy, "%s%s(\"%s\", \"%s\", \"%s\").\n",
                       prefix, predicate, name, repository, ref_name);
}

/* The longest filter pattern the policy language accepts. */
#define MG_REF_PATTERN_MAX 256u

typedef enum {
    REFEX_EXACT = 1,
    REFEX_PREFIX = 2
} refex_kind_t;

/* Reads one Gitolite refex and returns NULL, or the stable reason it is
 * refused. Gitolite anchors a refex at its start only, completes a name that
 * does not begin with refs/ by refs/heads/, and takes a final $ as equality.
 * Only literal names are converted, into a form whose equivalence holds:
 *   - a literal ending in '/' is a prefix;
 *   - a literal ending in '$' is the exact ref without the '$';
 *   - a bare literal denies as a prefix, which is what Gitolite does, and
 *     grants the exact ref only, which is stricter than Gitolite.
 * Alternation, classes, repetition and any other regular-expression syntax
 * have no bounded equivalent and are refused. */
static const char *classify_refex(const char *text, int deny, refex_kind_t *out_kind,
                                  char out_value[MG_REF_PATTERN_MAX + 1u]) {
    size_t length = strlen(text);
    int anchored = length > 0u && text[length - 1u] == '$';
    size_t body = anchored ? length - 1u : length;
    if (body == 0u) return "unsupported refex syntax";
    for (size_t i = 0u; i < body; ++i) {
        unsigned char ch = (unsigned char)text[i];
        if (!(isalnum(ch) || ch == '.' || ch == '_' || ch == '/' || ch == '-'))
            return "unsupported refex syntax";
    }
    const char *implied = strncmp(text, "refs/", 5u) == 0 ? "" : "refs/heads/";
    if (strlen(implied) + body > MG_REF_PATTERN_MAX) return "ref pattern exceeds 256 bytes";
    (void)snprintf(out_value, MG_REF_PATTERN_MAX + 1u, "%s%.*s", implied, (int)body, text);
    if (strstr(out_value, "..") || strstr(out_value, "//")) return "unsupported refex syntax";
    int open_namespace = out_value[strlen(out_value) - 1u] == '/';
    if (anchored && open_namespace) return "unsupported refex syntax";
    if (!anchored && (open_namespace || deny)) {
        *out_kind = REFEX_PREFIX;
        return NULL;
    }
    /* An exact ref is a policy atom: the full-ref form and the atom length apply. */
    if (!maelys_git_ref_name_is_valid(out_value)) return "unsupported refex syntax";
    if (strlen(out_value) >= 64u) return "exact ref exceeds 63 bytes";
    *out_kind = REFEX_EXACT;
    return NULL;
}

/* Appends a line unless the policy already has it: several prefix rules of
 * one subject share their two access rules. */
static int append_once(text_buffer_t *policy, const char *line) {
    if (policy->data && strstr(policy->data, line)) return 1;
    return append_text(policy, "%s", line);
}

/* A prefix is policy code: a rule with a constant filter pattern, never an
 * atom. The pattern holds only [A-Za-z0-9._/-], so it needs no escaping. The
 * access rules keep what an exact grant gives to requests that carry no ref:
 * the write operation and the summary of a push. */
static int append_ref_prefix_rules(text_buffer_t *policy, const char *right,
                                   const char *subject, const char *repository,
                                   const char *pattern) {
    int group = subject[0] == '@';
    const char *name = group ? subject + 1u : subject;
    if (!safe_atom(name) || strlen(pattern) > MG_REF_PATTERN_MAX) return 0;
    char who[160], member[224], line[1024];
    if (group) {
        (void)snprintf(who, sizeof(who), "U");
        (void)snprintf(member, sizeof(member), "effective_group_member(U, \"%s\"), ", name);
    } else {
        (void)snprintf(who, sizeof(who), "\"%s\"", name);
        member[0] = '\0';
    }
    static const char *const grant_heads[] = {"effective_ref_grant_push", "effective_ref_grant_force"};
    if (!strcmp(right, "-")) {
        (void)snprintf(line, sizeof(line),
                       "effective_ref_deny(%s, \"%s\", F) :- %sref(F), starts_with(F, \"%s\").\n",
                       who, repository, member, pattern);
        return append_once(policy, line);
    }
    if (strcmp(right, "RW") && strcmp(right, "RW+")) return 0;
    size_t heads = strcmp(right, "RW+") ? 1u : 2u;
    for (size_t i = 0u; i < heads; ++i) {
        (void)snprintf(line, sizeof(line),
                       "%s(%s, \"%s\", F) :- %sref(F), starts_with(F, \"%s\").\n",
                       grant_heads[i], who, repository, member, pattern);
        if (!append_once(policy, line)) return 0;
    }
    static const char *const access_heads[] = {"has_ref_write", "has_push_access"};
    for (size_t i = 0u; i < 2u; ++i) {
        if (group)
            (void)snprintf(line, sizeof(line),
                           "%s(U, \"%s\") :- effective_group_member(U, \"%s\").\n",
                           access_heads[i], repository, name);
        else
            (void)snprintf(line, sizeof(line),
                           "%s(\"%s\", \"%s\") :- user(\"%s\"), repository(\"%s\").\n",
                           access_heads[i], name, repository, name, repository);
        if (!append_once(policy, line)) return 0;
    }
    return 1;
}

static int append_ref_grant(text_buffer_t *policy,
                            const char *right,
                            const char *subject,
                            const char *repository,
                            refex_kind_t kind,
                            const char *ref_name) {
    if (kind == REFEX_PREFIX)
        return append_ref_prefix_rules(policy, right, subject, repository, ref_name);
    if (!strcmp(right, "-"))
        return append_ref_fact(policy, "ref_deny", subject, repository, ref_name);
    if (strcmp(right, "RW") && strcmp(right, "RW+")) return 0;
    if (!append_ref_fact(policy, "ref_grant_push", subject, repository, ref_name))
        return 0;
    return strcmp(right, "RW+") ||
           append_ref_fact(policy, "ref_grant_force", subject, repository, ref_name);
}

static int append_authorization_rules(text_buffer_t *policy) {
    if (!append_text(policy,
        "\neffective_group_member(U, G) :- group_member(U, G).\n"
        "effective_group_member(U, G) :- group_member(U, C), group_in_group(C, G).\n"
        "effective_group_member(U, G) :- effective_group_member(U, C), group_in_group(C, G).\n"
        "can_create_namespace(U, N) :- namespace_creator(U, N).\n"
        "can_create_namespace(U, N) :- effective_group_member(U, G), group_namespace_creator(G, N).\n"
        "push_request(R, U, P, F) :- request(R), user(U), repository(P), operation(\"push\"), ref(F).\n"
        "effective_ref_grant_push(U, P, F) :- ref_grant_push(U, P, F).\n"
        "effective_ref_grant_push(U, P, F) :- effective_group_member(U, G), group_ref_grant_push(G, P, F).\n"
        "effective_ref_grant_force(U, P, F) :- ref_grant_force(U, P, F).\n"
        "effective_ref_grant_force(U, P, F) :- effective_group_member(U, G), group_ref_grant_force(G, P, F).\n"
        "effective_ref_deny(U, P, F) :- ref_deny(U, P, F).\n"
        "effective_ref_deny(U, P, F) :- effective_group_member(U, G), group_ref_deny(G, P, F).\n"
        "has_ref_write(U, P) :- effective_ref_grant_push(U, P, _).\n"
        "has_push_access(U, P) :- grant_push(U, P).\n"
        "has_push_access(U, P) :- grant_force(U, P).\n"
        "has_push_access(U, P) :- effective_group_member(U, G), group_grant_push(G, P).\n"
        "has_push_access(U, P) :- effective_group_member(U, G), group_grant_force(G, P).\n"
        "has_push_access(U, P) :- effective_ref_grant_push(U, P, _).\n"
        "has_push_access(U, P) :- effective_ref_grant_force(U, P, _).\n"
        "\nallow(R) :- request(R), user(U), repository(P), operation(\"read\"), grant_read(U, P).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"write\"), grant_write(U, P).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), update_kind(\"create\"), grant_push(U, P).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), update_kind(\"fast_forward\"), grant_push(U, P).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), update_kind(\"force\"), grant_force(U, P).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), update_kind(\"delete\"), grant_force(U, P).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"merge\"), grant_push(U, P).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"update-ref\"), grant_force(U, P).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"create\"), grant_create(U, P).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"read\"), effective_group_member(U, G), group_grant_read(G, P).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"write\"), effective_group_member(U, G), group_grant_write(G, P).\n"))
        return 0;
    if (!append_text(policy,
        "allow(R) :- push_request(R, U, P, F), update_kind(\"create\"), effective_ref_grant_push(U, P, F).\n"
        "allow(R) :- push_request(R, U, P, F), update_kind(\"fast_forward\"), effective_ref_grant_push(U, P, F).\n"
        "allow(R) :- push_request(R, U, P, F), update_kind(\"force\"), effective_ref_grant_force(U, P, F).\n"
        "allow(R) :- push_request(R, U, P, F), update_kind(\"delete\"), effective_ref_grant_force(U, P, F).\n"
        "deny(R) :- push_request(R, U, P, F), effective_ref_deny(U, P, F).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"write\"), has_ref_write(U, P).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), changed_count(_), has_push_access(U, P).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"merge\"), ref(F), effective_ref_grant_push(U, P, F).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"update-ref\"), ref(F), effective_ref_grant_force(U, P, F).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), update_kind(\"create\"), effective_group_member(U, G), group_grant_push(G, P).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), update_kind(\"fast_forward\"), effective_group_member(U, G), group_grant_push(G, P).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), update_kind(\"force\"), effective_group_member(U, G), group_grant_force(G, P).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), update_kind(\"delete\"), effective_group_member(U, G), group_grant_force(G, P).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"merge\"), effective_group_member(U, G), group_grant_push(G, P).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"update-ref\"), effective_group_member(U, G), group_grant_force(G, P).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"create\"), effective_group_member(U, G), group_grant_create(G, P).\n"
        "allow(R) :- request(R), user(U), operation(\"create\"), repository_owner_namespace(N, U), can_create_namespace(U, N).\n"
        "allow(R) :- request(R), user(U), operation(\"read\"), repository_owner_namespace(N, U), owner_namespace_grant_read(N).\n"
        "allow(R) :- request(R), user(U), operation(\"write\"), repository_owner_namespace(N, U), owner_namespace_grant_write(N).\n"
        "allow(R) :- request(R), user(U), operation(\"push\"), update_kind(\"create\"), repository_owner_namespace(N, U), owner_namespace_grant_push(N).\n"
        "allow(R) :- request(R), user(U), operation(\"push\"), update_kind(\"fast_forward\"), repository_owner_namespace(N, U), owner_namespace_grant_push(N).\n"
        "allow(R) :- request(R), user(U), operation(\"push\"), update_kind(\"force\"), repository_owner_namespace(N, U), owner_namespace_grant_force(N).\n"
        "allow(R) :- request(R), user(U), operation(\"push\"), update_kind(\"delete\"), repository_owner_namespace(N, U), owner_namespace_grant_force(N).\n"
        "allow(R) :- request(R), user(U), operation(\"push\"), changed_count(_), repository_owner_namespace(N, U), owner_namespace_grant_push(N).\n"
        "allow(R) :- request(R), user(U), operation(\"push\"), changed_count(_), repository_owner_namespace(N, U), owner_namespace_grant_force(N).\n"
        "allow(R) :- request(R), user(U), operation(\"merge\"), repository_owner_namespace(N, U), owner_namespace_grant_push(N).\n"
        "allow(R) :- request(R), user(U), operation(\"update-ref\"), repository_owner_namespace(N, U), owner_namespace_grant_force(N).\n"))
        return 0;
    return append_text(policy,
        "effective_vref_deny_name(U, P, F) :- vref_deny_name(U, P, F).\n"
        "effective_vref_deny_name(U, P, F) :- effective_group_member(U, G), group_vref_deny_name(G, P, F).\n"
        "effective_vref_deny_count(U, P, N) :- vref_deny_count(U, P, N).\n"
        "effective_vref_deny_count(U, P, N) :- effective_group_member(U, G), group_vref_deny_count(G, P, N).\n"
        "effective_vref_deny_new_count(U, P, N) :- vref_deny_new_count(U, P, N).\n"
        "effective_vref_deny_new_count(U, P, N) :- effective_group_member(U, G), group_vref_deny_new_count(G, P, N).\n"
        "effective_vref_deny_max_new_binary(U, P, N) :- vref_deny_max_new_binary(U, P, N).\n"
        "effective_vref_deny_max_new_binary(U, P, N) :- effective_group_member(U, G), group_vref_deny_max_new_binary(G, P, N).\n"
        "vref_count_exceeded(U, P) :- changed_count(C), effective_vref_deny_count(U, P, N), C > N.\n"
        "vref_new_count_exceeded(U, P) :- added_count(C), effective_vref_deny_new_count(U, P, N), C > N.\n"
        "vref_new_binary_exceeded(U, P) :- change_binary(true), change_blob_size(S), effective_vref_deny_max_new_binary(U, P, N), S > N.\n"
        "deny(R) :- request(R), user(U), repository(P), operation(\"push\"), path(F), effective_vref_deny_name(U, P, F).\n"
        "deny(R) :- request(R), user(U), repository(P), operation(\"push\"), vref_count_exceeded(U, P).\n"
        "deny(R) :- request(R), user(U), repository(P), operation(\"push\"), vref_new_count_exceeded(U, P).\n"
        "deny(R) :- request(R), user(U), repository(P), operation(\"push\"), vref_new_binary_exceeded(U, P).\n");
}

typedef struct {
    const char *predicate;
    const char *symbol_value;
    unsigned long long integer_value;
    int uses_integer;
} vref_rule_t;

static int parse_vref_rule(char *descriptor, vref_rule_t *out) {
    memset(out, 0, sizeof(*out));
    if (strncmp(descriptor, "VREF/", 5u) != 0) return 0;
    char *kind = descriptor + 5u;
    if (!strncmp(kind, "NAME/", 5u)) {
        char *path = kind + 5u;
        if (!safe_exact_path(path)) return 0;
        out->predicate = "vref_deny_name";
        out->symbol_value = path;
        return 1;
    }
    if (!strncmp(kind, "COUNT/", 6u)) {
        char *limit = kind + 6u;
        char *qualifier = strchr(limit, '/');
        if (qualifier) *qualifier++ = '\0';
        if (!parse_limit(limit, &out->integer_value)) return 0;
        if (!qualifier || !*qualifier) out->predicate = "vref_deny_count";
        else if (!strcmp(qualifier, "NEWFILES")) out->predicate = "vref_deny_new_count";
        else return 0;
        out->uses_integer = 1;
        return 1;
    }
    if (!strncmp(kind, "MAX_NEWBIN_SIZE/", 16u)) {
        char *limit = kind + 16u;
        if (!parse_limit(limit, &out->integer_value)) return 0;
        out->predicate = "vref_deny_max_new_binary";
        out->uses_integer = 1;
        return 1;
    }
    return 0;
}

static maelys_git_result_t parse_gitolite(FILE *input,
                                          text_buffer_t *policy,
                                          maelys_git_gitolite_migration_result_t *migration,
                                          maelys_git_error_t *error) {
    char line[4096];
    repository_spec_t repositories[MG_GITOLITE_MAX_CURRENT_REPOSITORIES];
    size_t repository_count = 0u, line_number = 0u;
    while (fgets(line, sizeof(line), input)) {
        ++line_number;
        size_t raw_length = strlen(line);
        if (raw_length && line[raw_length - 1u] != '\n' && !feof(input)) {
            mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0,
                         "Gitolite line %zu exceeds 4095 bytes", line_number);
            return MAELYS_GIT_ERR_LIMIT;
        }
        while (raw_length && (line[raw_length - 1u] == '\n' ||
                              line[raw_length - 1u] == '\r'))
            line[--raw_length] = '\0';
        char original[4096];
        (void)mg_copy_string(original, sizeof(original), line);
        char *comment = strchr(line, '#');
        if (comment) *comment = '\0';
        char *content = trim(line);
        if (!*content || !strncmp(content, "include ", 8u) ||
            !strncmp(content, "subconf ", 8u)) {
            if (*content && !add_unsupported(migration, line_number,
                                             "include/subconf requires manual expansion", original))
                return MAELYS_GIT_ERR_IO;
            continue;
        }
        if (content[0] == '@') {
            char *equals = strchr(content, '=');
            if (!equals) {
                if (!add_unsupported(migration, line_number, "invalid group definition", original))
                    return MAELYS_GIT_ERR_IO;
                continue;
            }
            *equals = '\0';
            char *group = trim(content) + 1u;
            char *members = trim(equals + 1u);
            if (!safe_atom(group)) {
                if (!add_unsupported(migration, line_number, "unsupported group name", original))
                    return MAELYS_GIT_ERR_IO;
                continue;
            }
            int supported = 1;
            char *save = NULL;
            for (char *member = strtok_r(members, " \t", &save);
                 member; member = strtok_r(NULL, " \t", &save)) {
                const char *name = member[0] == '@' ? member + 1u : member;
                if (!safe_atom(name)) { supported = 0; break; }
                if (member[0] == '@') {
                    if (!append_text(policy, "group_in_group(\"%s\", \"%s\").\n",
                                     name, group)) return MAELYS_GIT_ERR_IO;
                } else if (!append_text(policy, "group_member(\"%s\", \"%s\").\n",
                                        name, group)) return MAELYS_GIT_ERR_IO;
            }
            if (!supported) {
                if (!add_unsupported(migration, line_number,
                                     "unsafe group member", original))
                    return MAELYS_GIT_ERR_IO;
            } else {
                ++migration->group_count;
            }
            continue;
        }
        if (!strncmp(content, "repo", 4u) && isspace((unsigned char)content[4])) {
            repository_count = 0u;
            repository_spec_kind_t block_kind = 0;
            char *save = NULL;
            for (char *repository = strtok_r(trim(content + 4u), " \t", &save);
                 repository; repository = strtok_r(NULL, " \t", &save)) {
                if (repository_count >= MG_GITOLITE_MAX_CURRENT_REPOSITORIES ||
                    !normalize_repository(repository, &repositories[repository_count]) ||
                    (block_kind && repositories[repository_count].kind != block_kind)) {
                    repository_count = 0u;
                    if (!add_unsupported(migration, line_number,
                                         "unsupported or mixed repository pattern", original))
                        return MAELYS_GIT_ERR_IO;
                    break;
                }
                block_kind = repositories[repository_count].kind;
                ++repository_count;
                ++migration->repository_count;
            }
            continue;
        }
        char *equals = strchr(content, '=');
        if (!equals || repository_count == 0u) {
            if (!add_unsupported(migration, line_number,
                                 "rule is outside an exact repository block", original))
                return MAELYS_GIT_ERR_IO;
            continue;
        }
        *equals = '\0';
        char *right = trim(content);
        char *subjects = trim(equals + 1u);
        int supported = *subjects != '\0';
        char subjects_copy[4096];
        (void)mg_copy_string(subjects_copy, sizeof(subjects_copy), subjects);
        char *save = NULL;
        for (char *subject = strtok_r(subjects_copy, " \t,", &save);
             supported && subject; subject = strtok_r(NULL, " \t,", &save)) {
            const char *name = subject[0] == '@' ? subject + 1u : subject;
            if (!safe_atom(name)) supported = 0;
        }
        if (!supported) {
            if (!add_unsupported(migration, line_number,
                                 "empty or unsafe rule subject", original))
                return MAELYS_GIT_ERR_IO;
            continue;
        }
        int is_vref = 0, is_ref_rule = 0;
        const char *ref_permission = NULL;
        refex_kind_t ref_kind = REFEX_EXACT;
        char ref_name[MG_REF_PATTERN_MAX + 1u];
        vref_rule_t vref = {0};
        if (right[0] == '-') {
            char *descriptor = trim(right + 1u);
            if (parse_vref_rule(descriptor, &vref)) {
                is_vref = 1;
            } else if (strncmp(descriptor, "VREF/", 5u) == 0) {
                if (!add_unsupported(migration, line_number,
                                     "unsupported negative ref or VREF", original))
                    return MAELYS_GIT_ERR_IO;
                continue;
            } else {
                const char *refused = classify_refex(descriptor, 1, &ref_kind, ref_name);
                if (refused) {
                    if (!add_unsupported(migration, line_number, refused, original))
                        return MAELYS_GIT_ERR_IO;
                    continue;
                }
                is_ref_rule = 1;
                ref_permission = "-";
            }
        } else {
            char *separator = strpbrk(right, " \t");
            if (separator) {
                *separator = '\0';
                char *candidate_ref = trim(separator + 1u);
                const char *refused =
                    (strcmp(right, "RW") && strcmp(right, "RW+")) ||
                    strncmp(candidate_ref, "VREF/", 5u) == 0
                        ? "only exact full-ref RW/RW+ rules are supported"
                        : classify_refex(candidate_ref, 0, &ref_kind, ref_name);
                if (refused) {
                    if (!add_unsupported(migration, line_number, refused, original))
                        return MAELYS_GIT_ERR_IO;
                    continue;
                }
                is_ref_rule = 1;
                ref_permission = right;
            } else if (strcmp(right, "C") && strcmp(right, "R") &&
                       strcmp(right, "RW") && strcmp(right, "RW+")) {
                if (!add_unsupported(migration, line_number,
                                     "positive VREF or unknown permission", original))
                    return MAELYS_GIT_ERR_IO;
                continue;
            }
        }
        save = NULL;
        int grant_supported = 1;
        char grant_subjects[4096];
        (void)mg_copy_string(grant_subjects, sizeof(grant_subjects), subjects);
        char *grant_save = NULL;
        for (char *subject = strtok_r(grant_subjects, " \t,", &grant_save);
             grant_supported && subject; subject = strtok_r(NULL, " \t,", &grant_save)) {
            if (!is_vref && !is_ref_rule &&
                repositories[0].kind == REPOSITORY_CREATOR_NAMESPACE &&
                ((!strcmp(right, "C") && !strcmp(subject, "CREATOR")) ||
                 (strcmp(right, "C") && strcmp(subject, "CREATOR"))))
                grant_supported = 0;
        }
        if (!grant_supported) {
            if (!add_unsupported(migration, line_number,
                                 "wild repository rules support C for principals and R/RW/RW+ for CREATOR only",
                                 original))
                return MAELYS_GIT_ERR_IO;
            continue;
        }
        for (char *subject = strtok_r(subjects, " \t,", &save);
             subject; subject = strtok_r(NULL, " \t,", &save)) {
            for (size_t i = 0u; i < repository_count; ++i) {
                int appended = is_vref ?
                    (repositories[i].kind == REPOSITORY_EXACT &&
                     append_vref_fact(policy, vref.predicate, subject, repositories[i].value,
                                     vref.symbol_value,
                                     vref.uses_integer ? &vref.integer_value : NULL)) :
                    is_ref_rule ?
                    (repositories[i].kind == REPOSITORY_EXACT &&
                     append_ref_grant(policy, ref_permission, subject,
                                      repositories[i].value, ref_kind, ref_name)) :
                    repositories[i].kind == REPOSITORY_EXACT ?
                        append_direct_grant(policy, right, subject, repositories[i].value) :
                        append_creator_namespace_grant(policy, right, subject,
                                                       repositories[i].value);
                if (!appended)
                    grant_supported = 0;
            }
        }
        if (!grant_supported) {
            if (!add_unsupported(migration, line_number,
                                 "ref/VREF rules on wild repositories are not yet supported", original))
                return MAELYS_GIT_ERR_IO;
            continue;
        }
        if (is_vref) ++migration->vref_count;
        ++migration->rule_count;
    }
    if (ferror(input)) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno, "cannot read Gitolite configuration");
        return MAELYS_GIT_ERR_IO;
    }
    if (!append_authorization_rules(policy)) return MAELYS_GIT_ERR_IO;
    /* Every converted prefix is a rule, and a policy holds a bounded number of
     * them. Exceeding it is reported like any other entry that cannot be
     * migrated: the plan says so and nothing is applied. */
    size_t rules = 0u;
    for (const char *neck = policy->data; (neck = strstr(neck, " :- ")) != NULL; neck += 4)
        ++rules;
    size_t limit = 0u;
    maelys_git_result_t limited = mg_policy_rule_limit(&limit, error);
    if (limited != MAELYS_GIT_OK) return limited;
    if (rules > limit) {
        char detail[96];
        (void)snprintf(detail, sizeof(detail), "%zu rules, limit %zu", rules, limit);
        if (!add_unsupported(migration, line_number, "rule budget exceeded", detail))
            return MAELYS_GIT_ERR_IO;
    }
    return MAELYS_GIT_OK;
}

maelys_git_result_t maelys_git_migrate_gitolite(
    const char *input_path,
    const char *output_directory,
    int apply,
    maelys_git_gitolite_migration_result_t *out_result,
    maelys_git_error_t *error) {
    maelys_git_error_clear(error);
    if (!input_path || !*input_path || !output_directory || !*output_directory || !out_result)
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    memset(out_result, 0, sizeof(*out_result));
    struct stat existing;
    if (lstat(output_directory, &existing) == 0 || errno != ENOENT) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                     "migration output must not already exist: %s", output_directory);
        return MAELYS_GIT_ERR_IO;
    }
    FILE *input = fopen(input_path, "rb");
    if (!input) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                     "cannot read Gitolite configuration: %s", strerror(errno));
        return MAELYS_GIT_ERR_IO;
    }
    text_buffer_t policy = {0};
    maelys_git_result_t result = parse_gitolite(input, &policy, out_result, error);
    fclose(input);
    if (result != MAELYS_GIT_OK) {
        free(policy.data);
        maelys_git_gitolite_migration_result_clear(out_result);
        if (!error->message[0]) mg_error_set(error, result, errno, "cannot compile Gitolite policy");
        return result;
    }
    if (!apply) { free(policy.data); return MAELYS_GIT_OK; }
    if (out_result->unsupported_count) {
        free(policy.data);
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0,
                     "migration has %zu unsupported entries; apply is refused",
                     out_result->unsupported_count);
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    char policy_sha[MAELYS_CLI_SHA256_HEX_SIZE];
    maelys_cli_sha256_hex(policy.data, policy.length, policy_sha);
    text_buffer_t manifest = {0};
    if (!append_text(&manifest,
        "{\n  \"policy_set_id\": \"maelys-git.gitolite-migration\",\n"
        "  \"policy_set_version\": \"1\",\n  \"manifest_version\": \"1\",\n"
        "  \"default_profile\": \"enforce\",\n  \"created_for\": \"maelys-git-core\",\n"
        "  \"strict_loading\": true,\n  \"fail_closed\": true,\n  \"capabilities\": [],\n"
        "  \"policies\": [{\n    \"policy_id\": \"maelys-git.gitolite.authorization\",\n"
        "    \"domain\": \"maelys_git\",\n    \"file\": \"gitolite-migrated.dl\",\n"
        "    \"sha256\": \"%s\",\n    \"mode\": \"enforce\",\n"
        "    \"enabled\": true,\n    \"description\": \"Safely migrated Gitolite ACL subset\",\n"
        "    \"queries\": [{\"name\":\"allow\",\"arity\":1},{\"name\":\"deny\",\"arity\":1}]\n"
        "  }]\n}\n", policy_sha)) {
        free(policy.data);
        return MAELYS_GIT_ERR_IO;
    }
    /* The transaction directory lives beside its destination so that the
     * final rename stays on one file system. */
    char prefix[PATH_MAX], temporary[PATH_MAX];
    int length = snprintf(prefix, sizeof(prefix), "%s.tmp", output_directory);
    if (length < 0 || (size_t)length >= sizeof(prefix)) {
        free(policy.data); free(manifest.data);
        return MAELYS_GIT_ERR_LIMIT;
    }
    result = mg_make_temporary_directory(prefix, temporary, error);
    if (result != MAELYS_GIT_OK) {
        free(policy.data); free(manifest.data);
        return result;
    }
    char policy_path[PATH_MAX], manifest_path[PATH_MAX];
    int p = snprintf(policy_path, sizeof(policy_path), "%s/gitolite-migrated.dl", temporary);
    int m = snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.json", temporary);
    if (p < 0 || m < 0 || (size_t)p >= sizeof(policy_path) || (size_t)m >= sizeof(manifest_path))
        result = MAELYS_GIT_ERR_LIMIT;
    if (result == MAELYS_GIT_OK)
        result = mg_write_file_exclusive(policy_path, policy.data, policy.length, 0600, error);
    if (result == MAELYS_GIT_OK)
        result = mg_write_file_exclusive(manifest_path, manifest.data, manifest.length, 0600, error);
    if (result == MAELYS_GIT_OK) {
        /* The engine is the authority on its language: the generated policy is
         * loaded as it will be in production before it is published. */
        maelys_git_policy_t *generated = NULL;
        maelys_git_error_t refusal;
        if (maelys_git_policy_open(manifest_path, &generated, &refusal) != MAELYS_GIT_OK) {
            mg_error_set(error, MAELYS_GIT_ERR_POLICY, 0,
                         "the generated policy is refused by the engine: %.3800s", refusal.message);
            result = MAELYS_GIT_ERR_POLICY;
        }
        maelys_git_policy_close(generated);
    }
    if (result == MAELYS_GIT_OK && rename(temporary, output_directory) != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                     "cannot publish migration output: %s", strerror(errno));
        result = MAELYS_GIT_ERR_IO;
    }
    if (result != MAELYS_GIT_OK) (void)mg_remove_tree(temporary);
    free(policy.data); free(manifest.data);
    return result;
}
