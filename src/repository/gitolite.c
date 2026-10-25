#include "internal.h"
#include "policy/grants.h"
#include "policy/policy_grants.h"
#include "policy/program.h"

#include <maelys/cli/digest.h>
#include <maelys/json.h>

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

int mg_gitolite_name_is_valid(const char *name) {
    return safe_atom(name);
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

/* ---- the snapshot of grants -------------------------------------------- */

/* The sections of maelys-git-grants/1, in key order, and the arity of their
 * tuples; the last element of a VREF limit is its integer. */
enum {
    SECTION_ACCESS, SECTION_MEMBERS, SECTION_CREATORS, SECTION_NESTED, SECTION_OWNERS,
    SECTION_REFS, SECTION_VREF_LIMITS, SECTION_VREF_NAMES, SECTION_COUNT
};

static const struct {
    const char *key;
    size_t texts;
    int number;
} k_sections[SECTION_COUNT] = {
    [SECTION_ACCESS] = {"access", 4u, 0},
    [SECTION_MEMBERS] = {"members", 2u, 0},
    [SECTION_CREATORS] = {"namespace_creators", 3u, 0},
    [SECTION_NESTED] = {"nested", 2u, 0},
    [SECTION_OWNERS] = {"owner_access", 2u, 0},
    [SECTION_REFS] = {"refs", 6u, 0},
    [SECTION_VREF_LIMITS] = {"vref_limits", 4u, 1},
    [SECTION_VREF_NAMES] = {"vref_names", 4u, 0},
};

typedef struct {
    char *text[6];
    size_t texts; /* the strings of its section */
    int64_t number;
} grant_tuple_t;

typedef struct {
    grant_tuple_t *items;
    size_t count, capacity;
} grant_section_t;

/* The elementary grants of a configuration, as the generator reads them:
 * the same entries the compiled encoding writes as facts and rules. */
typedef struct {
    grant_section_t sections[SECTION_COUNT];
} grants_builder_t;

static int add_tuple(grants_builder_t *grants, int section, const char *a, const char *b, const char *c,
                     const char *d, const char *e, const char *f, int64_t number) {
    if (!grants) return 1;
    grant_section_t *items = &grants->sections[section];
    if (items->count == items->capacity) {
        size_t next = items->capacity ? items->capacity * 2u : 64u;
        grant_tuple_t *grown = realloc(items->items, next * sizeof(*grown));
        if (!grown) return 0;
        items->items = grown;
        items->capacity = next;
    }
    grant_tuple_t *tuple = &items->items[items->count];
    const char *const values[6] = {a, b, c, d, e, f};
    memset(tuple, 0, sizeof(*tuple));
    tuple->number = number;
    tuple->texts = k_sections[section].texts;
    for (size_t i = 0u; i < tuple->texts; ++i) {
        tuple->text[i] = strdup(values[i]);
        if (!tuple->text[i]) {
            for (size_t k = 0u; k < i; ++k) free(tuple->text[k]);
            return 0;
        }
    }
    ++items->count;
    return 1;
}

static void grants_builder_clear(grants_builder_t *grants) {
    for (int s = 0; s < SECTION_COUNT; ++s) {
        grant_section_t *items = &grants->sections[s];
        for (size_t i = 0u; i < items->count; ++i)
            for (size_t k = 0u; k < 6u; ++k) free(items->items[i].text[k]);
        free(items->items);
    }
    memset(grants, 0, sizeof(*grants));
}

/* The snapshot's order, within one section: element by element, strings by
 * bytes, the integer last. */
static int compare_tuples(const void *left, const void *right) {
    const grant_tuple_t *a = left, *b = right;
    for (size_t i = 0u; i < a->texts; ++i) {
        int order = strcmp(a->text[i], b->text[i]);
        if (order) return order;
    }
    return a->number == b->number ? 0 : (a->number < b->number ? -1 : 1);
}

/* The snapshot of GRANTS in its one byte form: each section sorted, without
 * duplicates, serialized by maelys-json without a flag (Canonical JSON v1)
 * within the bounds its reader applies: three containers deep (the root, a
 * section, a tuple), nine members and at most seven values per tuple.
 * MAELYS_JSON_ERR_LIMIT when it does not fit them. */
static maelys_json_result_t serialize_grants(grants_builder_t *grants, char **out_bytes, size_t *out_size) {
    const maelys_json_limits_t limits = {.maximum_bytes = MG_GRANTS_MAX_BYTES, .maximum_depth = 3u,
                                         .maximum_tokens = 19u + 7u * MG_GRANTS_MAX_TUPLES};
    maelys_json_writer_t *writer = NULL;
    maelys_json_result_t status = maelys_json_writer_create(MAELYS_JSON_PROFILE_RFC8259, &limits, 0u, &writer);
    *out_bytes = NULL;
    *out_size = 0u;
    if (status != MAELYS_JSON_OK) return status;
#define WRITE(call) do { if (status == MAELYS_JSON_OK) status = (call); } while (0)
    WRITE(maelys_json_writer_object_begin(writer));
    WRITE(maelys_json_writer_key_cstr(writer, "format"));
    WRITE(maelys_json_writer_string_cstr(writer, MG_GRANTS_FORMAT));
    for (int s = 0; s < SECTION_COUNT; ++s) {
        grant_section_t *items = &grants->sections[s];
        if (items->count) qsort(items->items, items->count, sizeof(*items->items), compare_tuples);
        WRITE(maelys_json_writer_key_cstr(writer, k_sections[s].key));
        WRITE(maelys_json_writer_array_begin(writer));
        for (size_t i = 0u; i < items->count; ++i) {
            if (i && compare_tuples(&items->items[i - 1u], &items->items[i]) == 0) continue;
            WRITE(maelys_json_writer_array_begin(writer));
            for (size_t k = 0u; k < k_sections[s].texts; ++k)
                WRITE(maelys_json_writer_string_cstr(writer, items->items[i].text[k]));
            if (k_sections[s].number) WRITE(maelys_json_writer_i64(writer, items->items[i].number));
            WRITE(maelys_json_writer_array_end(writer));
        }
        WRITE(maelys_json_writer_array_end(writer));
    }
    WRITE(maelys_json_writer_object_end(writer));
    WRITE(maelys_json_writer_finish(writer, out_bytes, out_size));
#undef WRITE
    maelys_json_writer_release(writer);
    return status;
}

/* The tuple of one grant of a rule, for one subject and one repository of
 * its block, in the snapshot's form. */
typedef struct {
    int is_vref, is_ref_rule;
    const char *right;          /* the permission of a plain rule */
    const char *ref_permission; /* RW, RW+ or - */
    int ref_prefix;
    const char *ref_name;
    const char *vref_predicate, *vref_path;
    unsigned long long vref_limit;
} grant_rule_t;

static int record_grant(grants_builder_t *grants, const grant_rule_t *rule, const char *subject,
                        const repository_spec_t *repository) {
    const char *kind = subject[0] == '@' ? "group" : "user";
    const char *name = subject[0] == '@' ? subject + 1u : subject;
    if (rule->is_vref) {
        if (!strcmp(rule->vref_predicate, "vref_deny_name"))
            return add_tuple(grants, SECTION_VREF_NAMES, kind, name, repository->value, rule->vref_path, NULL, NULL, 0);
        const char *limit = !strcmp(rule->vref_predicate, "vref_deny_count") ? "count" :
                            !strcmp(rule->vref_predicate, "vref_deny_new_count") ? "new_count" : "max_new_binary";
        return add_tuple(grants, SECTION_VREF_LIMITS, kind, name, repository->value, limit, NULL, NULL,
                         (int64_t)rule->vref_limit);
    }
    if (rule->is_ref_rule)
        return add_tuple(grants, SECTION_REFS, kind, name, repository->value, rule->ref_prefix ? "prefix" : "exact",
                         rule->ref_name, rule->ref_permission, 0);
    if (repository->kind == REPOSITORY_EXACT)
        return add_tuple(grants, SECTION_ACCESS, kind, name, repository->value, rule->right, NULL, NULL, 0);
    if (!strcmp(rule->right, "C"))
        return add_tuple(grants, SECTION_CREATORS, kind, name, repository->value, NULL, NULL, NULL, 0);
    return add_tuple(grants, SECTION_OWNERS, repository->value, rule->right, NULL, NULL, NULL, NULL, 0);
}

/* One elementary grant on an exact repository is one fact: the subject, the
 * repository and the Gitolite level, which the fixed rules read. */
static int append_direct_grant(text_buffer_t *policy,
                               const char *right,
                               const char *subject,
                               const char *repository) {
    const char *prefix = subject[0] == '@' ? "group_" : "";
    const char *name = subject[0] == '@' ? subject + 1u : subject;
    if (!safe_atom(name)) return 0;
    if (strcmp(right, "C") && strcmp(right, "R") && strcmp(right, "RW") && strcmp(right, "RW+"))
        return 0;
    return append_text(policy, "%sgitolite_access(\"%s\", \"%s\", \"%s\").\n",
                       prefix, name, repository, right);
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
    if (strcmp(right, "R") && strcmp(right, "RW") && strcmp(right, "RW+")) return 0;
    return append_text(policy, "owner_namespace_access(\"%s\", \"%s\").\n",
                       namespace_name, right);
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

/* An exact ref, or a prefix ending in '/', granted or denied at one level.
 * Both are policy atoms: at most 63 bytes. */
static int append_ref_access(text_buffer_t *policy,
                             const char *subject,
                             const char *repository,
                             const char *ref_name,
                             const char *level) {
    const char *prefix = subject[0] == '@' ? "group_" : "";
    const char *name = subject[0] == '@' ? subject + 1u : subject;
    return safe_atom(name) && strlen(ref_name) < 64u &&
           append_text(policy, "%sgitolite_ref_access(\"%s\", \"%s\", \"%s\", \"%s\").\n",
                       prefix, name, repository, ref_name, level);
}


typedef enum {
    REFEX_EXACT = 1,
    REFEX_PREFIX = 2
} refex_kind_t;

/* The longest filter pattern the policy language accepts. */
#define MG_REF_PATTERN_MAX 256u

int mg_gitolite_pattern_is_valid(const char *pattern, int prefix, int deny) {
    size_t length = pattern ? strlen(pattern) : 0u;
    if (length < 5u || length > MG_REF_PATTERN_MAX || strncmp(pattern, "refs/", 5u) ||
        strstr(pattern, "..") || strstr(pattern, "//"))
        return 0;
    for (size_t i = 0u; i < length; ++i) {
        unsigned char ch = (unsigned char)pattern[i];
        if (!(isalnum(ch) || ch == '.' || ch == '_' || ch == '/' || ch == '-')) return 0;
    }
    if (prefix) return deny || pattern[length - 1u] == '/';
    return pattern[length - 1u] != '/' && maelys_git_ref_name_is_valid(pattern);
}

/* Reads one Gitolite refex and returns NULL, or the stable reason it is
 * refused. Gitolite anchors a refex at its start only, completes a name that
 * does not begin with refs/ by refs/heads/, and takes a final $ as equality.
 * Only literal names are converted, into a form whose equivalence holds:
 *   - a literal ending in '/' is a prefix;
 *   - a literal ending in '$' is the exact ref without the '$';
 *   - a bare literal denies as a prefix, which is what Gitolite does, and
 *     grants the exact ref only, which is stricter than Gitolite.
 * A '.' is any character in Gitolite: a literal dot is written '\.', and a
 * bare '.' is refused, since no literal covers what Gitolite reads, for a
 * deny as for a grant. Alternation, classes, repetition and any other
 * regular-expression syntax have no bounded equivalent and are refused. */
static const char *classify_refex(const char *text, int deny, refex_kind_t *out_kind,
                                  char out_value[MG_REF_PATTERN_MAX + 1u]) {
    size_t length = strlen(text);
    int anchored = length > 0u && text[length - 1u] == '$';
    size_t body = anchored ? length - 1u : length;
    if (body == 0u) return "unsupported refex syntax";
    /* Other syntax first: a '.' is named only in an otherwise literal refex. */
    int any_character = 0;
    for (size_t i = 0u; i < body; ++i) {
        unsigned char ch = (unsigned char)text[i];
        if (ch == '\\' && i + 1u < body && text[i + 1u] == '.')
            ++i;
        else if (ch == '.')
            any_character = 1;
        else if (!(isalnum(ch) || ch == '_' || ch == '/' || ch == '-'))
            return "unsupported refex syntax";
    }
    if (any_character) return "'.' is any character in Gitolite; write '\\.' for a literal dot";
    char literal[MG_REF_PATTERN_MAX + 1u];
    size_t used = 0u;
    for (size_t i = 0u; i < body; ++i) {
        if (text[i] == '\\') ++i;
        if (used == MG_REF_PATTERN_MAX) return "ref pattern exceeds 256 bytes";
        literal[used++] = text[i];
    }
    literal[used] = '\0';
    const char *implied = strncmp(literal, "refs/", 5u) == 0 ? "" : "refs/heads/";
    if (strlen(implied) + used > MG_REF_PATTERN_MAX) return "ref pattern exceeds 256 bytes";
    (void)snprintf(out_value, MG_REF_PATTERN_MAX + 1u, "%s%s", implied, literal);
    int open_namespace = out_value[strlen(out_value) - 1u] == '/';
    if (anchored && open_namespace) return "unsupported refex syntax";
    int prefix = !anchored && (open_namespace || deny);
    /* The normalized form, by the rule a snapshot of grants is read with. */
    if (!mg_gitolite_pattern_is_valid(out_value, prefix, deny)) return "unsupported refex syntax";
    if (prefix) {
        *out_kind = REFEX_PREFIX;
        return NULL;
    }
    /* An exact ref is a policy atom: the atom length applies. */
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

/* A prefix the request's ref_prefix facts can match: it ends with '/', it is
 * an atom, and it is among the first MG_REF_PREFIX_FACTS prefixes of any ref
 * it starts, because each of its '/' ends one of them. */
static int prefix_is_fact(const char *pattern) {
    size_t length = strlen(pattern), slashes = 0u;
    if (length == 0u || length >= 64u || pattern[length - 1u] != '/') return 0;
    for (size_t i = 0u; i < length; ++i) slashes += pattern[i] == '/';
    return slashes <= MG_REF_PREFIX_FACTS;
}

/* Any other prefix is policy code: a rule with a constant filter pattern,
 * never an atom, restricted to the request's subject and repository. The
 * pattern holds only [A-Za-z0-9._/-], so it needs no escaping. A grant also
 * gives what a ref grant gives to requests that carry no ref: has_ref_write,
 * from which the write operation and the summary of a push follow. */
static int append_ref_prefix_rules(text_buffer_t *policy, const char *right,
                                   const char *subject, const char *repository,
                                   const char *pattern) {
    int group = subject[0] == '@';
    const char *name = group ? subject + 1u : subject;
    if (!safe_atom(name) || strlen(pattern) > MG_REF_PATTERN_MAX) return 0;
    char who[160], guard[256], line[1024];
    if (group) {
        (void)snprintf(who, sizeof(who), "U");
        (void)snprintf(guard, sizeof(guard), "user(U), effective_group_member(U, \"%s\"), ", name);
    } else {
        (void)snprintf(who, sizeof(who), "\"%s\"", name);
        (void)snprintf(guard, sizeof(guard), "user(\"%s\"), ", name);
    }
    static const char *const grant_heads[] = {"effective_ref_grant_push", "effective_ref_grant_force"};
    const char *const deny_head[] = {"effective_ref_deny"};
    const char *const *heads = grant_heads;
    size_t head_count;
    if (!strcmp(right, "-")) { heads = deny_head; head_count = 1u; }
    else if (!strcmp(right, "RW")) head_count = 1u;
    else if (!strcmp(right, "RW+")) head_count = 2u;
    else return 0;
    for (size_t i = 0u; i < head_count; ++i) {
        (void)snprintf(line, sizeof(line),
                       "%s(%s, \"%s\", F) :- %srepository(\"%s\"), ref(F), starts_with(F, \"%s\").\n",
                       heads[i], who, repository, guard, repository, pattern);
        if (!append_once(policy, line)) return 0;
    }
    if (heads == deny_head) return 1;
    (void)snprintf(line, sizeof(line), "has_ref_write(%s, \"%s\") :- %srepository(\"%s\").\n",
                   who, repository, guard, repository);
    return append_once(policy, line);
}

/* With prefix_facts, a prefix the request's facts can match is a fact and
 * *facts counts it; without, every prefix is a rule. */
static int append_ref_grant(text_buffer_t *policy,
                            const char *right,
                            const char *subject,
                            const char *repository,
                            refex_kind_t kind,
                            const char *ref_name,
                            int prefix_facts,
                            size_t *facts) {
    if (strcmp(right, "-") && strcmp(right, "RW") && strcmp(right, "RW+")) return 0;
    if (kind == REFEX_EXACT)
        return append_ref_access(policy, subject, repository, ref_name, right);
    if (prefix_facts && prefix_is_fact(ref_name)) {
        ++*facts;
        return append_ref_access(policy, subject, repository, ref_name, right);
    }
    return append_ref_prefix_rules(policy, right, subject, repository, ref_name);
}

/* The fixed rules. Each one that reads a policy fact indexed by a subject or
 * a repository first binds them, and the ref or the path, from the request:
 * what a derived predicate holds then depends on the request, never on the
 * size of the configuration (see judge_budget). The level of the owner of a
 * CREATOR namespace is an access level like any grant's, read by the same
 * allow rules. */
static int append_authorization_rules(text_buffer_t *policy) {
    if (!append_text(policy,
        "\neffective_group_member(U, G) :- user(U), group_member(U, G).\n"
        "effective_group_member(U, G) :- user(U), effective_group_member(U, C), group_in_group(C, G).\n"
        "can_create_namespace(U, N) :- user(U), repository_owner_namespace(N, U), namespace_creator(U, N).\n"
        "can_create_namespace(U, N) :- user(U), repository_owner_namespace(N, U), effective_group_member(U, G), group_namespace_creator(G, N).\n"
        "effective_access(U, P, L) :- user(U), repository(P), gitolite_access(U, P, L).\n"
        "effective_access(U, P, L) :- user(U), repository(P), effective_group_member(U, G), group_gitolite_access(G, P, L).\n"
        "effective_access(U, P, L) :- user(U), repository(P), repository_owner_namespace(N, U), owner_namespace_access(N, L).\n"
        "push_request(R, U, P, F) :- request(R), user(U), repository(P), operation(\"push\"), ref(F).\n"
        "effective_ref_grant_push(U, P, F) :- user(U), repository(P), ref(F), gitolite_ref_access(U, P, F, \"RW\").\n"
        "effective_ref_grant_push(U, P, F) :- user(U), repository(P), ref(F), gitolite_ref_access(U, P, F, \"RW+\").\n"
        "effective_ref_grant_push(U, P, F) :- user(U), repository(P), ref(F), ref_prefix(X), gitolite_ref_access(U, P, X, \"RW\").\n"
        "effective_ref_grant_push(U, P, F) :- user(U), repository(P), ref(F), ref_prefix(X), gitolite_ref_access(U, P, X, \"RW+\").\n"
        "effective_ref_grant_push(U, P, F) :- user(U), repository(P), ref(F), effective_group_member(U, G), group_gitolite_ref_access(G, P, F, \"RW\").\n"
        "effective_ref_grant_push(U, P, F) :- user(U), repository(P), ref(F), effective_group_member(U, G), group_gitolite_ref_access(G, P, F, \"RW+\").\n"
        "effective_ref_grant_push(U, P, F) :- user(U), repository(P), ref(F), ref_prefix(X), effective_group_member(U, G), group_gitolite_ref_access(G, P, X, \"RW\").\n"
        "effective_ref_grant_push(U, P, F) :- user(U), repository(P), ref(F), ref_prefix(X), effective_group_member(U, G), group_gitolite_ref_access(G, P, X, \"RW+\").\n"
        "effective_ref_grant_force(U, P, F) :- user(U), repository(P), ref(F), gitolite_ref_access(U, P, F, \"RW+\").\n"
        "effective_ref_grant_force(U, P, F) :- user(U), repository(P), ref(F), ref_prefix(X), gitolite_ref_access(U, P, X, \"RW+\").\n"
        "effective_ref_grant_force(U, P, F) :- user(U), repository(P), ref(F), effective_group_member(U, G), group_gitolite_ref_access(G, P, F, \"RW+\").\n"
        "effective_ref_grant_force(U, P, F) :- user(U), repository(P), ref(F), ref_prefix(X), effective_group_member(U, G), group_gitolite_ref_access(G, P, X, \"RW+\").\n"
        "effective_ref_deny(U, P, F) :- user(U), repository(P), ref(F), gitolite_ref_access(U, P, F, \"-\").\n"
        "effective_ref_deny(U, P, F) :- user(U), repository(P), ref(F), ref_prefix(X), gitolite_ref_access(U, P, X, \"-\").\n"
        "effective_ref_deny(U, P, F) :- user(U), repository(P), ref(F), effective_group_member(U, G), group_gitolite_ref_access(G, P, F, \"-\").\n"
        "effective_ref_deny(U, P, F) :- user(U), repository(P), ref(F), ref_prefix(X), effective_group_member(U, G), group_gitolite_ref_access(G, P, X, \"-\").\n"
        "has_ref_write(U, P) :- user(U), repository(P), gitolite_ref_access(U, P, _, \"RW\").\n"
        "has_ref_write(U, P) :- user(U), repository(P), gitolite_ref_access(U, P, _, \"RW+\").\n"
        "has_ref_write(U, P) :- user(U), repository(P), effective_group_member(U, G), group_gitolite_ref_access(G, P, _, \"RW\").\n"
        "has_ref_write(U, P) :- user(U), repository(P), effective_group_member(U, G), group_gitolite_ref_access(G, P, _, \"RW+\").\n"
        "has_push_access(U, P) :- effective_access(U, P, \"RW\").\n"
        "has_push_access(U, P) :- effective_access(U, P, \"RW+\").\n"
        "has_push_access(U, P) :- has_ref_write(U, P).\n"))
        return 0;
    if (!append_text(policy,
        "\nallow(R) :- request(R), user(U), repository(P), operation(\"read\"), effective_access(U, P, \"R\").\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"read\"), effective_access(U, P, \"RW\").\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"read\"), effective_access(U, P, \"RW+\").\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"write\"), effective_access(U, P, \"RW\").\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"write\"), effective_access(U, P, \"RW+\").\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"write\"), has_ref_write(U, P).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), update_kind(\"create\"), effective_access(U, P, \"RW\").\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), update_kind(\"create\"), effective_access(U, P, \"RW+\").\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), update_kind(\"fast_forward\"), effective_access(U, P, \"RW\").\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), update_kind(\"fast_forward\"), effective_access(U, P, \"RW+\").\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), update_kind(\"force\"), effective_access(U, P, \"RW+\").\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), update_kind(\"delete\"), effective_access(U, P, \"RW+\").\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"merge\"), effective_access(U, P, \"RW\").\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"merge\"), effective_access(U, P, \"RW+\").\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"update-ref\"), effective_access(U, P, \"RW+\").\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"create\"), effective_access(U, P, \"C\").\n"
        "allow(R) :- push_request(R, U, P, F), update_kind(\"create\"), effective_ref_grant_push(U, P, F).\n"
        "allow(R) :- push_request(R, U, P, F), update_kind(\"fast_forward\"), effective_ref_grant_push(U, P, F).\n"
        "allow(R) :- push_request(R, U, P, F), update_kind(\"force\"), effective_ref_grant_force(U, P, F).\n"
        "allow(R) :- push_request(R, U, P, F), update_kind(\"delete\"), effective_ref_grant_force(U, P, F).\n"
        "deny(R) :- push_request(R, U, P, F), effective_ref_deny(U, P, F).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), changed_count(_), has_push_access(U, P).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"merge\"), ref(F), effective_ref_grant_push(U, P, F).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"update-ref\"), ref(F), effective_ref_grant_force(U, P, F).\n"))
        return 0;
    if (!append_text(policy,
        "allow(R) :- request(R), user(U), operation(\"create\"), repository_owner_namespace(N, U), can_create_namespace(U, N).\n"
))
        return 0;
    return append_text(policy,
        "vref_count_exceeded(U, P) :- user(U), repository(P), changed_count(C), vref_deny_count(U, P, N), C > N.\n"
        "vref_count_exceeded(U, P) :- user(U), repository(P), changed_count(C), effective_group_member(U, G), group_vref_deny_count(G, P, N), C > N.\n"
        "vref_new_count_exceeded(U, P) :- user(U), repository(P), added_count(C), vref_deny_new_count(U, P, N), C > N.\n"
        "vref_new_count_exceeded(U, P) :- user(U), repository(P), added_count(C), effective_group_member(U, G), group_vref_deny_new_count(G, P, N), C > N.\n"
        "vref_new_binary_exceeded(U, P) :- user(U), repository(P), change_binary(true), change_blob_size(S), vref_deny_max_new_binary(U, P, N), S > N.\n"
        "vref_new_binary_exceeded(U, P) :- user(U), repository(P), change_binary(true), change_blob_size(S), effective_group_member(U, G), group_vref_deny_max_new_binary(G, P, N), S > N.\n"
        "deny(R) :- request(R), user(U), repository(P), operation(\"push\"), path(F), vref_deny_name(U, P, F).\n"
        "deny(R) :- request(R), user(U), repository(P), operation(\"push\"), path(F), effective_group_member(U, G), group_vref_deny_name(G, P, F).\n"
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

/* The group graph of the configuration: who is a direct member of what, a
 * user or, when nested, a group. */
typedef struct {
    char *member;
    char *group;
    int nested;
} membership_t;

typedef struct {
    membership_t *items;
    size_t count;
    size_t capacity;
} memberships_t;

static int add_membership(memberships_t *graph, const char *member, const char *group, int nested) {
    if (graph->count == graph->capacity) {
        size_t next = graph->capacity ? graph->capacity * 2u : 64u;
        membership_t *grown = realloc(graph->items, next * sizeof(*grown));
        if (!grown) return 0;
        graph->items = grown;
        graph->capacity = next;
    }
    membership_t *item = &graph->items[graph->count];
    item->member = strdup(member);
    item->group = strdup(group);
    item->nested = nested;
    if (!item->member || !item->group) {
        free(item->member);
        free(item->group);
        return 0;
    }
    ++graph->count;
    return 1;
}

static void memberships_clear(memberships_t *graph) {
    for (size_t i = 0u; i < graph->count; ++i) {
        free(graph->items[i].member);
        free(graph->items[i].group);
    }
    free(graph->items);
    memset(graph, 0, sizeof(*graph));
}

static int group_seen(const char *const *groups, size_t count, const char *group) {
    for (size_t i = 0u; i < count; ++i)
        if (!strcmp(groups[i], group)) return 1;
    return 0;
}

/* The most groups any user belongs to, directly or through nesting: what
 * effective_group_member holds for one request. Returns 0 on allocation
 * failure with *out untouched. */
static int most_groups_of_a_user(const memberships_t *graph, size_t *out) {
    size_t most = 0u;
    const char **reached = graph->count ? malloc(graph->count * sizeof(*reached)) : NULL;
    if (graph->count && !reached) return 0;
    for (size_t u = 0u; u < graph->count; ++u) {
        if (graph->items[u].nested) continue;
        const char *user = graph->items[u].member;
        size_t count = 0u;
        for (size_t i = 0u; i < graph->count; ++i)
            if (!graph->items[i].nested && !strcmp(graph->items[i].member, user) &&
                !group_seen(reached, count, graph->items[i].group))
                reached[count++] = graph->items[i].group;
        /* Breadth first over nesting; each group is reached once. */
        for (size_t next = 0u; next < count; ++next)
            for (size_t i = 0u; i < graph->count; ++i)
                if (graph->items[i].nested && !strcmp(graph->items[i].member, reached[next]) &&
                    !group_seen(reached, count, graph->items[i].group))
                    reached[count++] = graph->items[i].group;
        if (count > most) most = count;
    }
    free(reached);
    *out = most;
    return 1;
}

static maelys_git_result_t parse_gitolite(FILE *input,
                                          int prefix_facts,
                                          text_buffer_t *policy,
                                          grants_builder_t *grants,
                                          memberships_t *graph,
                                          size_t *out_lines,
                                          size_t *out_prefix_facts,
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
                if (!add_membership(graph, name, group, member[0] == '@') ||
                    !add_tuple(grants, member[0] == '@' ? SECTION_NESTED : SECTION_MEMBERS, name, group, NULL,
                               NULL, NULL, NULL, 0))
                    return MAELYS_GIT_ERR_IO;
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
        const grant_rule_t rule = {
            .is_vref = is_vref, .is_ref_rule = is_ref_rule, .right = right,
            .ref_permission = ref_permission, .ref_prefix = ref_kind == REFEX_PREFIX, .ref_name = ref_name,
            .vref_predicate = vref.predicate, .vref_path = vref.symbol_value, .vref_limit = vref.integer_value};
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
                                      repositories[i].value, ref_kind, ref_name,
                                      prefix_facts, out_prefix_facts)) :
                    repositories[i].kind == REPOSITORY_EXACT ?
                        append_direct_grant(policy, right, subject, repositories[i].value) :
                        append_creator_namespace_grant(policy, right, subject,
                                                       repositories[i].value);
                if (!appended)
                    grant_supported = 0;
                else if (!record_grant(grants, &rule, subject, &repositories[i]))
                    return MAELYS_GIT_ERR_IO;
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
    *out_lines = line_number;
    return MAELYS_GIT_OK;
}

#define MG_GITOLITE_POLICY_ID "maelys-git.gitolite.authorization"

static int build_manifest(const char *source, size_t length, const char *description, text_buffer_t *manifest) {
    char policy_sha[MAELYS_CLI_SHA256_HEX_SIZE];
    maelys_cli_sha256_hex(source, length, policy_sha);
    return append_text(manifest,
        "{\n  \"policy_set_id\": \"maelys-git.gitolite-migration\",\n"
        "  \"policy_set_version\": \"1\",\n  \"manifest_version\": \"1\",\n"
        "  \"default_profile\": \"enforce\",\n  \"created_for\": \"maelys-git-core\",\n"
        "  \"strict_loading\": true,\n  \"fail_closed\": true,\n  \"capabilities\": [],\n"
        "  \"policies\": [{\n    \"policy_id\": \"" MG_GITOLITE_POLICY_ID "\",\n"
        "    \"domain\": \"maelys_git\",\n    \"file\": \"gitolite-migrated.dl\",\n"
        "    \"sha256\": \"%s\",\n    \"mode\": \"enforce\",\n"
        "    \"enabled\": true,\n    \"description\": \"%s\",\n"
        "    \"queries\": [{\"name\":\"allow\",\"arity\":1},{\"name\":\"deny\",\"arity\":1}]\n"
        "  }]\n}\n", policy_sha, description);
}

/* What one derived predicate holds for one request, beside the groups of its
 * user, under the fixed rules: effective_access holds at most the four
 * levels, whether they come from a grant or from the owner's namespace;
 * every other derived predicate one fact, for the request's subject,
 * repository and ref. Together, beside the groups: effective_access 4,
 * can_create_namespace, push_request, the three ref grants, has_ref_write,
 * has_push_access, the three VREF excesses, allow and deny, one each. */
#define MG_GITOLITE_DERIVED_PER_PREDICATE 4u
#define MG_GITOLITE_DERIVED_BESIDE_GROUPS 16u

static int add_budget_refusal(maelys_git_gitolite_migration_result_t *migration, size_t line_number,
                              const maelys_git_failure_detail_t *detail, const char *subject) {
    char text[192];
    if (detail->kind == MAELYS_GIT_FAILURE_CAPACITY)
        (void)snprintf(text, sizeof(text), "%s %llu requested, limit %llu%s%s", detail->budget,
                       (unsigned long long)detail->requested, (unsigned long long)detail->limit,
                       subject ? " for " : "", subject ? subject : "");
    else
        (void)snprintf(text, sizeof(text), "%s", detail->diagnostic[0] ? detail->diagnostic : "refused");
    return add_unsupported(migration, line_number,
                           detail->kind == MAELYS_GIT_FAILURE_CAPACITY ? "policy budget exceeded" :
                           "policy refused by the engine", text);
}

/* The plan's verdict on the generated policy. The engine compiles it as it
 * will load it, which judges every budget of compilation. Execution depends
 * on the request, which the engine cannot see at load time: its worst case
 * is the generator's to compute, from the fixed rules and the group graph.
 * A budget that does not hold is an entry that cannot be migrated, and
 * budget.failure says which, for a machine. */
static maelys_git_result_t judge_budget(const char *source, size_t source_length, const text_buffer_t *manifest,
                                        mg_grants_t *grants, const memberships_t *graph, size_t line_number,
                                        maelys_git_gitolite_migration_result_t *migration,
                                        maelys_git_error_t *error) {
    maelys_git_policy_budget_t *budget = &migration->budget;
    maelys_git_policy_t *compiled = NULL;
    maelys_git_error_t refusal = {0};
    maelys_git_result_t opened = mg_policy_open_buffer(manifest->data, manifest->length,
        MG_GITOLITE_POLICY_ID, source, source_length, grants, &compiled, &refusal);
    if (opened != MAELYS_GIT_OK && opened != MAELYS_GIT_ERR_POLICY) {
        mg_error_set(error, opened, 0, "%s", refusal.message);
        return opened;
    }
    maelys_git_result_t result = mg_policy_budget(compiled, budget, error);
    maelys_git_policy_close(compiled);
    if (result != MAELYS_GIT_OK) return result;
    if (opened != MAELYS_GIT_OK) {
        budget->failure = refusal.detail;
        if (budget->failure.kind == MAELYS_GIT_FAILURE_NONE)
            budget->failure.kind = MAELYS_GIT_FAILURE_ENGINE;
        if (!add_budget_refusal(migration, line_number, &budget->failure, NULL))
            return MAELYS_GIT_ERR_IO;
    }
    size_t groups = 0u;
    if (!most_groups_of_a_user(graph, &groups)) return MAELYS_GIT_ERR_IO;
    budget->derived_per_predicate =
        groups > MG_GITOLITE_DERIVED_PER_PREDICATE ? groups : MG_GITOLITE_DERIVED_PER_PREDICATE;
    budget->derived = groups + MG_GITOLITE_DERIVED_BESIDE_GROUPS;
    maelys_git_failure_detail_t excess = {.kind = MAELYS_GIT_FAILURE_CAPACITY};
    if (budget->derived_per_predicate > budget->derived_per_predicate_limit) {
        (void)mg_copy_string(excess.budget, sizeof(excess.budget), "MAX_FACTS_PER_PRED");
        excess.requested = budget->derived_per_predicate;
        excess.limit = budget->derived_per_predicate_limit;
    } else if (budget->derived > budget->derived_limit) {
        (void)mg_copy_string(excess.budget, sizeof(excess.budget), "MAX_IDB_FACTS");
        excess.requested = budget->derived;
        excess.limit = budget->derived_limit;
    } else {
        return MAELYS_GIT_OK;
    }
    (void)mg_copy_string(excess.diagnostic, sizeof(excess.diagnostic),
                         "derived:effective_group_member");
    if (budget->failure.kind == MAELYS_GIT_FAILURE_NONE) budget->failure = excess;
    return add_budget_refusal(migration, line_number, &excess, "effective_group_member")
        ? MAELYS_GIT_OK : MAELYS_GIT_ERR_IO;
}

/* One encoding of the configuration, its manifest and the plan's verdict. */
static maelys_git_result_t generate(FILE *input, int prefix_facts, text_buffer_t *policy,
                                    text_buffer_t *manifest, size_t *out_prefix_facts,
                                    maelys_git_gitolite_migration_result_t *migration,
                                    maelys_git_error_t *error) {
    memberships_t graph = {0};
    size_t lines = 0u;
    *out_prefix_facts = 0u;
    maelys_git_result_t result = parse_gitolite(input, prefix_facts, policy, NULL, &graph, &lines,
                                                out_prefix_facts, migration, error);
    if (result == MAELYS_GIT_OK &&
        !build_manifest(policy->data, policy->length, "Safely migrated Gitolite ACL subset", manifest))
        result = MAELYS_GIT_ERR_IO;
    if (result == MAELYS_GIT_OK)
        result = judge_budget(policy->data, policy->length, manifest, NULL, &graph, lines, migration, error);
    memberships_clear(&graph);
    return result;
}

typedef struct {
    const char *name;
    const char *data;
    size_t length;
} output_file_t;

/* The directory that holds PATH, in OUT: "." for a bare name, "/" at the
 * root. */
static const char *parent_of(const char *path, char *out, size_t size) {
    const char *slash = strrchr(path, '/');
    if (!slash) return ".";
    if (slash == path) return "/";
    (void)snprintf(out, size, "%.*s", (int)(slash - path), path);
    return out;
}

/* Writes FILES into a transaction directory beside OUTPUT_DIRECTORY, loads
 * the manifest as production will (with the snapshot of grants.json when
 * WITH_GRANTS), then publishes the directory by one rename: no file of a
 * published output is ever written in place. The engine is the authority on
 * its language: the generated policy is loaded before it is published. */
static maelys_git_result_t publish(const char *output_directory, const output_file_t *files, size_t count,
                                   int with_grants, maelys_git_error_t *error) {
    /* The transaction directory lives beside its destination so that the
     * final rename stays on one file system. */
    char prefix[PATH_MAX], temporary[PATH_MAX];
    int length = snprintf(prefix, sizeof(prefix), "%s.tmp", output_directory);
    if (length < 0 || (size_t)length >= sizeof(prefix)) return MAELYS_GIT_ERR_LIMIT;
    maelys_git_result_t result = mg_make_temporary_directory(prefix, temporary, error);
    if (result != MAELYS_GIT_OK) return result;
    char path[PATH_MAX], manifest_path[PATH_MAX], grants_path[PATH_MAX];
    int m = snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.json", temporary);
    int g = snprintf(grants_path, sizeof(grants_path), "%s/grants.json", temporary);
    if (m < 0 || g < 0 || (size_t)m >= sizeof(manifest_path) || (size_t)g >= sizeof(grants_path))
        result = MAELYS_GIT_ERR_LIMIT;
    for (size_t i = 0u; result == MAELYS_GIT_OK && i < count; ++i) {
        int p = snprintf(path, sizeof(path), "%s/%s", temporary, files[i].name);
        result = p < 0 || (size_t)p >= sizeof(path) ? MAELYS_GIT_ERR_LIMIT :
                 mg_write_file_exclusive(path, files[i].data, files[i].length, 0600, error);
    }
    if (result == MAELYS_GIT_OK) {
        maelys_git_policy_t *generated = NULL;
        maelys_git_error_t refusal;
        maelys_git_result_t opened = with_grants
            ? mg_policy_open_grants(manifest_path, grants_path, &generated, &refusal)
            : maelys_git_policy_open(manifest_path, &generated, &refusal);
        if (opened != MAELYS_GIT_OK) {
            mg_error_set(error, MAELYS_GIT_ERR_POLICY, 0,
                         "the generated policy is refused by the engine: %.3800s", refusal.message);
            mg_error_set_detail(error, &refusal.detail);
            result = MAELYS_GIT_ERR_POLICY;
        }
        maelys_git_policy_close(generated);
    }
    /* Each file was synced as it was written; the directory that names them
     * is synced before its rename, and its parent after it. */
    if (result == MAELYS_GIT_OK && !mg_sync_directory(temporary)) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                     "cannot make migration output durable: %s", strerror(errno));
        result = MAELYS_GIT_ERR_IO;
    }
    if (result == MAELYS_GIT_OK && rename(temporary, output_directory) != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                     "cannot publish migration output: %s", strerror(errno));
        result = MAELYS_GIT_ERR_IO;
    }
    if (result != MAELYS_GIT_OK) (void)mg_remove_tree(temporary);
    if (result == MAELYS_GIT_OK && !mg_sync_directory(parent_of(output_directory, path, sizeof(path)))) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                     "migration output published, but its directory could not be synced: %s", strerror(errno));
        result = MAELYS_GIT_ERR_IO;
    }
    return result;
}

/* The refusals of apply, before anything is written: a budget that does not
 * hold refuses as the engine would at load time, with the same detail; an
 * unsupported entry refuses the whole migration. */
static maelys_git_result_t refuse_apply(const maelys_git_gitolite_migration_result_t *migration,
                                        maelys_git_error_t *error) {
    const maelys_git_failure_detail_t *failure = &migration->budget.failure;
    if (failure->kind != MAELYS_GIT_FAILURE_NONE) {
        mg_error_set(error, MAELYS_GIT_ERR_POLICY, 0,
                     "the generated policy is refused by its budget: %s %llu requested, limit %llu%s%s",
                     failure->budget[0] ? failure->budget : failure->diagnostic,
                     (unsigned long long)failure->requested, (unsigned long long)failure->limit,
                     failure->kind == MAELYS_GIT_FAILURE_CAPACITY ? "" : " ",
                     failure->kind == MAELYS_GIT_FAILURE_CAPACITY ? "" :
                         maelys_git_failure_kind_name(failure->kind));
        mg_error_set_detail(error, failure);
        return MAELYS_GIT_ERR_POLICY;
    }
    if (migration->unsupported_count) {
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0,
                     "migration has %zu unsupported entries; apply is refused",
                     migration->unsupported_count);
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    return MAELYS_GIT_OK;
}

static FILE *open_migration_input(const char *input_path, const char *output_directory,
                                  maelys_git_error_t *error) {
    struct stat existing;
    if (lstat(output_directory, &existing) == 0 || errno != ENOENT) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                     "migration output must not already exist: %s", output_directory);
        return NULL;
    }
    FILE *input = fopen(input_path, "rb");
    if (!input)
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                     "cannot read Gitolite configuration: %s", strerror(errno));
    return input;
}

maelys_git_result_t maelys_git_migrate_gitolite(
    const char *input_path,
    const char *output_directory,
    int apply,
    maelys_git_gitolite_migration_result_t *out_result,
    maelys_git_error_t *error) {
    return mg_migrate_gitolite_grants(input_path, output_directory, apply, out_result, error);
}

/* The compiled encoding of GIT-C03: one fact per elementary grant, a rule
 * per prefix beyond the facts, in a policy whose text is the configuration.
 * Kept to judge the grants as data against it (GIT-C06, D1). */
maelys_git_result_t mg_migrate_gitolite_compiled(
    const char *input_path,
    const char *output_directory,
    int apply,
    maelys_git_gitolite_migration_result_t *out_result,
    maelys_git_error_t *error) {
    maelys_git_error_clear(error);
    if (!input_path || !*input_path || !output_directory || !*output_directory || !out_result)
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    memset(out_result, 0, sizeof(*out_result));
    FILE *input = open_migration_input(input_path, output_directory, error);
    if (!input) return MAELYS_GIT_ERR_IO;
    text_buffer_t policy = {0}, manifest = {0};
    size_t prefix_facts = 0u;
    maelys_git_result_t result = generate(input, 1, &policy, &manifest, &prefix_facts,
                                          out_result, error);
    /* A prefix as a fact spends a fact and an atom where the rule form spends
     * rules. When those budgets refuse a policy that has prefix facts, the
     * rule form is tried, and kept if every budget then holds: what the rule
     * form of 62778f0 admitted stays admitted. */
    const maelys_git_failure_detail_t *refused = &out_result->budget.failure;
    if (result == MAELYS_GIT_OK && prefix_facts > 0u &&
        refused->kind == MAELYS_GIT_FAILURE_CAPACITY &&
        (!strcmp(refused->budget, "MAX_RULE_FACTS") || !strcmp(refused->budget, "MAX_POLICY_ATOMS"))) {
        text_buffer_t rule_policy = {0}, rule_manifest = {0};
        maelys_git_gitolite_migration_result_t rule_form;
        memset(&rule_form, 0, sizeof(rule_form));
        rewind(input);
        result = generate(input, 0, &rule_policy, &rule_manifest, &prefix_facts, &rule_form, error);
        if (result == MAELYS_GIT_OK && rule_form.budget.failure.kind == MAELYS_GIT_FAILURE_NONE) {
            maelys_git_gitolite_migration_result_clear(out_result);
            free(policy.data); free(manifest.data);
            *out_result = rule_form;
            policy = rule_policy;
            manifest = rule_manifest;
        } else {
            maelys_git_gitolite_migration_result_clear(&rule_form);
            free(rule_policy.data); free(rule_manifest.data);
        }
    }
    fclose(input);
    if (result != MAELYS_GIT_OK) {
        free(policy.data); free(manifest.data);
        maelys_git_gitolite_migration_result_clear(out_result);
        if (!error->message[0]) mg_error_set(error, result, errno, "cannot compile Gitolite policy");
        return result;
    }
    if (apply) result = refuse_apply(out_result, error);
    if (!apply || result != MAELYS_GIT_OK) {
        free(policy.data); free(manifest.data);
        return result;
    }
    const output_file_t files[] = {
        {"gitolite-migrated.dl", policy.data, policy.length},
        {"manifest.json", manifest.data, manifest.length}};
    result = publish(output_directory, files, 2u, 0, error);
    free(policy.data); free(manifest.data);
    return result;
}

/* The grants snapshot of a configuration: its bytes, or an unsupported entry
 * when they exceed the snapshot's bounds; and, parsed, the snapshot the
 * program is judged with, which is empty when they do. */
static maelys_git_result_t snapshot_of(grants_builder_t *grants, size_t line_number, char **out_bytes,
                                       size_t *out_size, mg_grants_t **out_parsed,
                                       maelys_git_gitolite_migration_result_t *migration,
                                       maelys_git_error_t *error) {
    maelys_git_error_t refusal = {0};
    maelys_json_result_t written = serialize_grants(grants, out_bytes, out_size);
    if (written == MAELYS_JSON_OK && mg_grants_parse(*out_bytes, *out_size, out_parsed, &refusal) == MAELYS_GIT_OK)
        return MAELYS_GIT_OK;
    if (written == MAELYS_JSON_ERR_MEMORY) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, ENOMEM, "cannot write the grants snapshot");
        return MAELYS_GIT_ERR_IO;
    }
    free(*out_bytes);
    *out_bytes = NULL;
    if (!add_unsupported(migration, line_number, "grants snapshot refused",
                         written == MAELYS_JSON_OK ? refusal.message :
                         "it exceeds the bounds of maelys-git-grants/1"))
        return MAELYS_GIT_ERR_IO;
    grants_builder_t empty = {0};
    char *bytes = NULL;
    size_t size = 0u;
    maelys_git_result_t result = serialize_grants(&empty, &bytes, &size) == MAELYS_JSON_OK
        ? mg_grants_parse(bytes, size, out_parsed, error) : MAELYS_GIT_ERR_IO;
    free(bytes);
    return result;
}

maelys_git_result_t mg_migrate_gitolite_grants(const char *input_path, const char *output_directory, int apply,
                                               maelys_git_gitolite_migration_result_t *out_result,
                                               maelys_git_error_t *error) {
    maelys_git_error_clear(error);
    if (!input_path || !*input_path || !output_directory || !*output_directory || !out_result)
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    memset(out_result, 0, sizeof(*out_result));
    FILE *input = open_migration_input(input_path, output_directory, error);
    if (!input) return MAELYS_GIT_ERR_IO;
    /* The compiled text is read and discarded: the grants are what the
     * generator would have compiled, entry for entry. */
    text_buffer_t compiled = {0}, manifest = {0};
    grants_builder_t grants = {0};
    memberships_t graph = {0};
    size_t lines = 0u, prefix_facts = 0u;
    maelys_git_result_t result = parse_gitolite(input, 1, &compiled, &grants, &graph, &lines, &prefix_facts,
                                                out_result, error);
    fclose(input);
    free(compiled.data);
    size_t program_length = 0u;
    const char *program = mg_gitolite_program_text(&program_length);
    char *snapshot = NULL;
    size_t snapshot_size = 0u;
    mg_grants_t *parsed = NULL;
    if (result == MAELYS_GIT_OK)
        result = snapshot_of(&grants, lines, &snapshot, &snapshot_size, &parsed, out_result, error);
    if (result == MAELYS_GIT_OK &&
        !build_manifest(program, program_length, "Audited Gitolite program " MG_GITOLITE_PROGRAM_FORMAT
                        "; its grants are a maelys-git-grants/1 snapshot", &manifest))
        result = MAELYS_GIT_ERR_IO;
    if (result == MAELYS_GIT_OK) {
        result = judge_budget(program, program_length, &manifest, parsed, &graph, lines, out_result, error);
        parsed = NULL; /* the judged handle owned it */
    }
    mg_grants_free(parsed);
    grants_builder_clear(&grants);
    memberships_clear(&graph);
    if (result != MAELYS_GIT_OK) {
        maelys_git_gitolite_migration_result_clear(out_result);
        if (!error->message[0]) mg_error_set(error, result, errno, "cannot migrate Gitolite grants");
    } else if (apply) {
        result = refuse_apply(out_result, error);
    }
    if (result == MAELYS_GIT_OK && apply) {
        const output_file_t files[] = {
            {"gitolite-migrated.dl", program, program_length},
            {"manifest.json", manifest.data, manifest.length},
            {"grants.json", snapshot, snapshot_size}};
        result = publish(output_directory, files, 3u, 1, error);
    }
    free(snapshot);
    free(manifest.data);
    return result;
}
