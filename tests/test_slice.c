/* The slice of a grants snapshot for one request, maelys-git-slice/1: the
 * indexed extractor against a reference that reads the definition of each
 * predicate literally, over the whole snapshot; a snapshot whose expected
 * slice is written out; and the corpus of ref matches. */
#include "internal.h"
#include "policy/slice.h"
#include "slice_reference.h"
#include "test_support.h"

#include <stdarg.h>

/* ---- texts ------------------------------------------------------------------ */

typedef struct {
    char *data;
    size_t length, capacity;
} text_t;

static int append(text_t *text, const char *format, ...) MG_PRINTF(2, 3);

static int append(text_t *text, const char *format, ...) {
    va_list args;
    va_start(args, format);
    va_list copy;
    va_copy(copy, args);
    int needed = vsnprintf(NULL, 0u, format, copy);
    va_end(copy);
    if (needed < 0) { va_end(args); return 0; }
    while (text->length + (size_t)needed + 1u > text->capacity) {
        size_t next = text->capacity ? text->capacity * 2u : 1024u;
        char *grown = realloc(text->data, next);
        if (!grown) { va_end(args); return 0; }
        text->data = grown;
        text->capacity = next;
    }
    (void)vsnprintf(text->data + text->length, text->capacity - text->length, format, args);
    va_end(args);
    text->length += (size_t)needed;
    return 1;
}

/* A canonical snapshot from its sections, each the inside of its array. */
static char *snapshot(const char *access, const char *members, const char *creators, const char *nested,
                      const char *owners, const char *refs, const char *limits, const char *names) {
    text_t text = {0};
    int ok = append(&text,
                    "{\"access\":[%s],\"format\":\"maelys-git-grants/1\",\"members\":[%s],"
                    "\"namespace_creators\":[%s],\"nested\":[%s],\"owner_access\":[%s],\"refs\":[%s],"
                    "\"vref_limits\":[%s],\"vref_names\":[%s]}",
                    access ? access : "", members ? members : "", creators ? creators : "",
                    nested ? nested : "", owners ? owners : "", refs ? refs : "", limits ? limits : "",
                    names ? names : "");
    if (!ok) free(text.data);
    return ok ? text.data : NULL;
}

static mg_grants_t *load(const char *text) {
    mg_grants_t *grants = NULL;
    maelys_git_error_t error = {0};
    if (!text || mg_grants_parse(text, strlen(text), &grants, &error) != MAELYS_GIT_OK)
        (void)fprintf(stderr, "snapshot refused: %s\n%s\n", error.message, text ? text : "");
    return grants;
}

/* ---- the reference extractor: slice_reference.h --------------------------------- */

/* The two slices hold the same facts, string by string. */
static int same_slice(const mg_slice_t *a, const mg_slice_t *b) {
    if (a->count != b->count) return 0;
    for (size_t i = 0u; i < a->count; ++i)
        if (mg_slice_fact_compare(&a->facts[i], &b->facts[i])) return 0;
    return 1;
}

static void print_slice(const char *label, const mg_slice_t *slice) {
    (void)fprintf(stderr, "%s (%zu):\n", label, slice->count);
    for (size_t i = 0u; i < slice->count; ++i) {
        const mg_slice_fact_t *f = &slice->facts[i];
        (void)fprintf(stderr, "  %s(%s, %s, %s, %lld)\n", mg_slice_predicate_name(f->predicate),
                      f->text[0] ? f->text[0] : "-", f->text[1] ? f->text[1] : "-",
                      f->text[2] ? f->text[2] : "-", (long long)f->number);
    }
}

/* ---- the written-out slice ---------------------------------------------------- */

static int has_fact(const mg_slice_t *slice, mg_slice_predicate_t predicate, const char *a, const char *b,
                    const char *c, int64_t number) {
    const mg_slice_fact_t wanted = {predicate, {a, b, c}, number};
    for (size_t i = 0u; i < slice->count; ++i)
        if (!mg_slice_fact_compare(&slice->facts[i], &wanted)) return 1;
    return 0;
}

static int test_written_slice(void) {
    char *text = snapshot(
        "[\"group\",\"all\",\"app.git\",\"R\"],[\"group\",\"devs\",\"app.git\",\"RW\"],"
        "[\"user\",\"alice\",\"other.git\",\"RW+\"]",
        "[\"alice\",\"devs\"],[\"bob\",\"ops\"]",
        "[\"user\",\"alice\",\"team\"]",
        "[\"devs\",\"eng\"],[\"eng\",\"all\"]",
        "[\"team\",\"RW\"]",
        "[\"group\",\"devs\",\"app.git\",\"prefix\",\"refs/heads/rel/\",\"RW\"],"
        "[\"group\",\"eng\",\"app.git\",\"prefix\",\"refs/heads/main\",\"-\"],"
        "[\"user\",\"alice\",\"app.git\",\"exact\",\"refs/heads/feature\",\"RW+\"]",
        "[\"group\",\"devs\",\"app.git\",\"count\",5]",
        "[\"group\",\"devs\",\"app.git\",\"docs/secret.txt\"],[\"group\",\"ops\",\"app.git\",\"docs/ops.txt\"]");
    mg_grants_t *grants = load(text);
    CHECK(grants);
    const char *paths[] = {"docs/secret.txt", "src/x.c"};
    mg_slice_request_t request = {"alice", "app.git", "refs/heads/main", paths, 2u};
    mg_slice_t slice;
    maelys_git_error_t error = {0};
    CHECK(mg_slice_extract(grants, &request, &slice, &error) == MAELYS_GIT_OK);
    /* Groups closed through two nesting edges. */
    CHECK(has_fact(&slice, MG_SLICE_MEMBER, "alice", "devs", NULL, 0));
    CHECK(has_fact(&slice, MG_SLICE_NESTED, "devs", "eng", NULL, 0));
    CHECK(has_fact(&slice, MG_SLICE_NESTED, "eng", "all", NULL, 0));
    /* Access on the repository only, for alice's groups. */
    CHECK(has_fact(&slice, MG_SLICE_GROUP_ACCESS, "all", "app.git", "R", 0));
    CHECK(has_fact(&slice, MG_SLICE_GROUP_ACCESS, "devs", "app.git", "RW", 0));
    /* The bare deny of eng matches main; alice's exact feature ref does not. */
    CHECK(has_fact(&slice, MG_SLICE_GROUP_REF_MATCH, "eng", "app.git", "-", 0));
    /* Write levels on some ref of the repository, whatever the ref. */
    CHECK(has_fact(&slice, MG_SLICE_GROUP_REF_LEVEL, "devs", "app.git", "RW", 0));
    CHECK(has_fact(&slice, MG_SLICE_REF_LEVEL, "alice", "app.git", "RW+", 0));
    /* A VREF name of the request's paths; the limits all. Not bob's group. */
    CHECK(has_fact(&slice, MG_SLICE_GROUP_VREF_NAME, "devs", "app.git", "docs/secret.txt", 0));
    CHECK(has_fact(&slice, MG_SLICE_GROUP_VREF_COUNT, "devs", "app.git", NULL, 5));
    if (slice.count != 10u) print_slice("written slice", &slice);
    CHECK(slice.count == 10u);
    mg_slice_clear(&slice);

    /* In the namespace alice owns: its creator and owner access. */
    mg_slice_request_t owned = {"alice", "team/alice/x.git", NULL, NULL, 0u};
    CHECK(mg_slice_extract(grants, &owned, &slice, &error) == MAELYS_GIT_OK);
    CHECK(has_fact(&slice, MG_SLICE_NAMESPACE_CREATOR, "alice", "team", NULL, 0));
    CHECK(has_fact(&slice, MG_SLICE_OWNER_ACCESS, "team", "RW", NULL, 0));
    mg_slice_clear(&slice);
    /* Not in another user's namespace. */
    mg_slice_request_t foreign = {"alice", "team/bob/x.git", NULL, NULL, 0u};
    CHECK(mg_slice_extract(grants, &foreign, &slice, &error) == MAELYS_GIT_OK);
    CHECK(!has_fact(&slice, MG_SLICE_OWNER_ACCESS, "team", "RW", NULL, 0));
    mg_slice_clear(&slice);
    mg_grants_free(grants);
    free(text);
    return 1;
}

/* ---- the corpus of matches ------------------------------------------------------- */

static int test_matches(void) {
    char deep[300], long_pattern[257], long_ref[300];
    (void)snprintf(deep, sizeof(deep), "refs/heads/%s", "a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/");
    memset(long_pattern, 'x', 256u);
    memcpy(long_pattern, "refs/heads/", 11u);
    long_pattern[255] = '/';
    long_pattern[256] = '\0';
    (void)snprintf(long_ref, sizeof(long_ref), "%sleaf", long_pattern);
    char deep_ref[320];
    (void)snprintf(deep_ref, sizeof(deep_ref), "%sleaf", deep);
    static const struct {
        int prefix;
        const char *pattern, *ref;
        int expected;
    } corpus[] = {
        {1, "refs/heads/rel/", "refs/heads/rel/1", 1},
        {1, "refs/heads/rel/", "refs/heads/release", 0},   /* the '/' is a boundary */
        {1, "refs/heads/rel/", "refs/heads/rel", 0},
        {1, "refs/heads/main", "refs/heads/main", 1},      /* a deny's bare literal */
        {1, "refs/heads/main", "refs/heads/mainline", 1},  /* Gitolite denies it as a prefix */
        {0, "refs/heads/main", "refs/heads/main", 1},
        {0, "refs/heads/main", "refs/heads/mainline", 0},
        {0, "refs/heads/main", "refs/heads/mai", 0},
        {1, "refs/", "refs/tags/v1", 1},
        {1, "refs/tags/", "refs/heads/tags/x", 0},
    };
    for (size_t i = 0u; i < sizeof(corpus) / sizeof(corpus[0]); ++i)
        CHECK(mg_slice_pattern_matches(corpus[i].prefix, corpus[i].pattern, corpus[i].ref) == corpus[i].expected);
    /* Deeper than 16 '/' and longer than 63 bytes: matches like the others. */
    CHECK(mg_slice_pattern_matches(1, deep, deep_ref));
    CHECK(mg_slice_pattern_matches(1, long_pattern, long_ref));
    CHECK(!mg_slice_pattern_matches(1, long_pattern, "refs/heads/x"));
    CHECK(!mg_slice_pattern_matches(1, "refs/heads/", NULL));

    char out[64];
    CHECK(mg_slice_owner_namespace("team/alice/x.git", "alice", out, sizeof(out)) &&
          !strcmp(out, "team"));
    CHECK(!mg_slice_owner_namespace("team/alice.git", "alice", out, sizeof(out)));
    CHECK(!mg_slice_owner_namespace("team/bob/x.git", "alice", out, sizeof(out)));
    CHECK(mg_slice_owner_namespace("team/alice/a/b.git", "alice", out, sizeof(out)) && !strcmp(out, "team"));
    return 1;
}

/* ---- the oracle -------------------------------------------------------------------- */

static unsigned long g_seed;
static unsigned rnd(unsigned bound) {
    g_seed = g_seed * 6364136223846793005ul + 1442695040888963407ul;
    return (unsigned)((g_seed >> 33) % bound);
}

static const char *const k_users[] = {"u0", "u1", "u2", "u3", "u4", "u5"};
static const char *const k_groups[] = {"g0", "g1", "g2", "g3", "g4"};
static const char *const k_repos[] = {"a.git", "b.git", "ns/u1/c.git", "ns/u2/d.git", "ns/u1/deep/e.git"};
static const char *const k_patterns[][3] = {
    /* form, pattern, level */
    {"exact", "refs/heads/main", "RW"}, {"exact", "refs/heads/main", "RW+"}, {"prefix", "refs/heads/rel/", "RW"},
    {"prefix", "refs/heads/main", "-"}, {"prefix", "refs/", "RW+"}, {"exact", "refs/tags/v1", "-"},
    {"prefix", "refs/heads/rel/", "-"}, {"exact", "refs/heads/feature", "RW"},
};
static const char *const k_levels[] = {"C", "R", "RW", "RW+"};
static const char *const k_paths[] = {"docs/a.md", "src/x.c", "bin/tool"};

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

typedef struct {
    char *items[512];
    size_t count;
} tuples_t;

static int add_tuple(tuples_t *tuples, const char *text) {
    if (tuples->count == COUNT(tuples->items)) return 1;
    tuples->items[tuples->count] = strdup(text);
    return tuples->items[tuples->count++] != NULL;
}

static int compare_strings(const void *a, const void *b) {
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/* The section, sorted and without duplicates. With the characters of the
 * schema, the text order of tuples is the reader's field order: '"' sorts
 * below every one of them, and VREF values are single digits. */
static char *section(tuples_t *tuples) {
    qsort(tuples->items, tuples->count, sizeof(char *), compare_strings);
    text_t text = {0};
    (void)append(&text, "%s", "");
    for (size_t i = 0u; i < tuples->count; ++i)
        if (!i || strcmp(tuples->items[i], tuples->items[i - 1u]))
            (void)append(&text, "%s%s", text.length ? "," : "", tuples->items[i]);
    for (size_t i = 0u; i < tuples->count; ++i) free(tuples->items[i]);
    tuples->count = 0u;
    return text.data;
}

static const char *subject_of(int group, char *kind_out) {
    (void)kind_out;
    return group ? k_groups[rnd(COUNT(k_groups))] : k_users[rnd(COUNT(k_users))];
}

static char *random_snapshot(void) {
    tuples_t t = {0};
    char line[256];
    char *access, *members, *creators, *nested, *owners, *refs, *limits, *names;
    for (unsigned i = rnd(10) + 2u; i; --i) {
        (void)snprintf(line, sizeof(line), "[\"%s\",\"%s\"]", k_users[rnd(COUNT(k_users))], k_groups[rnd(COUNT(k_groups))]);
        (void)add_tuple(&t, line);
    }
    members = section(&t);
    for (unsigned i = rnd(5); i; --i) {
        (void)snprintf(line, sizeof(line), "[\"%s\",\"%s\"]", k_groups[rnd(COUNT(k_groups))], k_groups[rnd(COUNT(k_groups))]);
        (void)add_tuple(&t, line);
    }
    nested = section(&t);
    for (unsigned i = rnd(15) + 1u; i; --i) {
        int group = (int)rnd(2);
        (void)snprintf(line, sizeof(line), "[\"%s\",\"%s\",\"%s\",\"%s\"]", group ? "group" : "user",
                       subject_of(group, NULL), k_repos[rnd(COUNT(k_repos))], k_levels[rnd(COUNT(k_levels))]);
        (void)add_tuple(&t, line);
    }
    access = section(&t);
    for (unsigned i = rnd(15); i; --i) {
        int group = (int)rnd(2);
        const char *const *p = k_patterns[rnd(COUNT(k_patterns))];
        (void)snprintf(line, sizeof(line), "[\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"]", group ? "group" : "user",
                       subject_of(group, NULL), k_repos[rnd(COUNT(k_repos))], p[0], p[1], p[2]);
        (void)add_tuple(&t, line);
    }
    refs = section(&t);
    for (unsigned i = rnd(4); i; --i) {
        int group = (int)rnd(2);
        (void)snprintf(line, sizeof(line), "[\"%s\",\"%s\",\"ns\"]", group ? "group" : "user", subject_of(group, NULL));
        (void)add_tuple(&t, line);
    }
    creators = section(&t);
    if (rnd(2)) (void)add_tuple(&t, "[\"ns\",\"RW\"]");
    owners = section(&t);
    for (unsigned i = rnd(5); i; --i) {
        int group = (int)rnd(2);
        (void)snprintf(line, sizeof(line), "[\"%s\",\"%s\",\"%s\",\"%s\"]", group ? "group" : "user",
                       subject_of(group, NULL), k_repos[rnd(COUNT(k_repos))], k_paths[rnd(COUNT(k_paths))]);
        (void)add_tuple(&t, line);
    }
    names = section(&t);
    static const char *const kinds[] = {"count", "new_count", "max_new_binary"};
    for (unsigned i = rnd(5); i; --i) {
        int group = (int)rnd(2);
        (void)snprintf(line, sizeof(line), "[\"%s\",\"%s\",\"%s\",\"%s\",%u]", group ? "group" : "user",
                       subject_of(group, NULL), k_repos[rnd(COUNT(k_repos))], kinds[rnd(3)], rnd(10));
        (void)add_tuple(&t, line);
    }
    limits = section(&t);
    char *text = snapshot(access, members, creators, nested, owners, refs, limits, names);
    free(access); free(members); free(creators); free(nested); free(owners); free(refs); free(limits); free(names);
    return text;
}

static int test_oracle(void) {
    static const char *const refs[] = {NULL, "refs/heads/main", "refs/heads/rel/1", "refs/heads/mainline",
                                       "refs/tags/v1", "refs/heads/feature", "refs/heads/release"};
    static const char *const users[] = {"u0", "u1", "u2", "u3", "u4", "u5", "nobody"};
    static const char *const repos[] = {"a.git", "b.git", "ns/u1/c.git", "ns/u2/d.git", "ns/u1/deep/e.git",
                                        "zz.git"};
    const char *one_path[] = {"docs/a.md"};
    const char *two_paths[] = {"docs/a.md", "src/x.c"};
    size_t compared = 0u, facts = 0u;
    for (unsigned snapshot_index = 0u; snapshot_index < 200u; ++snapshot_index) {
        g_seed = 0x5eedu + snapshot_index;
        char *text = random_snapshot();
        mg_grants_t *grants = load(text);
        CHECK(grants);
        for (size_t u = 0u; u < COUNT(users); ++u)
            for (size_t p = 0u; p < COUNT(repos); ++p)
                for (size_t r = 0u; r < COUNT(refs); ++r)
                    for (size_t paths = 0u; paths < 3u; ++paths) {
                        mg_slice_request_t request = {users[u], repos[p], refs[r],
                                                      paths == 2u ? two_paths : one_path, paths};
                        mg_slice_t indexed, reference;
                        maelys_git_error_t error = {0};
                        CHECK(mg_slice_extract(grants, &request, &indexed, &error) == MAELYS_GIT_OK);
                        CHECK(reference_slice(grants, &request, &reference));
                        if (!same_slice(&indexed, &reference)) {
                            (void)fprintf(stderr, "snapshot %u, %s on %s, ref %s:\n%s\n", snapshot_index, users[u],
                                          repos[p], refs[r] ? refs[r] : "none", text);
                            print_slice("indexed", &indexed);
                            print_slice("reference", &reference);
                        }
                        CHECK(same_slice(&indexed, &reference));
                        facts += indexed.count;
                        ++compared;
                        mg_slice_clear(&indexed);
                        mg_slice_clear(&reference);
                    }
        mg_grants_free(grants);
        free(text);
    }
    CHECK(compared == 200u * COUNT(users) * COUNT(repos) * COUNT(refs) * 3u && facts > compared);
    return 1;
}

/* Hundreds of groups and a cycle: alice belongs to 64 groups, each nested
 * in 8 others, each of those in one of 16 more, the first of which closes a
 * cycle back to a group of alice; bob belongs to one group in the middle.
 * The index of the groups reached grows several times and its slots
 * collide; the slices must still be the full scan's. */
static int test_many_groups(void) {
    text_t members = {0}, nested = {0}, access = {0};
    int ok = 1;
    for (unsigned d = 0u; ok && d < 64u; ++d)
        ok = append(&members, "%s[\"alice\",\"d%02u\"]", d ? "," : "", d);
    ok = ok && append(&members, ",[\"bob\",\"p100\"]");
    for (unsigned d = 0u; ok && d < 64u; ++d)
        for (unsigned k = 0u; ok && k < 8u; ++k)
            ok = append(&nested, "%s[\"d%02u\",\"p%03u\"]", nested.length ? "," : "", d, d * 8u + k);
    for (unsigned q = 0u; ok && q < 512u; ++q) ok = append(&nested, ",[\"p%03u\",\"t%02u\"]", q, q % 16u);
    ok = ok && append(&nested, ",[\"t00\",\"d00\"]");
    for (unsigned q = 0u; ok && q < 512u; q += 7u)
        ok = append(&access, "%s[\"group\",\"p%03u\",\"app.git\",\"R\"]", access.length ? "," : "", q);
    for (unsigned t = 0u; ok && t < 16u; ++t) ok = append(&access, ",[\"group\",\"t%02u\",\"app.git\",\"RW\"]", t);
    CHECK(ok);
    char *text = snapshot(access.data, members.data, NULL, nested.data, NULL, NULL, NULL, NULL);
    free(members.data);
    free(nested.data);
    free(access.data);
    mg_grants_t *grants = load(text);
    free(text);
    CHECK(grants);
    static const char *const users[] = {"alice", "bob", "nobody"};
    static const char *const repos[] = {"app.git", "other.git"};
    size_t alice_nested = 0u;
    for (size_t u = 0u; u < COUNT(users); ++u)
        for (size_t r = 0u; r < COUNT(repos); ++r) {
            mg_slice_request_t request = {users[u], repos[r], "refs/heads/main", NULL, 0u};
            mg_slice_t indexed, reference;
            maelys_git_error_t error = {0};
            CHECK(mg_slice_extract(grants, &request, &indexed, &error) == MAELYS_GIT_OK);
            CHECK(reference_slice(grants, &request, &reference));
            CHECK(same_slice(&indexed, &reference));
            if (u == 0u && r == 0u)
                for (size_t i = 0u; i < indexed.count; ++i) alice_nested += indexed.facts[i].predicate == MG_SLICE_NESTED;
            mg_slice_clear(&indexed);
            mg_slice_clear(&reference);
        }
    /* alice reaches 64 + 512 + 16 groups: every edge, the cycle's included. */
    CHECK(alice_nested == 512u + 512u + 1u);
    mg_grants_free(grants);
    return 1;
}

int main(void) {
    int ok = test_written_slice() && test_matches() && test_oracle() && test_many_groups();
    if (ok) puts("grants slice: written slice, matches, oracle against the full scan, many groups: ok");
    return ok ? 0 : 1;
}
