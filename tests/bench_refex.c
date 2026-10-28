/* The measurements of GIT-C08 for the review of D3: what "regex" patterns
 * cost, at the budgets of policy/refex.h. Not a test: timings and memory
 * depend on the machine.
 *
 *   bench-maelys-git-refex [ROUNDS]
 *   bench-maelys-git-refex push COMMITS CHANGES DIRECTORY
 *     Through the policy, the requests of a push of one ref as the hook makes
 *     them (the update, COMMITS commits, CHANGES changed files, a summary),
 *     on a repository of 50 patterns (.*a){16}xNN (4 000 states) and on the
 *     same grants as literals: the time of the whole series for each, the
 *     regex searches made (one per pattern, the memo kept for the ref), and
 *     the difference, which is what the patterns cost. DIRECTORY receives
 *     the manifest and the snapshots.
 *   bench-maelys-git-refex peak FAMILY GENERATIONS
 *     In a process of its own, the resident peak of loading GENERATIONS
 *     distinct snapshots of FAMILY (large: 256 patterns of 4 095 states;
 *     small: 40 000 distinct patterns with classes), each kept while the
 *     next loads, as a stream holds the old one: the peak includes the
 *     input bytes and the transient memory of the parse.
 *
 * Prints, each a median of ROUNDS (default 9):
 *   load      large: 256 patterns of 4 095 states, one per repository, the
 *             total budget; small: 40 000 distinct patterns with classes,
 *             100 on each of 400 repositories; realistic: 1 024 grants of 16
 *             refexes. Parse time, bytes held once loaded, per state, and
 *             the scratch;
 *   reload    the bytes held while an old and a new generation of each are
 *             both loaded, as a stream holds them;
 *   request   one repository within 4 096 states, a ref of 511 bytes: a
 *             linear pattern, an alternation under a repeat, and 50 small
 *             patterns that each keep threads alive along the ref;
 *   shared    one pattern a user reaches through 64 groups at 3 levels:
 *             192 searches, as the extractor would without a memo, against
 *             one;
 *   realistic the refexes of the oracle's corpus on refs of about 30 bytes;
 *   push      the searches of one push: the hook authorizes the update, each
 *             commit and each changed file of a ref, and a summary, each
 *             request with the same ref (up to 1 + 10 000 + 100 000 + 1 by
 *             default): computed from the worst request, with a memo per
 *             request and with a memo kept for the ref across requests. */
#include <sys/resource.h>
#include "policy/grants.h"
#include "policy/policy_grants.h"
#include "policy/program.h"
#include "policy/refex.h"

#include <maelys/cli/digest.h>

#include <maelys/cli/regex.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef __APPLE__
#include <malloc/malloc.h>
static double in_use_bytes(void) {
    malloc_statistics_t stats;
    malloc_zone_statistics(NULL, &stats);
    return (double)stats.size_in_use;
}
#else
#include <malloc.h>
static double in_use_bytes(void) {
    struct mallinfo2 info = mallinfo2();
    return (double)(info.uordblks + info.hblkhd);
}
#endif

static double now_ns(void) {
    struct timespec now;
    (void)clock_gettime(CLOCK_MONOTONIC, &now);
    return (double)now.tv_sec * 1e9 + (double)now.tv_nsec;
}

static int compare_double(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static double median(double *values, size_t count) {
    qsort(values, count, sizeof(*values), compare_double);
    return values[count / 2u];
}

/* Appends to a growing text, or fails the program. */
static void add(char **text, size_t *length, size_t *capacity, const char *piece) {
    size_t n = strlen(piece);
    while (*length + n + 1u > *capacity) {
        *capacity = *capacity ? *capacity * 2u : 4096u;
        *text = realloc(*text, *capacity);
        if (!*text) exit(2);
    }
    memcpy(*text + *length, piece, n + 1u);
    *length += n;
}

/* A maelys-git-grants/2 snapshot of REFS. */
static char *snapshot_of(const char *refs) {
    static const char k_format[] =
        "{\"access\":[],\"format\":\"maelys-git-grants/2\",\"members\":[],\"namespace_creators\":[],"
        "\"nested\":[],\"owner_access\":[],\"refs\":[%s],\"vref_limits\":[],\"vref_names\":[]}";
    size_t size = strlen(k_format) + strlen(refs) + 1u;
    char *text = malloc(size);
    if (!text) exit(2);
    (void)snprintf(text, size, k_format, refs);
    return text;
}

static const char *const k_realistic[] = {
    "refs/heads/(main|dev)$", "refs/heads/[a-z]+/[0-9]+$", "refs/heads/feature/.*", "refs/heads/fix-[0-9]+",
    "refs/heads/hotfix/v[0-9]+\\\\.[0-9]+", "refs/heads/release[0-9]", "refs/heads/release/[0-9]+\\\\.[0-9]+$",
    "refs/heads/team-(a|b|c)/", "refs/heads/u/[a-z]+/.*", "refs/heads/wip/", "refs/heads/x[^a-c]y",
    "refs/tags/rc-[0-9]{1,3}$", "refs/tags/v[0-9]+$", "refs/tags/v[0-9]+\\\\.[0-9]+\\\\.[0-9]+$",
    "refs/tags/v[0-9]+\\\\.0", "refs/tags/[a-z]+-[0-9]{4}",
};
#define REALISTIC_COUNT (sizeof(k_realistic) / sizeof(k_realistic[0]))

/* 1 024 grants: 64 users on 16 repositories, the 16 refexes (sorted). */
static char *realistic_snapshot(void) {
    char *refs = NULL, piece[200];
    size_t length = 0u, capacity = 0u, made = 0u;
    add(&refs, &length, &capacity, "");
    for (size_t u = 0u; u < 64u; ++u)
        for (size_t r = 0u; r < 16u; ++r, ++made) {
            (void)snprintf(piece, sizeof(piece), "%s[\"user\",\"u%02zu\",\"r%02zu.git\",\"regex\",\"%s\",\"RW\"]",
                           made ? "," : "", u, r, k_realistic[r]);
            add(&refs, &length, &capacity, piece);
        }
    char *text = snapshot_of(refs);
    free(refs);
    return text;
}

/* 40 000 distinct small patterns with classes, 100 on each of 400
 * repositories (2 200 states each); SALT changes every pattern. */
static char *small_snapshot(char salt) {
    char *refs = NULL, piece[200];
    size_t length = 0u, capacity = 0u;
    add(&refs, &length, &capacity, "");
    for (size_t i = 0u; i < 40000u; ++i) {
        (void)snprintf(piece, sizeof(piece),
                       "%s[\"user\",\"alice\",\"r%05zu.git\",\"regex\",\"refs/[%c][b][c][d][e][f][g][h][i][j]%05zu\","
                       "\"RW\"]",
                       i ? "," : "", i / 100u, salt, i);
        add(&refs, &length, &capacity, piece);
    }
    char *text = snapshot_of(refs);
    free(refs);
    return text;
}

/* 256 repositories of one distinct pattern of 4 095 states each; SALT
 * changes every pattern. */
static char *large_snapshot(char salt) {
    char *refs = NULL, piece[200];
    size_t length = 0u, capacity = 0u;
    add(&refs, &length, &capacity, "");
    for (size_t r = 0u; r < 256u; ++r) {
        (void)snprintf(piece, sizeof(piece),
                       "%s[\"user\",\"alice\",\"r%03zu.git\",\"regex\",\"refs/heads/(a{255}){16}%c%c\",\"RW\"]",
                       r ? "," : "", r, (char)((size_t)salt + r / 26u), (char)('a' + r % 26u));
        add(&refs, &length, &capacity, piece);
    }
    char *text = snapshot_of(refs);
    free(refs);
    return text;
}

/* N patterns of one repository: PREFIX and their index on two digits. */
static char *repository_snapshot(const char *prefix, size_t n) {
    char *refs = NULL, piece[200], pattern[120];
    size_t length = 0u, capacity = 0u;
    add(&refs, &length, &capacity, "");
    for (size_t i = 0u; i < n; ++i) {
        (void)snprintf(pattern, sizeof(pattern), "%s%02zu", prefix, i);
        (void)snprintf(piece, sizeof(piece), "%s[\"user\",\"alice\",\"app.git\",\"regex\",\"%s\",\"RW\"]",
                       i ? "," : "", pattern);
        add(&refs, &length, &capacity, piece);
    }
    char *text = snapshot_of(refs);
    free(refs);
    return text;
}

static double peak_bytes(void) {
    struct rusage usage;
    (void)getrusage(RUSAGE_SELF, &usage);
#ifdef __APPLE__
    return (double)usage.ru_maxrss;          /* bytes */
#else
    return (double)usage.ru_maxrss * 1024.0; /* KiB */
#endif
}

static mg_grants_t *load(const char *text) {
    mg_grants_t *grants = NULL;
    maelys_git_error_t error = {0};
    if (mg_grants_parse(text, strlen(text), &grants, &error) != MAELYS_GIT_OK) {
        (void)fprintf(stderr, "snapshot refused: %s\n", error.message);
        exit(1);
    }
    return grants;
}

static void measure_load(const char *label, const char *text, size_t rounds) {
    double times[64], bytes = 0.0;
    mg_grants_view_t view = {0};
    for (size_t i = 0u; i < rounds; ++i) {
        double before = in_use_bytes(), start = now_ns();
        mg_grants_t *grants = load(text);
        times[i] = now_ns() - start;
        bytes = in_use_bytes() - before;
        mg_grants_view(grants, &view);
        mg_grants_free(grants);
    }
    (void)printf("load %-9s %zu patterns, %zu states (most per repository %zu): %.2f ms, %.2f MiB held, "
                 "%.1f bytes per state, scratch %zu bytes\n",
                 label, view.regex_count, view.regex_states, view.regex_repository_states, median(times, rounds) / 1e6,
                 bytes / 1048576.0, view.regex_states ? bytes / (double)view.regex_states : 0.0, view.scratch_bytes);
}

/* One search of each pattern of GRANTS on REF, in its scratch. */
static double search_all(const mg_grants_t *grants, const char *ref, size_t rounds, size_t repeat) {
    size_t scratch_size = 0u;
    void *scratch = mg_grants_scratch(grants, &scratch_size);
    mg_grants_view_t view;
    mg_grants_view(grants, &view);
    double times[64];
    size_t length = strlen(ref);
    for (size_t i = 0u; i < rounds; ++i) {
        double start = now_ns();
        for (size_t k = 0u; k < repeat; ++k)
            for (size_t p = 0u; p < view.regex_count; ++p)
                if (maelys_cli_regex_search_scratch(mg_grants_regex(grants, p), scratch, scratch_size, ref, length) <
                    0)
                    exit(3);
        times[i] = now_ns() - start;
    }
    return median(times, rounds);
}

static double request_ms(const char *label, const char *text, const char *ref, size_t rounds) {
    mg_grants_t *grants = load(text);
    mg_grants_view_t view;
    mg_grants_view(grants, &view);
    double ms = search_all(grants, ref, rounds, 1u) / 1e6;
    (void)printf("request   %-36s %3zu patterns, %4zu states on the repository, ref of %zu bytes: %.2f ms\n", label,
                 view.regex_count, view.regex_repository_states, strlen(ref), ms);
    mg_grants_free(grants);
    return ms;
}

static int write_bytes(const char *path, const char *text) {
    FILE *file = fopen(path, "w");
    if (!file) return 0;
    int ok = fputs(text, file) >= 0;
    return fclose(file) == 0 && ok;
}

/* The series of requests of one push of REF on POLICY: seconds. */
static double push_series(maelys_git_policy_t *policy, const char *ref, size_t commits, size_t changes) {
    static const char *const paths[1] = {"src/file.c"};
    maelys_git_policy_request_t update = {.request_id = "u", .principal = "alice", .repository = "app.git",
                                          .operation = "push", .ref_name = ref, .update_kind = "fast_forward"};
    maelys_git_policy_request_t commit = update, change = update, summary = update;
    commit.request_id = "c";
    commit.commit_signature_status = "unsigned";
    change.request_id = "f";
    change.paths = paths;
    change.path_count = 1u;
    change.has_change_details = 1;
    change.change_kind = "modified";
    summary.request_id = "s";
    summary.has_summary = 1;
    summary.changed_count = changes;
    summary.commit_count = commits;
    maelys_git_policy_decision_t decision;
    maelys_git_error_t error;
    double start = now_ns();
    int ok = maelys_git_policy_authorize(policy, &update, &decision, &error) == MAELYS_GIT_OK;
    for (size_t i = 0u; ok && i < commits; ++i)
        ok = maelys_git_policy_authorize(policy, &commit, &decision, &error) == MAELYS_GIT_OK;
    for (size_t i = 0u; ok && i < changes; ++i)
        ok = maelys_git_policy_authorize(policy, &change, &decision, &error) == MAELYS_GIT_OK;
    ok = ok && maelys_git_policy_authorize(policy, &summary, &decision, &error) == MAELYS_GIT_OK;
    if (!ok) {
        (void)fprintf(stderr, "push: %s\n", error.message);
        exit(1);
    }
    return (now_ns() - start) / 1e9;
}

static int push_bench(size_t commits, size_t changes, const char *directory) {
    char path[1024], manifest[4096], digest[MAELYS_CLI_SHA256_HEX_SIZE];
    size_t length = 0u;
    const char *program = mg_gitolite_program_text(&length);
    maelys_cli_sha256_hex(program, length, digest);
    (void)snprintf(path, sizeof(path), "%s/program.dl", directory);
    if (!write_bytes(path, program)) return 1;
    (void)snprintf(manifest, sizeof(manifest),
        "{\"policy_set_id\":\"bench.refex\",\"policy_set_version\":\"1\",\"manifest_version\":\"1\","
        "\"default_profile\":\"enforce\",\"created_for\":\"maelys-git-core-bench\",\"strict_loading\":true,"
        "\"fail_closed\":true,\"capabilities\":[],\"policies\":[{\"policy_id\":\"bench.refex.program\","
        "\"domain\":\"maelys_git\",\"file\":\"program.dl\",\"sha256\":\"%s\",\"mode\":\"enforce\","
        "\"enabled\":true,\"description\":\"bench\","
        "\"queries\":[{\"name\":\"allow\",\"arity\":1},{\"name\":\"deny\",\"arity\":1}]}]}\n", digest);
    char manifest_path[1024];
    (void)snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.json", directory);
    if (!write_bytes(manifest_path, manifest)) return 1;
    /* The 50 patterns, and one literal prefix that grants the push; the
     * same grants with literals only. */
    char *refs = NULL, piece[200];
    size_t used = 0u, capacity = 0u;
    add(&refs, &used, &capacity, "[\"user\",\"alice\",\"app.git\",\"prefix\",\"refs/heads/\",\"RW\"]");
    for (size_t i = 0u; i < 50u; ++i) {
        (void)snprintf(piece, sizeof(piece),
                       ",[\"user\",\"alice\",\"app.git\",\"regex\",\"refs/heads/(.*a){16}x%02zu\",\"RW\"]", i);
        add(&refs, &used, &capacity, piece);
    }
    char *with_regex = snapshot_of(refs);
    free(refs);
    char *literal = snapshot_of("[\"user\",\"alice\",\"app.git\",\"prefix\",\"refs/heads/\",\"RW\"]");
    memcpy(strstr(literal, "grants/2"), "grants/1", 8u);
    char ref[512];
    (void)snprintf(ref, sizeof(ref), "refs/heads/");
    memset(ref + 11, 'a', 500u);
    ref[511] = '\0';
    const char *texts[2] = {literal, with_regex}, *labels[2] = {"literal", "regex"};
    double seconds[2] = {0.0, 0.0};
    size_t searches[2] = {0u, 0u};
    for (size_t k = 0u; k < 2u; ++k) {
        char snapshot[1024];
        (void)snprintf(snapshot, sizeof(snapshot), "%s/grants-%s.json", directory, labels[k]);
        if (!write_bytes(snapshot, texts[k])) return 1;
        maelys_git_policy_t *policy = NULL;
        maelys_git_error_t error;
        if (mg_policy_open_grants(manifest_path, snapshot, &policy, &error) != MAELYS_GIT_OK) {
            (void)fprintf(stderr, "open: %s\n", error.message);
            return 1;
        }
        seconds[k] = push_series(policy, ref, commits, changes);
        searches[k] = mg_policy_regex_searches(policy);
        maelys_git_policy_close(policy);
    }
    size_t requests = 2u + commits + changes;
    (void)printf("push      %zu requests of one ref of 511 bytes: literal %.3f s; 50 regex patterns %.3f s, "
                 "%zu searches; the patterns cost %.3f s (%.1f us per request)\n",
                 requests, seconds[0], seconds[1], searches[1], seconds[1] - seconds[0],
                 (seconds[1] - seconds[0]) * 1e6 / (double)requests);
    free(with_regex);
    free(literal);
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 5 && !strcmp(argv[1], "push"))
        return push_bench((size_t)strtoul(argv[2], NULL, 10), (size_t)strtoul(argv[3], NULL, 10), argv[4]);
    if (argc == 4 && !strcmp(argv[1], "peak")) {
        int small = !strcmp(argv[2], "small");
        size_t generations = (size_t)strtoul(argv[3], NULL, 10);
        if (generations == 0u || generations > 4u) return 2;
        mg_grants_t *held[4] = {NULL, NULL, NULL, NULL};
        double base = peak_bytes(), in_use = in_use_bytes();
        for (size_t g = 0u; g < generations; ++g) {
            char *text = small ? small_snapshot((char)('a' + g)) : large_snapshot((char)('a' + g));
            held[g] = load(text);
            free(text);
        }
        (void)printf("peak      %-5s %zu generation(s) held: process peak %.1f MiB (%.1f MiB before), "
                     "%.2f MiB held\n",
                     argv[2], generations, peak_bytes() / 1048576.0, base / 1048576.0,
                     (in_use_bytes() - in_use) / 1048576.0);
        for (size_t g = 0u; g < generations; ++g) mg_grants_free(held[g]);
        return 0;
    }
    size_t rounds = argc > 1 ? (size_t)strtoul(argv[1], NULL, 10) : 9u;
    if (rounds == 0u || rounds > 64u) rounds = 9u;

    char *large = large_snapshot('a'), *small = small_snapshot('a'), *realistic = realistic_snapshot();
    measure_load("large", large, rounds);
    measure_load("small", small, rounds);
    measure_load("realistic", realistic, rounds);

    /* A stream keeps the old generation until the new one is loaded. */
    char *large2 = large_snapshot('b'), *small2 = small_snapshot('b');
    const char *const families[2][3] = {{"large", NULL, NULL}, {"small", NULL, NULL}};
    char *firsts[2] = {large, small}, *seconds[2] = {large2, small2};
    for (size_t f = 0u; f < 2u; ++f) {
        double before = in_use_bytes();
        mg_grants_t *old_generation = load(firsts[f]);
        double one = in_use_bytes() - before;
        mg_grants_t *new_generation = load(seconds[f]);
        double both = in_use_bytes() - before;
        mg_grants_free(old_generation);
        mg_grants_free(new_generation);
        (void)printf("reload    %-9s one generation %.2f MiB held, old and new together %.2f MiB\n", families[f][0],
                     one / 1048576.0, both / 1048576.0);
    }

    /* Requests on one repository within 4 096 states, a ref of 511 bytes. */
    char ref[512];
    (void)snprintf(ref, sizeof(ref), "refs/heads/");
    memset(ref + 11, 'a', 500u);
    ref[511] = '\0';
    char *linear = repository_snapshot("refs/heads/(a{255}){16}x", 1u);
    char *hard = repository_snapshot("refs/heads/(a|aa|aaa|b){1,255}x", 1u);
    char *many = repository_snapshot("refs/heads/(.*a){16}x", 50u);
    double worst = request_ms("one linear pattern", linear, ref, rounds);
    double ms = request_ms("one alternation under a repeat", hard, ref, rounds);
    if (ms > worst) worst = ms;
    ms = request_ms("50 patterns (.*a){16}xNN", many, ref, rounds);
    if (ms > worst) worst = ms;

    /* One pattern reached 192 times: a memo searches it once. */
    char *one_pattern = snapshot_of("[\"user\",\"alice\",\"app.git\",\"regex\",\"refs/heads/(a{255}){16}xy\",\"RW\"]");
    mg_grants_t *shared = load(one_pattern);
    double repeated = search_all(shared, ref, rounds, 192u), once = search_all(shared, ref, rounds, 1u);
    (void)printf("shared    192 searches %.2f ms, one %.3f ms\n", repeated / 1e6, once / 1e6);
    mg_grants_free(shared);

    /* One push of one ref at the hook's default limits. */
    const double requests = 1.0 + 10000.0 + 100000.0 + 1.0;
    (void)printf("push      %.0f requests on one ref, at the worst request (%.2f ms): memo per request %.0f s, "
                 "memo kept for the ref %.2f ms\n",
                 requests, worst, requests * worst / 1e3, worst);

    /* Realistic refexes on refs of about 30 bytes. */
    mg_grants_t *grants = load(realistic);
    mg_grants_view_t view;
    mg_grants_view(grants, &view);
    static const char *const k_refs[] = {"refs/heads/feature/login-form", "refs/tags/v1.2.3", "refs/heads/main"};
    for (size_t r = 0u; r < sizeof(k_refs) / sizeof(k_refs[0]); ++r) {
        double all = search_all(grants, k_refs[r], rounds, 1u);
        (void)printf("realistic %zu patterns on %-30s %.1f us for all, %.0f ns per search\n", view.regex_count,
                     k_refs[r], all / 1e3, all / (double)view.regex_count);
    }
    mg_grants_free(grants);

    free(large);
    free(small);
    free(realistic);
    free(large2);
    free(small2);
    free(linear);
    free(hard);
    free(many);
    free(one_pattern);
    return 0;
}
