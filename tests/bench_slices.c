/* The measurements of GIT-C06 on grants as data, one per subcommand. Not a
 * test: timings depend on the machine and have no place in CTest.
 *
 *   bench-maelys-git-slices sizes MANIFEST GRANTS [MAX_REQUESTS]
 *     The facts of the slice per request, as receipts count them
 *     (grants.facts), over the user and repository pairs of the snapshot, a
 *     stride apart beyond MAX_REQUESTS (default 200000): maximum, p99,
 *     median, and the most loaded predicate of one request.
 *   bench-maelys-git-slices hot CONFIGURATION ITERATIONS PRINCIPAL REPOSITORY
 *     One authorization, hot, of the compiled encoding against the program
 *     with its slice, both migrated from CONFIGURATION: ten alternating pairs
 *     of series, minimum and median of each in nanoseconds.
 *   bench-maelys-git-slices extract GRANTS ITERATIONS [MAX_REQUESTS]
 *     The indexed extractor against the reference one, on the same requests
 *     (at most MAX_REQUESTS pairs, default 1000, a stride apart), in
 *     nanoseconds per slice. The reference scans the whole snapshot and
 *     closes groups by repeated passes: keep few requests on deep groups.
 *   bench-maelys-git-slices reread GRANTS ITERATIONS
 *     A stream's reading before each command, the file unchanged: trusted
 *     read and SHA-256, in microseconds; and one full load for comparison.
 *   bench-maelys-git-slices window MANIFEST GRANTS ITERATIONS PRINCIPAL REPOSITORY
 *     The batch of one request solved by session_solve against a
 *     group_window of one group, which recomputes on each push: time per
 *     solve and the storage the window reserves.
 *   bench-maelys-git-slices store DIRECTORY GRANTS...
 *     The agent's store: the bytes and the disk blocks each distinct
 *     snapshot adds under DIRECTORY/grants-store. */
#include "agent/agent_internal.h"
#include "policy/grants.h"
#include "policy/policy_grants.h"
#include "slice_reference.h"

#include <maelys/datalog_window.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

static double now_ns(void) {
    struct timespec now;
    (void)clock_gettime(CLOCK_MONOTONIC, &now);
    return (double)now.tv_sec * 1e9 + (double)now.tv_nsec;
}

static int compare_double(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

static int compare_size(const void *a, const void *b) {
    size_t x = *(const size_t *)a, y = *(const size_t *)b;
    return x < y ? -1 : x > y;
}

static double median(double *values, size_t count) {
    qsort(values, count, sizeof(*values), compare_double);
    return values[count / 2u];
}

/* A push of three changed paths with its summary, as bench-maelys-git-authorize
 * measures it. */
static maelys_git_policy_request_t push_request(const char *principal, const char *repository) {
    static const char *const paths[] = {"src/main.c", "docs/README.md", "src/util.c"};
    return (maelys_git_policy_request_t){
        .request_id = "r1", .principal = principal, .repository = repository, .operation = "push",
        .ref_name = "refs/heads/main", .ref_kind = "branch", .update_kind = "update", .paths = paths,
        .path_count = 3u, .has_summary = 1, .changed_count = 3u, .added_count = 1u, .modified_count = 2u,
        .max_new_blob_size = 4096u, .total_new_blob_size = 8192u, .commit_count = 2u};
}

/* ---- the names of a snapshot ----------------------------------------------------- */

typedef struct {
    const char **names;
    size_t count, capacity;
} names_t;

static int add_name(names_t *set, const char *name) {
    for (size_t i = 0u; i < set->count; ++i)
        if (!strcmp(set->names[i], name)) return 1;
    if (set->count == set->capacity) {
        size_t next = set->capacity ? set->capacity * 2u : 256u;
        const char **grown = realloc(set->names, next * sizeof(*grown));
        if (!grown) return 0;
        set->names = grown;
        set->capacity = next;
    }
    set->names[set->count++] = name;
    return 1;
}

/* The users the snapshot names, and the repositories it grants rights on. */
static int snapshot_names(const mg_grants_t *grants, names_t *users, names_t *repositories) {
    mg_grants_view_t view;
    mg_grants_view(grants, &view);
    memset(users, 0, sizeof(*users));
    memset(repositories, 0, sizeof(*repositories));
    int ok = 1;
    for (size_t i = 0u; ok && i < view.member_count; ++i) ok = add_name(users, view.members[i].user);
    for (size_t i = 0u; ok && i < view.access_count; ++i) {
        if (view.access[i].kind == MG_SUBJECT_USER) ok = add_name(users, view.access[i].subject);
        if (ok) ok = add_name(repositories, view.access[i].repository);
    }
    for (size_t i = 0u; ok && i < view.ref_count; ++i) {
        if (view.refs[i].kind == MG_SUBJECT_USER) ok = add_name(users, view.refs[i].subject);
        if (ok) ok = add_name(repositories, view.refs[i].repository);
    }
    for (size_t i = 0u; ok && i < view.vref_name_count; ++i)
        ok = add_name(repositories, view.vref_names[i].repository);
    for (size_t i = 0u; ok && i < view.vref_limit_count; ++i)
        ok = add_name(repositories, view.vref_limits[i].repository);
    return ok && users->count > 0u && repositories->count > 0u;
}

static mg_grants_t *load(const char *path) {
    mg_grants_t *grants = NULL;
    maelys_git_error_t error;
    if (mg_grants_load(path, &grants, &error) != MAELYS_GIT_OK) {
        (void)fprintf(stderr, "%s: %s\n", path, error.message);
        return NULL;
    }
    return grants;
}

/* ---- sizes ----------------------------------------------------------------------- */

static size_t g_predicate_counts[MG_SLICE_PREDICATE_COUNT];

static int count_fact(const mg_slice_fact_t *fact, void *context) {
    (void)context;
    ++g_predicate_counts[fact->predicate];
    return 1;
}

static int sizes(const char *manifest, const char *grants_path, size_t max_requests) {
    mg_grants_t *grants = load(grants_path);
    names_t users, repositories;
    if (!grants || !snapshot_names(grants, &users, &repositories)) return 1;
    maelys_git_policy_t *policy = NULL;
    maelys_git_error_t error;
    if (maelys_git_policy_open_grants(manifest, grants_path, &policy, &error) != MAELYS_GIT_OK) {
        (void)fprintf(stderr, "open: %s\n", error.message);
        return 1;
    }
    mg_policy_set_slice_filter(policy, count_fact, NULL);
    size_t pairs = users.count * repositories.count;
    size_t stride = pairs > max_requests ? (pairs + max_requests - 1u) / max_requests : 1u;
    size_t *facts = malloc((pairs / stride + 1u) * sizeof(*facts));
    size_t measured = 0u, refused = 0u, loaded_count = 0u;
    mg_slice_predicate_t loaded = MG_SLICE_MEMBER;
    for (size_t pair = 0u; facts && pair < pairs; pair += stride) {
        maelys_git_policy_request_t request = {
            .request_id = "size", .principal = users.names[pair / repositories.count],
            .repository = repositories.names[pair % repositories.count], .operation = "write",
            .ref_name = "refs/heads/main", .ref_kind = "branch", .update_kind = "update"};
        memset(g_predicate_counts, 0, sizeof(g_predicate_counts));
        maelys_git_policy_decision_t decision;
        maelys_git_receipt_t receipt;
        if (maelys_git_policy_authorize_receipt(policy, &request, MAELYS_GIT_EXPLAIN_NEVER, NULL, 0u, &decision,
                                                &receipt, &error) != MAELYS_GIT_OK ||
            !receipt.grants.present) {
            ++refused;
            continue;
        }
        facts[measured++] = receipt.grants.facts;
        for (size_t p = 0u; p < MG_SLICE_PREDICATE_COUNT; ++p)
            if (g_predicate_counts[p] > loaded_count) {
                loaded_count = g_predicate_counts[p];
                loaded = (mg_slice_predicate_t)p;
            }
    }
    if (!facts || measured == 0u) return 1;
    qsort(facts, measured, sizeof(*facts), compare_size);
    (void)printf("%zu users, %zu repositories: %zu requests (1 in %zu), %zu refused\n", users.count,
                 repositories.count, measured, stride, refused);
    (void)printf("grants.facts per request: max %zu, p99 %zu, median %zu\n", facts[measured - 1u],
                 facts[(measured * 99u) / 100u], facts[measured / 2u]);
    (void)printf("most loaded predicate of one request: %s, %zu facts\n", mg_slice_predicate_name(loaded),
                 loaded_count);
    free(facts);
    free(users.names);
    free(repositories.names);
    maelys_git_policy_close(policy);
    mg_grants_free(grants);
    return refused ? 1 : 0;
}

/* ---- hot ------------------------------------------------------------------------- */

static int migrate(const char *configuration, const char *directory, int compiled) {
    maelys_git_gitolite_migration_result_t migration;
    maelys_git_error_t error;
    maelys_git_result_t result = compiled ? mg_migrate_gitolite_compiled(configuration, directory, 1, &migration, &error)
                                          : mg_migrate_gitolite_grants(configuration, directory, 1, &migration, &error);
    maelys_git_gitolite_migration_result_clear(&migration);
    if (result != MAELYS_GIT_OK) (void)fprintf(stderr, "migrate %s: %s\n", directory, error.message);
    return result == MAELYS_GIT_OK;
}

static double series(maelys_git_policy_t *policy, const maelys_git_policy_request_t *request, long iterations,
                     int *allowed) {
    maelys_git_policy_decision_t decision;
    maelys_git_error_t error;
    double started = now_ns();
    for (long i = 0; i < iterations; ++i)
        if (maelys_git_policy_authorize(policy, request, &decision, &error) != MAELYS_GIT_OK) return -1.0;
    *allowed = decision.allowed;
    return (now_ns() - started) / (double)iterations;
}

static int hot(const char *configuration, long iterations, const char *principal, const char *repository) {
    char root[] = "/tmp/maelys_git_bench_hot_XXXXXX", compiled[64], data[64], manifest[96], snapshot[96];
    if (!mkdtemp(root)) return 1;
    (void)snprintf(compiled, sizeof(compiled), "%s/compiled", root);
    (void)snprintf(data, sizeof(data), "%s/grants", root);
    maelys_git_policy_t *a = NULL, *b = NULL;
    maelys_git_error_t error;
    int ok = migrate(configuration, compiled, 1) && migrate(configuration, data, 0);
    (void)snprintf(manifest, sizeof(manifest), "%s/manifest.json", compiled);
    ok = ok && maelys_git_policy_open(manifest, &a, &error) == MAELYS_GIT_OK;
    (void)snprintf(manifest, sizeof(manifest), "%s/manifest.json", data);
    (void)snprintf(snapshot, sizeof(snapshot), "%s/grants.json", data);
    ok = ok && maelys_git_policy_open_grants(manifest, snapshot, &b, &error) == MAELYS_GIT_OK;
    maelys_git_policy_request_t request = push_request(principal, repository);
    double times[2][10];
    int allowed[2] = {0, 0};
    for (int warm = 0; ok && warm < 2; ++warm)
        ok = series(a, &request, 300, &allowed[0]) >= 0.0 && series(b, &request, 300, &allowed[1]) >= 0.0;
    for (int pair = 0; ok && pair < 10; ++pair) {
        /* Alternated, so that a drift of the machine weighs on both. */
        times[0][pair] = series(a, &request, iterations, &allowed[0]);
        times[1][pair] = series(b, &request, iterations, &allowed[1]);
        ok = times[0][pair] >= 0.0 && times[1][pair] >= 0.0;
    }
    size_t context = 0u, slice = 0u;
    mg_policy_slice_counts(b, &context, &slice);
    if (ok) {
        double minimum[2] = {times[0][0], times[1][0]};
        for (int e = 0; e < 2; ++e)
            for (int pair = 1; pair < 10; ++pair)
                if (times[e][pair] < minimum[e]) minimum[e] = times[e][pair];
        double compiled_median = median(times[0], 10u), slice_median = median(times[1], 10u);
        (void)printf("compiled encoding: min %.0f ns, median %.0f ns, allowed=%d\n", minimum[0], compiled_median,
                     allowed[0]);
        (void)printf("program and slice: min %.0f ns, median %.0f ns, allowed=%d (%zu context facts, %zu slice "
                     "facts)\n", minimum[1], slice_median, allowed[1], context, slice);
        (void)printf("ratio of medians, slice / compiled: %.2f\n", slice_median / compiled_median);
    } else {
        (void)fprintf(stderr, "hot: %s\n", error.message);
    }
    maelys_git_policy_close(a);
    maelys_git_policy_close(b);
    (void)test_remove_tree(root);
    return ok && allowed[0] == allowed[1] ? 0 : 1;
}

/* ---- extract --------------------------------------------------------------------- */

static int extract(const char *grants_path, long iterations, size_t max_requests) {
    mg_grants_t *grants = load(grants_path);
    names_t users, repositories;
    if (!grants || !snapshot_names(grants, &users, &repositories)) return 1;
    size_t pairs = users.count * repositories.count;
    size_t stride = pairs > max_requests ? (pairs + max_requests - 1u) / max_requests : 1u;
    size_t count = 0u;
    mg_slice_request_t *requests = calloc(pairs / stride + 1u, sizeof(*requests));
    for (size_t pair = 0u; requests && pair < pairs; pair += stride)
        requests[count++] = (mg_slice_request_t){.user = users.names[pair / repositories.count],
                                                 .repository = repositories.names[pair % repositories.count],
                                                 .ref = "refs/heads/main"};
    double indexed[64], reference[64];
    if (iterations > 64) iterations = 64;
    size_t facts = 0u, differ = 0u;
    int ok = requests != NULL;
    for (long round = 0; ok && round < iterations; ++round) {
        maelys_git_error_t error;
        double started = now_ns();
        for (size_t i = 0u; ok && i < count; ++i) {
            mg_slice_t slice;
            ok = mg_slice_extract(grants, &requests[i], &slice, &error) == MAELYS_GIT_OK;
            if (round == 0) facts += slice.count;
            mg_slice_clear(&slice);
        }
        indexed[round] = (now_ns() - started) / (double)count;
        started = now_ns();
        for (size_t i = 0u; ok && i < count; ++i) {
            mg_slice_t slice;
            ok = reference_slice(grants, &requests[i], &slice);
            mg_slice_clear(&slice);
        }
        reference[round] = (now_ns() - started) / (double)count;
    }
    /* Both give the same slices; the tests prove it, this checks the sample. */
    for (size_t i = 0u; ok && i < count; ++i) {
        mg_slice_t a, b;
        maelys_git_error_t error;
        ok = mg_slice_extract(grants, &requests[i], &a, &error) == MAELYS_GIT_OK && reference_slice(grants, &requests[i], &b);
        if (ok && a.count != b.count) ++differ;
        for (size_t f = 0u; ok && a.count == b.count && f < a.count; ++f)
            if (mg_slice_fact_compare(&a.facts[f], &b.facts[f])) { ++differ; break; }
        mg_slice_clear(&a);
        mg_slice_clear(&b);
    }
    if (ok)
        (void)printf("%zu requests, %zu facts in all, %zu differ: indexed %.0f ns, reference %.0f ns per slice "
                     "(medians of %ld rounds)\n", count, facts, differ, median(indexed, (size_t)iterations),
                     median(reference, (size_t)iterations), iterations);
    free(requests);
    free(users.names);
    free(repositories.names);
    mg_grants_free(grants);
    return ok && differ == 0u ? 0 : 1;
}

/* ---- reread ---------------------------------------------------------------------- */

static int reread(const char *grants_path, long iterations) {
    struct stat status;
    if (stat(grants_path, &status) != 0) return 1;
    double started = now_ns();
    mg_grants_t *grants = load(grants_path);
    double loaded = now_ns() - started;
    if (!grants) return 1;
    double *times = malloc((size_t)iterations * sizeof(*times));
    int ok = times != NULL;
    for (long i = 0; ok && i < iterations; ++i) {
        mg_grants_t *fresh = NULL;
        maelys_git_error_t error;
        started = now_ns();
        ok = mg_grants_reload(grants_path, grants, &fresh, &error) == MAELYS_GIT_OK && fresh == NULL;
        times[i] = (now_ns() - started) / 1000.0;
    }
    if (ok) {
        double minimum = times[0];
        for (long i = 1; i < iterations; ++i)
            if (times[i] < minimum) minimum = times[i];
        (void)printf("%lld bytes: reading again, unchanged, min %.1f us, median %.1f us (%ld readings); "
                     "first load %.1f us\n", (long long)status.st_size, minimum, median(times, (size_t)iterations),
                     iterations, loaded / 1000.0);
    }
    free(times);
    mg_grants_free(grants);
    return ok ? 0 : 1;
}

/* ---- window ---------------------------------------------------------------------- */

static int window(const char *manifest, const char *grants_path, long iterations, const char *principal,
                  const char *repository) {
    maelys_git_policy_t *policy = NULL;
    maelys_git_error_t error;
    if (maelys_git_policy_open_grants(manifest, grants_path, &policy, &error) != MAELYS_GIT_OK) {
        (void)fprintf(stderr, "open: %s\n", error.message);
        return 1;
    }
    maelys_git_policy_request_t request = push_request(principal, repository);
    maelys_git_policy_decision_t decision;
    if (maelys_git_policy_authorize(policy, &request, &decision, &error) != MAELYS_GIT_OK) {
        (void)fprintf(stderr, "authorize: %s\n", error.message);
        return 1;
    }
    size_t count = 0u;
    const maelys_datalog_fact_t *batch = mg_policy_entry_batch(policy, 0u, &count);
    size_t text = 0u;
    for (size_t i = 0u; i < count; ++i) {
        text += strlen(batch[i].predicate) + 1u;
        for (size_t t = 0u; t < batch[i].arity; ++t)
            if (batch[i].terms[t].kind == MAELYS_DATALOG_VALUE_SYMBOL) text += strlen(batch[i].terms[t].as.symbol) + 1u;
    }
    /* The same program, loaded again: three sessions of equal fingerprints. */
    maelys_datalog_diagnostic_t diagnostic = MAELYS_DATALOG_DIAGNOSTIC_INIT;
    maelys_datalog_policy_t *loaded = NULL;
    maelys_datalog_session_t *solo = NULL, *a = NULL, *b = NULL;
    int ok = maelys_datalog_policy_load_manifest(manifest, MAELYS_DATALOG_PUBLIC_ALLOW_UNDECLARED_POLICY_ATOMS,
                                                 &loaded, &diagnostic) == MAELYS_DATALOG_STATUS_OK &&
             maelys_datalog_session_create(loaded, 0u, &solo) == MAELYS_DATALOG_STATUS_OK &&
             maelys_datalog_session_create(loaded, 0u, &a) == MAELYS_DATALOG_STATUS_OK &&
             maelys_datalog_session_create(loaded, 0u, &b) == MAELYS_DATALOG_STATUS_OK;
    double *solved = malloc((size_t)iterations * sizeof(*solved));
    double *pushed = malloc((size_t)iterations * sizeof(*pushed));
    ok = ok && solved && pushed;
    for (long i = 0; ok && i < iterations; ++i) {
        maelys_datalog_result_t *result = NULL;
        double started = now_ns();
        ok = maelys_datalog_session_solve(solo, batch, count, &result, &diagnostic) == MAELYS_DATALOG_STATUS_OK;
        solved[i] = now_ns() - started;
        (void)maelys_datalog_result_free(result);
    }
    maelys_datalog_group_window_capacities_t capacities = {
        .groups = 1u, .contributions = count, .unique_facts = count, .text_bytes = text};
    size_t bytes = 0u, alignment = 0u;
    void *storage = NULL;
    maelys_datalog_group_window_t *group = NULL;
    ok = ok && maelys_datalog_group_window_storage_requirements(&capacities, &bytes, &alignment) ==
                   MAELYS_DATALOG_STATUS_OK;
    if (ok) {
        size_t rounded = (bytes + alignment - 1u) / alignment * alignment;
        storage = aligned_alloc(alignment, rounded);
        ok = storage && maelys_datalog_group_window_init(storage, rounded, &capacities, 0u, a, b, &group,
                                                         &diagnostic) == MAELYS_DATALOG_STATUS_OK;
    }
    /* One group: each push expires the previous request and recomputes. */
    for (long i = 0; ok && i < iterations; ++i) {
        double started = now_ns();
        ok = maelys_datalog_group_window_push(group, batch, count, NULL, &diagnostic) == MAELYS_DATALOG_STATUS_OK;
        pushed[i] = now_ns() - started;
    }
    if (ok)
        (void)printf("%zu facts (%zu bytes of text), decision allowed=%d: session_solve median %.0f ns, "
                     "group_window N=1 push median %.0f ns; the window reserves %zu bytes beside its two "
                     "sessions\n", count, text, decision.allowed, median(solved, (size_t)iterations),
                     median(pushed, (size_t)iterations), bytes);
    else
        (void)fprintf(stderr, "window: %s\n", diagnostic.message);
    if (group) (void)maelys_datalog_group_window_free(group);
    free(storage);
    free(solved);
    free(pushed);
    (void)maelys_datalog_session_free(solo);
    (void)maelys_datalog_session_free(a);
    (void)maelys_datalog_session_free(b);
    (void)maelys_datalog_policy_free(loaded);
    maelys_git_policy_close(policy);
    return ok ? 0 : 1;
}

/* ---- store ----------------------------------------------------------------------- */

static int store(const char *directory, int count, char **files) {
    char database[4096];
    (void)snprintf(database, sizeof(database), "%s/agent.sqlite3", directory);
    long long bytes = 0, blocks = 0;
    int distinct = 0;
    for (int i = 0; i < count; ++i) {
        mg_grants_archive_t archive;
        maelys_git_error_t error;
        struct stat status;
        if (mg_grants_store_archive(files[i], database, &archive, &error) != MAELYS_GIT_OK ||
            stat(archive.path, &status) != 0) {
            (void)fprintf(stderr, "%s: %s\n", files[i], error.message);
            return 1;
        }
        mg_grants_archive_release(&archive);
        /* A snapshot already kept adds nothing: it is read back. */
        int seen = 0;
        for (int j = 0; j < i && !seen; ++j) seen = !strcmp(files[j], files[i]);
        (void)printf("%s: %lld bytes, %lld bytes on disk%s\n", archive.sha256, (long long)status.st_size,
                     (long long)status.st_blocks * 512, seen ? ", already kept" : "");
        if (seen) continue;
        ++distinct;
        bytes += status.st_size;
        blocks += (long long)status.st_blocks * 512;
    }
    (void)printf("%d distinct snapshots: %lld bytes, %lld bytes on disk\n", distinct, bytes, blocks);
    return 0;
}

int main(int argc, char **argv) {
    const char *command = argc > 1 ? argv[1] : "";
    if (!strcmp(command, "sizes") && (argc == 4 || argc == 5))
        return sizes(argv[2], argv[3], argc == 5 ? (size_t)strtoull(argv[4], NULL, 10) : 200000u);
    if (!strcmp(command, "hot") && argc == 6 && atol(argv[3]) > 0)
        return hot(argv[2], atol(argv[3]), argv[4], argv[5]);
    if (!strcmp(command, "extract") && (argc == 4 || argc == 5) && atol(argv[3]) > 0 &&
        (argc == 4 || atol(argv[4]) > 0))
        return extract(argv[2], atol(argv[3]), argc == 5 ? (size_t)atol(argv[4]) : 1000u);
    if (!strcmp(command, "reread") && argc == 4 && atol(argv[3]) > 0) return reread(argv[2], atol(argv[3]));
    if (!strcmp(command, "window") && argc == 7 && atol(argv[4]) > 0)
        return window(argv[2], argv[3], atol(argv[4]), argv[5], argv[6]);
    if (!strcmp(command, "store") && argc >= 4) return store(argv[2], argc - 3, argv + 3);
    (void)fprintf(stderr, "usage: %s sizes|hot|extract|reread|window|store ... (see the source)\n", argv[0]);
    return 2;
}
