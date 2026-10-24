/* The Gitolite encoding of this cycle against the one it replaces. Each case
 * has a configuration and the policy the migration of 62778f0 generated from
 * it (old/). For every request of the case's grid:
 *   - the new policy gives the outcome recorded in expected.tsv, which is the
 *     old policy's outcome on the LARGE profile;
 *   - the old policy, on this profile, gives the same outcome or, in SMALL
 *     only, a capacity failure of execution;
 *   - the new policy never fails for capacity;
 *   - the same configuration as grants as data (the audited program and its
 *     snapshot, GIT-C06) gives the recorded outcome too, never failing for
 *     capacity.
 * MG_RECORD_DIFFERENTIAL=FILE writes the old policy's outcomes instead; it is
 * run on the LARGE profile, in a commit that explains every changed line. */
#include "maelys_git.h"
#include "internal.h"
#include "policy/policy_grants.h"
#include "test_support.h"

#include <stdint.h>

#define MAX_ROWS 4096u

static char g_root[256];
static FILE *g_record;
static char *g_expected[MAX_ROWS];
static size_t g_expected_count, g_row;
static size_t g_old_capacity_failures, g_compared;
static maelys_git_policy_t *g_grants_policy;

typedef struct {
    const char *name;
    const char *const *principals;
    const char *const *repositories;     /* operations without a ref */
    const char *const *ref_repositories; /* operations on a ref */
    const char *const *refs;             /* NULL-terminated; "-" is no ref */
} grid_t;

static const char k_deep[] =
    "refs/heads/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/x";
static const char k_long[] =
    "refs/heads/llllllllllllllllllllllllllllllllllllllllllllllllllllllllllll/x";

static const char *const k_mixed_principals[] = {
    "alice", "bob", "carol", "dave", "erin", "guest", "admin", "mallory", "zed", NULL};
static const char *const k_mixed_repositories[] = {
    "app.git", "tools.git", "refs.git", "users/alice/p.git", "users/bob/p.git",
    "shared/erin/x.git", "shared/zed/x.git", "unknown.git", NULL};
static const char *const k_mixed_ref_repositories[] = {
    "refs.git", "app.git", "users/alice/p.git", NULL};
static const char *const k_mixed_refs[] = {
    "-", "refs/heads/main", "refs/heads/main-hotfix", "refs/heads/release",
    "refs/heads/release/1.0", "refs/heads/release/frozen/x", "refs/heads/releases",
    "refs/tags/release/2.0", "refs/heads/topic/x", k_deep, k_long, NULL};

static const char *const k_app[] = {"app.git", NULL};
static const char *const k_members_principals[] = {"m1", "m32", "m64", "m65", "zed", NULL};
static const char *const k_main_refs[] = {"-", "refs/heads/main", NULL};
static const char *const k_refs_principals[] = {"u1", "u33", "u65", "zed", NULL};
static const char *const k_refs_refs[] = {"-", "refs/heads/b1", "refs/heads/b2", "refs/heads/b65", NULL};
static const char *const k_vref_principals[] = {"alice", "zed", NULL};
static const char *const k_r70_principals[] = {"u1", "u70", "u71", NULL};
static const char *const k_bare_principals[] = {"alice", "mallory", "zed", NULL};
static const char *const k_bare_refs[] = {
    "-", "refs/heads/lock1", "refs/heads/lock56", "refs/heads/lock1-x", "refs/heads/main", NULL};
static const char *const k_fallback_principals[] = {"r1", "r120", "w1", "w10", "zed", NULL};
static const char *const k_fallback_refs[] = {
    "-", "refs/heads/team1/x", "refs/heads/team10/y/z", "refs/heads/team1", "refs/heads/main", NULL};

static const grid_t k_grids[] = {
    {"mixed", k_mixed_principals, k_mixed_repositories, k_mixed_ref_repositories, k_mixed_refs},
    {"members-64", k_members_principals, k_app, k_app, k_main_refs},
    {"members-65", k_members_principals, k_app, k_app, k_main_refs},
    {"refs-65", k_refs_principals, k_app, k_app, k_refs_refs},
    {"vref-65", k_vref_principals, k_app, k_app, k_main_refs},
    {"r70", k_r70_principals, k_app, k_app, k_main_refs},
    /* Accepted by 62778f0 at its bounds: 56 bare-literal denies fill its
     * rules; 120 facts and 10 prefixes fill the new facts, and take the
     * rule form. */
    {"bare-56", k_bare_principals, k_app, k_app, k_bare_refs},
    {"fallback", k_fallback_principals, k_app, k_app, k_fallback_refs},
};

static void outcome_of(maelys_git_policy_t *policy, const maelys_git_policy_request_t *request,
                       char *out, size_t size, int *capacity) {
    maelys_git_policy_decision_t decision;
    maelys_git_error_t error;
    maelys_git_result_t result = maelys_git_policy_authorize(policy, request, &decision, &error);
    *capacity = 0;
    if (result != MAELYS_GIT_OK) {
        *capacity = result == MAELYS_GIT_ERR_POLICY &&
                    error.detail.kind == MAELYS_GIT_FAILURE_CAPACITY;
        (void)snprintf(out, size, "error=%s kind=%s", maelys_git_result_name(result),
                       maelys_git_failure_kind_name(error.detail.kind));
        return;
    }
    char matched[32] = "-";
    if (decision.matched_policy != SIZE_MAX)
        (void)snprintf(matched, sizeof(matched), "%zu", decision.matched_policy);
    (void)snprintf(out, size, "allowed=%d explicit=%d matched=%s reason=%s", decision.allowed,
                   decision.explicit_deny, matched, decision.reason);
}

/* One request on both policies, checked against the recorded outcome. */
static int compare(const char *name, maelys_git_policy_t *old_policy, maelys_git_policy_t *new_policy,
                   const maelys_git_policy_request_t *request, const char *label) {
    char old_outcome[512], new_outcome[512], row[1024];
    int old_capacity = 0, new_capacity = 0;
    outcome_of(old_policy, request, old_outcome, sizeof(old_outcome), &old_capacity);
    (void)snprintf(row, sizeof(row), "%s\t%s\t", name, label);
    if (g_record) {
        (void)fprintf(g_record, "%s%s\n", row, old_outcome);
        return 1;
    }
    CHECK(g_row < g_expected_count);
    const char *expected = g_expected[g_row++];
    size_t prefix = strlen(row);
    if (strncmp(expected, row, prefix) != 0) {
        (void)fprintf(stderr, "grid out of step: expected %s, built %s\n", expected, row);
        return 0;
    }
    expected += prefix;
    outcome_of(new_policy, request, new_outcome, sizeof(new_outcome), &new_capacity);
    if (new_capacity || strcmp(new_outcome, expected) != 0) {
        (void)fprintf(stderr, "%s%s: new %s, expected %s\n", row, "", new_outcome, expected);
        return 0;
    }
    outcome_of(g_grants_policy, request, new_outcome, sizeof(new_outcome), &new_capacity);
    if (new_capacity || strcmp(new_outcome, expected) != 0) {
        (void)fprintf(stderr, "%s%s: grants %s, expected %s\n", row, "", new_outcome, expected);
        return 0;
    }
    if (strcmp(old_outcome, expected) != 0) {
        if (!old_capacity) {
            (void)fprintf(stderr, "%s: old %s, expected %s\n", row, old_outcome, expected);
            return 0;
        }
        ++g_old_capacity_failures;
    }
    ++g_compared;
    return 1;
}

static int run_grid(const grid_t *grid, maelys_git_policy_t *old_policy, maelys_git_policy_t *new_policy) {
    static const char *const plain_operations[] = {"read", "write", "create"};
    static const char *const ref_operations[] = {"merge", "update-ref"};
    static const char *const kinds[] = {"create", "fast_forward", "force", "delete"};
    char label[1024];
    for (const char *const *user = grid->principals; *user; ++user) {
        for (const char *const *repository = grid->repositories; *repository; ++repository) {
            for (size_t o = 0u; o < 3u; ++o) {
                maelys_git_policy_request_t request = {
                    .request_id = "d", .principal = *user, .repository = *repository,
                    .operation = plain_operations[o]};
                (void)snprintf(label, sizeof(label), "%s %s %s", *user, *repository, plain_operations[o]);
                CHECK(compare(grid->name, old_policy, new_policy, &request, label));
            }
            /* The summary of a push: six changes, three added files. */
            maelys_git_policy_request_t summary = {
                .request_id = "d", .principal = *user, .repository = *repository,
                .operation = "push", .has_summary = 1, .changed_count = 6u, .added_count = 3u,
                .modified_count = 3u, .commit_count = 1u};
            (void)snprintf(label, sizeof(label), "%s %s push-summary", *user, *repository);
            CHECK(compare(grid->name, old_policy, new_policy, &summary, label));
        }
        for (const char *const *repository = grid->ref_repositories; *repository; ++repository) {
            for (const char *const *ref = grid->refs; *ref; ++ref) {
                const char *ref_name = strcmp(*ref, "-") ? *ref : NULL;
                for (size_t o = 0u; o < 2u; ++o) {
                    maelys_git_policy_request_t request = {
                        .request_id = "d", .principal = *user, .repository = *repository,
                        .operation = ref_operations[o], .ref_name = ref_name};
                    (void)snprintf(label, sizeof(label), "%s %s %s %s", *user, *repository,
                                   ref_operations[o], *ref);
                    CHECK(compare(grid->name, old_policy, new_policy, &request, label));
                }
                for (size_t k = 0u; k < 4u; ++k) {
                    maelys_git_policy_request_t request = {
                        .request_id = "d", .principal = *user, .repository = *repository,
                        .operation = "push", .ref_name = ref_name, .update_kind = kinds[k],
                        .ref_kind = ref_name ? "branch" : NULL};
                    (void)snprintf(label, sizeof(label), "%s %s push %s %s", *user, *repository,
                                   *ref, kinds[k]);
                    CHECK(compare(grid->name, old_policy, new_policy, &request, label));
                }
            }
            /* A changed path, and a new binary file, on the repository. */
            static const char *const paths[] = {"Makefile", "file1", "file65", "img.bin"};
            for (size_t p = 0u; p < 4u; ++p) {
                const char *path[1] = {paths[p]};
                maelys_git_policy_request_t request = {
                    .request_id = "d", .principal = *user, .repository = *repository,
                    .operation = "push", .ref_name = "refs/heads/topic/x", .update_kind = "create",
                    .paths = path, .path_count = 1u, .has_change_details = 1,
                    .change_kind = "added", .change_binary = p == 3u,
                    .change_blob_size = p == 3u ? 2048u : 10u};
                (void)snprintf(label, sizeof(label), "%s %s push-path %s", *user, *repository, paths[p]);
                CHECK(compare(grid->name, old_policy, new_policy, &request, label));
            }
        }
    }
    return 1;
}

static int run_case(const grid_t *grid) {
    char old_manifest[512], input[512], output[512], new_manifest[600], grants_output[600],
        grants_manifest[700], snapshot[700];
    (void)snprintf(old_manifest, sizeof(old_manifest), "%s/%s/old/manifest.json", DIFFERENTIAL_DIR,
                   grid->name);
    (void)snprintf(input, sizeof(input), "%s/%s/gitolite.conf", DIFFERENTIAL_DIR, grid->name);
    (void)snprintf(output, sizeof(output), "%s/%s", g_root, grid->name);
    maelys_git_error_t error;
    maelys_git_policy_t *old_policy = NULL, *new_policy = NULL;
    CHECK(maelys_git_policy_open(old_manifest, &old_policy, &error) == MAELYS_GIT_OK);
    maelys_git_gitolite_migration_result_t migration;
    CHECK(mg_migrate_gitolite_compiled(input, output, 1, &migration, &error) == MAELYS_GIT_OK);
    CHECK(migration.unsupported_count == 0u);
    maelys_git_gitolite_migration_result_clear(&migration);
    (void)snprintf(new_manifest, sizeof(new_manifest), "%s/manifest.json", output);
    CHECK(maelys_git_policy_open(new_manifest, &new_policy, &error) == MAELYS_GIT_OK);
    (void)snprintf(grants_output, sizeof(grants_output), "%s-grants", output);
    CHECK(mg_migrate_gitolite_grants(input, grants_output, 1, &migration, &error) == MAELYS_GIT_OK);
    CHECK(migration.unsupported_count == 0u);
    maelys_git_gitolite_migration_result_clear(&migration);
    (void)snprintf(grants_manifest, sizeof(grants_manifest), "%s/manifest.json", grants_output);
    (void)snprintf(snapshot, sizeof(snapshot), "%s/grants.json", grants_output);
    CHECK(mg_policy_open_grants(grants_manifest, snapshot, &g_grants_policy, &error) == MAELYS_GIT_OK);
    int ok = run_grid(grid, old_policy, new_policy);
    maelys_git_policy_close(old_policy);
    maelys_git_policy_close(new_policy);
    maelys_git_policy_close(g_grants_policy);
    g_grants_policy = NULL;
    return ok;
}

static int load_expected(void) {
    FILE *file = fopen(DIFFERENTIAL_DIR "/expected.tsv", "r");
    CHECK(file != NULL);
    char line[2048];
    while (fgets(line, sizeof(line), file)) {
        size_t length = strlen(line);
        if (length && line[length - 1u] == '\n') line[--length] = '\0';
        if (line[0] == '#' || !length) continue;
        CHECK(g_expected_count < MAX_ROWS);
        g_expected[g_expected_count] = strdup(line);
        CHECK(g_expected[g_expected_count] != NULL);
        ++g_expected_count;
    }
    (void)fclose(file);
    return g_expected_count > 0u;
}

int main(void) {
    char template[] = "/tmp/maelys_git_differential_XXXXXX";
    char *root = mkdtemp(template);
    if (!root) return 1;
    (void)snprintf(g_root, sizeof(g_root), "%s", root);
    const char *record = getenv("MG_RECORD_DIFFERENTIAL");
    int ok = 1;
    if (record && *record) {
        g_record = fopen(record, "w");
        ok = g_record != NULL &&
             fprintf(g_record, "# outcomes of the Gitolite policies migrated by 62778f0, LARGE profile\n") > 0;
    } else {
        ok = load_expected();
    }
    for (size_t i = 0u; ok && i < sizeof(k_grids) / sizeof(k_grids[0]); ++i)
        ok = run_case(&k_grids[i]);
    if (ok && !g_record && g_row != g_expected_count) {
        (void)fprintf(stderr, "%zu recorded rows, %zu compared\n", g_expected_count, g_row);
        ok = 0;
    }
    if (g_record && fclose(g_record) != 0) ok = 0;
    for (size_t i = 0u; i < g_expected_count; ++i) free(g_expected[i]);
    if (!test_remove_tree(g_root)) ok = 0;
    if (ok && !g_record)
        (void)printf("Gitolite encodings, compiled and as grants: %zu requests identical; %zu where the old "
                     "policy failed for capacity on this profile: ok\n",
                     g_compared, g_old_capacity_failures);
    return ok ? 0 : 1;
}
