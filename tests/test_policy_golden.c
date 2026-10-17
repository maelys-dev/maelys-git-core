/* Golden corpus of authorization decisions.
 *
 * The expected file was written by this program built on the baseline commit
 * recorded in its first line, before the migration to the Maelys Datalog
 * consumer API. Every later build must reproduce result code, allowed,
 * explicit_deny, matched_policy and reason for every request.
 *
 *   test-maelys-git-policy-golden            compare with GOLDEN_FILE
 *   test-maelys-git-policy-golden --write F  write the corpus decisions to F
 */
#include "maelys_git.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *key;
    const char *manifest;
} corpus_manifest_t;

static const corpus_manifest_t k_manifests[] = {
    {"example", TEST_MANIFEST_FILE},
    {"gitolite-exact", FIXTURE_DIR "/gitolite-exact/manifest.json"},
    {"filters", FIXTURE_DIR "/filters/manifest.json"},
};

static FILE *g_out;
static FILE *g_expected;
static size_t g_rows;
static size_t g_mismatches;

static void row(const char *key, const char *label, maelys_git_policy_t *policy,
                const maelys_git_policy_request_t *request) {
    maelys_git_policy_decision_t decision;
    maelys_git_error_t error;
    memset(&decision, 0, sizeof(decision));
    maelys_git_result_t result = maelys_git_policy_authorize(policy, request, &decision, &error);
    char matched[32];
    if (decision.matched_policy == SIZE_MAX) (void)snprintf(matched, sizeof(matched), "-");
    else (void)snprintf(matched, sizeof(matched), "%zu", decision.matched_policy);
    char line[1024];
    (void)snprintf(line, sizeof(line), "%s\t%s\t%d\t%d\t%d\t%s\t%s\n", key, label, (int)result,
                   decision.allowed, decision.explicit_deny, matched,
                   decision.reason[0] ? decision.reason : "-");
    ++g_rows;
    if (g_out) {
        (void)fputs(line, g_out);
        return;
    }
    char expected[1024];
    if (!fgets(expected, sizeof(expected), g_expected) || strcmp(expected, line) != 0) {
        ++g_mismatches;
        if (g_mismatches <= 10u)
            (void)fprintf(stderr, "golden mismatch at row %zu\n  expected: %s  actual:   %s",
                          g_rows, expected, line);
    }
}

static const char *or_dash(const char *value) { return value ? value : "-"; }

static void example_corpus(const char *key, maelys_git_policy_t *policy) {
    static const char *const users[] = {"alice", "bob", "mallory"};
    static const char *const operations[] = {"read", "write", "push", "merge", "update-ref", "create"};
    static const char *const refs[] = {NULL, "refs/heads/main", "refs/heads/feature"};
    static const char *const path_values[] = {NULL, "secrets/production.env"};
    static const char *const repositories[] = {"example.git", "new-project.git", "team-project.git"};
    for (size_t p = 0u; p < 3u; ++p)
        for (size_t u = 0u; u < 3u; ++u)
            for (size_t o = 0u; o < 6u; ++o)
                for (size_t r = 0u; r < 3u; ++r)
                    for (size_t f = 0u; f < 2u; ++f) {
                        if (p > 0u && (r > 0u || f > 0u)) continue;
                        const char *paths[] = {path_values[f]};
                        maelys_git_policy_request_t request = {
                            .request_id = "golden", .principal = users[u],
                            .repository = repositories[p], .operation = operations[o],
                            .ref_name = refs[r], .paths = path_values[f] ? paths : NULL,
                            .path_count = path_values[f] ? 1u : 0u};
                        char label[256];
                        (void)snprintf(label, sizeof(label), "%s %s %s %s %s", repositories[p],
                                       users[u], operations[o], or_dash(refs[r]), or_dash(path_values[f]));
                        row(key, label, policy, &request);
                    }
    /* A request whose facts cannot be built is denied with an error. */
    maelys_git_policy_request_t overflow = {
        .request_id = "golden", .principal = "alice", .repository = "example.git",
        .operation = "push", .has_summary = 1, .changed_count = SIZE_MAX};
    row(key, "overflowing summary", policy, &overflow);
    /* Missing required fields are refused before evaluation. */
    maelys_git_policy_request_t invalid = {.request_id = "golden", .principal = "alice",
                                           .repository = "example.git"};
    row(key, "missing operation", policy, &invalid);
}

static void gitolite_corpus(const char *key, maelys_git_policy_t *policy) {
    static const char *const users[] = {"alice", "bob", "carol", "dave", "mallory", "erin", "zed"};
    static const char *const refs[] = {"refs/heads/main", "refs/heads/release", "refs/heads/dev",
                                       "refs/tags/v1", "refs/heads/main-hotfix", "refs/tags/v1.0"};
    static const char *const kinds[] = {"create", "fast_forward", "force", "delete"};
    for (size_t u = 0u; u < 7u; ++u) {
        for (size_t o = 0u; o < 2u; ++o) {
            maelys_git_policy_request_t request = {
                .request_id = "golden", .principal = users[u], .repository = "refs.git",
                .operation = o ? "write" : "read"};
            char label[256];
            (void)snprintf(label, sizeof(label), "%s %s", users[u], request.operation);
            row(key, label, policy, &request);
        }
        for (size_t r = 0u; r < 6u; ++r)
            for (size_t k = 0u; k < 4u; ++k) {
                maelys_git_policy_request_t request = {
                    .request_id = "golden", .principal = users[u], .repository = "refs.git",
                    .operation = "push", .ref_name = refs[r], .update_kind = kinds[k]};
                char label[256];
                (void)snprintf(label, sizeof(label), "%s push %s %s", users[u], refs[r], kinds[k]);
                row(key, label, policy, &request);
            }
        /* The push summary carries counters and no ref. */
        maelys_git_policy_request_t summary = {
            .request_id = "golden", .principal = users[u], .repository = "refs.git",
            .operation = "push", .has_summary = 1, .changed_count = 2u, .added_count = 1u,
            .modified_count = 1u, .commit_count = 1u};
        char label[256];
        (void)snprintf(label, sizeof(label), "%s push summary", users[u]);
        row(key, label, policy, &summary);
    }
}

static void filters_corpus(const char *key, maelys_git_policy_t *policy) {
    static const char *const users[] = {"alice", "bob", "zed"};
    static const char *const refs[] = {NULL, "refs/heads/release/1.0", "refs/heads/release",
                                       "refs/heads/releases", "refs/heads/release-evil",
                                       "refs/heads/release/1.0/frozen", "refs/heads/topic-wip",
                                       "refs/heads/release/next-wip"};
    static const char *const path_values[] = {NULL, "config/secret.env"};
    static const char *const repositories[] = {"team/public-site.git", "team/app.git"};
    for (size_t p = 0u; p < 2u; ++p)
        for (size_t u = 0u; u < 3u; ++u)
            for (size_t o = 0u; o < 2u; ++o)
                for (size_t r = 0u; r < 8u; ++r)
                    for (size_t f = 0u; f < 2u; ++f) {
                        if (o == 1u && r > 0u) continue;
                        const char *paths[] = {path_values[f]};
                        maelys_git_policy_request_t request = {
                            .request_id = "golden", .principal = users[u],
                            .repository = repositories[p], .operation = o ? "read" : "push",
                            .ref_name = refs[r], .paths = path_values[f] ? paths : NULL,
                            .path_count = path_values[f] ? 1u : 0u};
                        char label[256];
                        (void)snprintf(label, sizeof(label), "%s %s %s %s %s", repositories[p],
                                       users[u], request.operation, or_dash(refs[r]),
                                       or_dash(path_values[f]));
                        row(key, label, policy, &request);
                    }
}

int main(int argc, char **argv) {
    const char *write_path = argc == 3 && strcmp(argv[1], "--write") == 0 ? argv[2] : NULL;
    if (argc != 1 && !write_path) {
        (void)fprintf(stderr, "usage: %s [--write FILE]\n", argv[0]);
        return 2;
    }
    char header[256];
    if (write_path) {
        g_out = fopen(write_path, "w");
        if (!g_out) return 1;
        (void)fprintf(g_out, "# baseline %s\n", GOLDEN_BASELINE);
    } else {
        g_expected = fopen(GOLDEN_FILE, "r");
        if (!g_expected || !fgets(header, sizeof(header), g_expected) || header[0] != '#') {
            (void)fprintf(stderr, "cannot read %s\n", GOLDEN_FILE);
            return 1;
        }
    }
    for (size_t m = 0u; m < sizeof(k_manifests) / sizeof(k_manifests[0]); ++m) {
        maelys_git_policy_t *policy = NULL;
        maelys_git_error_t error;
        if (maelys_git_policy_open(k_manifests[m].manifest, &policy, &error) != MAELYS_GIT_OK) {
            (void)fprintf(stderr, "open %s: %s\n", k_manifests[m].manifest, error.message);
            return 1;
        }
        if (m == 0u) example_corpus(k_manifests[m].key, policy);
        else if (m == 1u) gitolite_corpus(k_manifests[m].key, policy);
        else filters_corpus(k_manifests[m].key, policy);
        maelys_git_policy_close(policy);
    }
    if (g_out) {
        if (fclose(g_out) != 0) return 1;
        (void)printf("golden corpus: wrote %zu decisions\n", g_rows);
        return 0;
    }
    char trailing[8];
    int extra = fgets(trailing, sizeof(trailing), g_expected) != NULL;
    (void)fclose(g_expected);
    if (g_mismatches || extra) {
        (void)fprintf(stderr, "golden corpus: %zu of %zu decisions differ%s\n", g_mismatches,
                      g_rows, extra ? "; the expected file has more rows" : "");
        return 1;
    }
    (void)printf("golden corpus: %zu decisions identical to the baseline\n", g_rows);
    return 0;
}
