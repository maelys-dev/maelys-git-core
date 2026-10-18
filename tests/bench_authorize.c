/* Cost of one authorization: request facts, solve, decision; with a receipt,
 * also its explanation when asked for, its serialization and its digest.
 *
 *   bench-maelys-git-authorize MANIFEST [ITERATIONS [MODE [PRINCIPAL REPOSITORY]]]
 *
 * MODE is plain (maelys_git_policy_authorize, the default), never or always
 * (a receipt in that explanation mode, serialized and hashed). Prints the
 * minimum of five series, in nanoseconds per authorization. Not a test:
 * timing depends on the machine and has no place in CTest. */
#include "maelys_git.h"
#include "maelys_git_receipt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef enum { MODE_PLAIN, MODE_NEVER, MODE_ALWAYS } bench_mode_t;

static char g_text[MAELYS_GIT_RECEIPT_MAX_EXPLANATION_TEXT + 1u];

static maelys_git_result_t authorize_once(maelys_git_policy_t *policy, const maelys_git_policy_request_t *request,
                                          bench_mode_t mode, maelys_git_policy_decision_t *decision,
                                          maelys_git_error_t *error) {
    if (mode == MODE_PLAIN) return maelys_git_policy_authorize(policy, request, decision, error);
    maelys_git_receipt_t receipt;
    maelys_git_result_t result = maelys_git_policy_authorize_receipt(
        policy, request, mode == MODE_ALWAYS ? MAELYS_GIT_EXPLAIN_ALWAYS : MAELYS_GIT_EXPLAIN_NEVER,
        mode == MODE_ALWAYS ? g_text : NULL, mode == MODE_ALWAYS ? sizeof(g_text) : 0u, decision,
        &receipt, error);
    if (result != MAELYS_GIT_OK) return result;
    char *bytes = NULL;
    size_t size = 0u;
    char sha256[65];
    result = maelys_git_receipt_serialize(&receipt, &bytes, &size, sha256, error);
    free(bytes);
    return result;
}

static double now_ns(void) {
    struct timespec now;
    (void)clock_gettime(CLOCK_MONOTONIC, &now);
    return (double)now.tv_sec * 1e9 + (double)now.tv_nsec;
}

int main(int argc, char **argv) {
    if (argc < 2 || argc == 5 || argc > 7) {
        (void)fprintf(stderr, "usage: %s MANIFEST [ITERATIONS [plain|never|always [PRINCIPAL REPOSITORY [REF]]]]\n",
                      argv[0]);
        return 2;
    }
    long iterations = argc > 2 ? atol(argv[2]) : 30000;
    const char *mode_name = argc > 3 ? argv[3] : "plain";
    bench_mode_t mode = !strcmp(mode_name, "never") ? MODE_NEVER :
                        !strcmp(mode_name, "always") ? MODE_ALWAYS : MODE_PLAIN;
    if (iterations <= 0 || (mode == MODE_PLAIN && strcmp(mode_name, "plain"))) return 2;
    maelys_git_error_t error;
    maelys_git_policy_t *policy = NULL;
    if (maelys_git_policy_open(argv[1], &policy, &error) != MAELYS_GIT_OK) {
        (void)fprintf(stderr, "open: %s\n", error.message);
        return 1;
    }
    /* A push of three changed paths with its summary: 24 request facts, and
     * the prefixes of its ref with their count, 3 for refs/heads/main. */
    const char *paths[] = {"src/main.c", "docs/README.md", "src/util.c"};
    maelys_git_policy_request_t request = {
        .request_id = "r1", .principal = argc > 5 ? argv[4] : "alice",
        .repository = argc > 5 ? argv[5] : "team/app.git",
        .operation = "push", .ref_name = argc > 6 ? argv[6] : "refs/heads/main", .ref_kind = "branch",
        .update_kind = "update", .paths = paths, .path_count = 3u, .has_summary = 1,
        .changed_count = 3u, .added_count = 1u, .modified_count = 2u,
        .max_new_blob_size = 4096u, .total_new_blob_size = 8192u, .commit_count = 2u};
    maelys_git_policy_decision_t decision;
    for (int i = 0; i < 300; ++i)
        (void)authorize_once(policy, &request, mode, &decision, &error);
    double best = 0.0;
    long completed = 0;
    for (int series = 0; series < 5; ++series) {
        completed = 0;
        double started = now_ns();
        for (long i = 0; i < iterations; ++i)
            if (authorize_once(policy, &request, mode, &decision, &error) == MAELYS_GIT_OK)
                ++completed;
        double each = (now_ns() - started) / (double)iterations;
        if (series == 0 || each < best) best = each;
    }
    (void)printf("%.0f ns per authorization, %s (minimum of 5 x %ld, %ld completed, allowed=%d)\n",
                 best, mode_name, iterations, completed, decision.allowed);
    maelys_git_policy_close(policy);
    return completed == iterations ? 0 : 1;
}
