/* Cost of one authorization: request facts, solve, decision.
 *
 *   bench-maelys-git-authorize MANIFEST [ITERATIONS]
 *
 * Prints the minimum of five series, in nanoseconds per authorization. Not a
 * test: timing depends on the machine and has no place in CTest. */
#include "maelys_git.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static double now_ns(void) {
    struct timespec now;
    (void)clock_gettime(CLOCK_MONOTONIC, &now);
    return (double)now.tv_sec * 1e9 + (double)now.tv_nsec;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        (void)fprintf(stderr, "usage: %s MANIFEST [ITERATIONS]\n", argv[0]);
        return 2;
    }
    long iterations = argc > 2 ? atol(argv[2]) : 30000;
    if (iterations <= 0) return 2;
    maelys_git_error_t error;
    maelys_git_policy_t *policy = NULL;
    if (maelys_git_policy_open(argv[1], &policy, &error) != MAELYS_GIT_OK) {
        (void)fprintf(stderr, "open: %s\n", error.message);
        return 1;
    }
    /* A push of three changed paths with its summary: 24 request facts. */
    const char *paths[] = {"src/main.c", "docs/README.md", "src/util.c"};
    maelys_git_policy_request_t request = {
        .request_id = "r1", .principal = "alice", .repository = "team/app.git",
        .operation = "push", .ref_name = "refs/heads/main", .ref_kind = "branch",
        .update_kind = "update", .paths = paths, .path_count = 3u, .has_summary = 1,
        .changed_count = 3u, .added_count = 1u, .modified_count = 2u,
        .max_new_blob_size = 4096u, .total_new_blob_size = 8192u, .commit_count = 2u};
    maelys_git_policy_decision_t decision;
    for (int i = 0; i < 300; ++i)
        (void)maelys_git_policy_authorize(policy, &request, &decision, &error);
    double best = 0.0;
    long completed = 0;
    for (int series = 0; series < 5; ++series) {
        completed = 0;
        double started = now_ns();
        for (long i = 0; i < iterations; ++i)
            if (maelys_git_policy_authorize(policy, &request, &decision, &error) == MAELYS_GIT_OK)
                ++completed;
        double each = (now_ns() - started) / (double)iterations;
        if (series == 0 || each < best) best = each;
    }
    (void)printf("%.0f ns per authorization (minimum of 5 x %ld, %ld completed, allowed=%d)\n",
                 best, iterations, completed, decision.allowed);
    maelys_git_policy_close(policy);
    return completed == iterations ? 0 : 1;
}
