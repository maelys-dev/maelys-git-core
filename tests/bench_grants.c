/* Cost of loading a grants snapshot: the trusted read, the parse, the
 * validation and the index. Prints the minimum over ITERATIONS loads, the
 * counts and the bytes of the index. Not a test.
 *
 *   bench-maelys-git-grants FILE [ITERATIONS] */
#include "policy/grants.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        (void)fprintf(stderr, "usage: %s FILE [ITERATIONS]\n", argv[0]);
        return 2;
    }
    long iterations = argc > 2 ? atol(argv[2]) : 10;
    double best = 0.0;
    mg_grants_view_t view = {0};
    for (long i = 0; i < iterations; ++i) {
        struct timespec start, end;
        mg_grants_t *grants = NULL;
        maelys_git_error_t error = {0};
        (void)clock_gettime(CLOCK_MONOTONIC, &start);
        if (mg_grants_load(argv[1], &grants, &error) != MAELYS_GIT_OK) {
            (void)fprintf(stderr, "%s\n", error.message);
            return 1;
        }
        (void)clock_gettime(CLOCK_MONOTONIC, &end);
        double ms = (double)(end.tv_sec - start.tv_sec) * 1e3 + (double)(end.tv_nsec - start.tv_nsec) / 1e6;
        if (i == 0 || ms < best) best = ms;
        mg_grants_view(grants, &view);
        mg_grants_free(grants);
    }
    size_t tuples = view.member_count + view.nested_count + view.access_count + view.ref_count +
                    view.creator_count + view.owner_count + view.vref_name_count + view.vref_limit_count;
    printf("%.2f ms tuples=%zu groups=%zu index_bytes=%zu\n", best, tuples, view.group_count, view.index_bytes);
    return 0;
}
