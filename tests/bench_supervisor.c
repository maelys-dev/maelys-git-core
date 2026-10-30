/* Cost of one supervised command, as the agent runs each Cloud command: a
 * fresh executor, its request written, its JSONL result read and validated,
 * its exit waited for, its process group terminated.
 *
 *   bench-maelys-git-supervisor EXECUTOR MANIFEST [ITERATIONS]
 *
 * EXECUTOR is maelys-git-executor; the command is health. Prints the minimum
 * and the median of five series, in milliseconds per command. Not a test:
 * timing depends on the machine and has no place in CTest. */
#include "agent/agent_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int compare_doubles(const void *left, const void *right) {
    double a = *(const double *)left, b = *(const double *)right;
    return (a > b) - (a < b);
}

int main(int argc, char **argv) {
    if (argc < 3 || argc > 4) {
        (void)fprintf(stderr, "usage: %s EXECUTOR MANIFEST [ITERATIONS]\n", argv[0]);
        return 2;
    }
    long iterations = argc > 3 ? atol(argv[3]) : 200;
    if (iterations <= 0) return 2;
    maelys_git_agent_config_t config = {0};
    (void)snprintf(config.executor_path, sizeof(config.executor_path), "%s", argv[1]);
    (void)snprintf(config.manifest_path, sizeof(config.manifest_path), "%s", argv[2]);
    (void)snprintf(config.repository_root, sizeof(config.repository_root), "/tmp");
    (void)snprintf(config.git_executable, sizeof(config.git_executable), "/usr/bin/git");
    config.request_timeout_ms = 60000u;
    mg_agent_message_t command = {.message_id = "bench", .agent_id = "bench-agent", .command = "health"};
    char request[512];
    double series_ms[5];
    for (int series = 0; series < 5; ++series) {
        int64_t started = mg_monotonic_ms();
        for (long i = 0; i < iterations; ++i) {
            int64_t now = mg_now_ms();
            (void)snprintf(request, sizeof(request),
                           "{\"protocol\":\"maelys-git-agent/1\",\"message_id\":\"bench\","
                           "\"agent_id\":\"bench-agent\",\"type\":\"command\",\"command\":\"health\","
                           "\"issued_at_ms\":%lld,\"expires_at_ms\":%lld,\"payload\":{}}",
                           (long long)now, (long long)now + 120000LL);
            char *response = NULL;
            int succeeded = 0;
            maelys_git_error_t error = {0};
            maelys_git_result_t result = mg_supervisor_execute(
                &config, &command, request, NULL, &response, &succeeded, &error);
            free(response);
            if (result != MAELYS_GIT_OK || !succeeded) {
                (void)fprintf(stderr, "supervised health failed: %s\n", error.message);
                return 1;
            }
        }
        series_ms[series] = (double)(mg_monotonic_ms() - started) / (double)iterations;
    }
    qsort(series_ms, 5u, sizeof(series_ms[0]), compare_doubles);
    (void)printf("%ld commands per series: min %.3f ms, median %.3f ms per command\n",
                 iterations, series_ms[0], series_ms[2]);
    return 0;
}
