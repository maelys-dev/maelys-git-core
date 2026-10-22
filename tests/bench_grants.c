/* Cost of loading grants snapshots: the trusted read, the parse, the
 * validation and the index. Load I reads FILE number I modulo their count,
 * so successive loads read different generations. Each load keeps the
 * previous snapshot until it succeeds, as a reload in a stream does, so the
 * peak includes both; a refused load keeps the previous one. Prints, at
 * loads 1, 5, 10, 20, 30, 40, every fiftieth and the last, the peak
 * resident memory, the resident memory now and the bytes still allocated; then, per file, the
 * minimum and median time, the counts or the refusal. Not a test.
 *
 *   bench-maelys-git-grants ITERATIONS FILE... */
#include "policy/grants.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

#ifdef __APPLE__
#include <mach/mach.h>
#include <malloc/malloc.h>
static double in_use_mib(void) {
    malloc_statistics_t stats;
    malloc_zone_statistics(NULL, &stats);
    return (double)stats.size_in_use / 1048576.0;
}
static double resident_mib(void) {
    task_vm_info_data_t info;
    mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&info, &count) != KERN_SUCCESS) return -1.0;
    return (double)info.phys_footprint / 1048576.0;
}
static double peak_mib(void) {
    struct rusage usage;
    (void)getrusage(RUSAGE_SELF, &usage);
    return (double)usage.ru_maxrss / 1048576.0; /* bytes on macOS */
}
#else
#include <malloc.h>
#include <unistd.h>
static double in_use_mib(void) {
    struct mallinfo2 info = mallinfo2();
    return (double)(info.uordblks + info.hblkhd) / 1048576.0;
}
static double resident_mib(void) {
    long pages = 0, resident = 0;
    FILE *file = fopen("/proc/self/statm", "r");
    if (!file) return -1.0;
    int read = fscanf(file, "%ld %ld", &pages, &resident);
    (void)fclose(file);
    return read == 2 ? (double)resident * (double)sysconf(_SC_PAGESIZE) / 1048576.0 : -1.0;
}
static double peak_mib(void) {
    struct rusage usage;
    (void)getrusage(RUSAGE_SELF, &usage);
    return (double)usage.ru_maxrss / 1024.0; /* KiB on Linux */
}
#endif

static int compare_doubles(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static int checkpoint(long load, long last) {
    return load == 1 || load == 5 || load == 10 || load == 20 || load == 30 || load == 40 || load % 50 == 0 ||
           load == last;
}

int main(int argc, char **argv) {
    if (argc < 3 || atol(argv[1]) < 1) {
        (void)fprintf(stderr, "usage: %s ITERATIONS FILE...\n", argv[0]);
        return 2;
    }
    long iterations = atol(argv[1]);
    int files = argc - 2;
    long per_file = (iterations + files - 1) / files;
    double *times = calloc((size_t)files * (size_t)per_file, sizeof(*times));
    long *timed = calloc((size_t)files, sizeof(*timed));
    mg_grants_view_t *views = calloc((size_t)files, sizeof(*views));
    char (*refusals)[256] = calloc((size_t)files, sizeof(*refusals));
    if (!times || !timed || !views || !refusals) return 1;
    mg_grants_t *previous = NULL;
    for (long i = 0; i < iterations; ++i) {
        int f = (int)(i % files);
        struct timespec start, end;
        mg_grants_t *grants = NULL;
        maelys_git_error_t error = {0};
        (void)clock_gettime(CLOCK_MONOTONIC, &start);
        maelys_git_result_t result = mg_grants_load(argv[2 + f], &grants, &error);
        (void)clock_gettime(CLOCK_MONOTONIC, &end);
        times[(size_t)f * (size_t)per_file + (size_t)timed[f]++] =
            (double)(end.tv_sec - start.tv_sec) * 1e3 + (double)(end.tv_nsec - start.tv_nsec) / 1e6;
        if (result == MAELYS_GIT_OK) {
            mg_grants_view(grants, &views[f]);
            mg_grants_free(previous);
            previous = grants;
        } else {
            (void)snprintf(refusals[f], sizeof(refusals[f]), "%s", error.message);
        }
        if (checkpoint(i + 1, iterations))
            printf("load=%ld peak=%.1f MiB resident=%.1f MiB in_use=%.2f MiB\n", i + 1, peak_mib(), resident_mib(),
                   in_use_mib());
    }
    mg_grants_free(previous);
    for (int f = 0; f < files; ++f) {
        double *own = times + (size_t)f * (size_t)per_file;
        qsort(own, (size_t)timed[f], sizeof(*own), compare_doubles);
        double median = timed[f] % 2 ? own[timed[f] / 2] : (own[timed[f] / 2 - 1] + own[timed[f] / 2]) / 2.0;
        const char *name = strrchr(argv[2 + f], '/');
        name = name ? name + 1 : argv[2 + f];
        if (refusals[f][0]) {
            printf("%s: min %.2f ms median %.2f ms refused: %s\n", name, own[0], median, refusals[f]);
            continue;
        }
        const mg_grants_view_t *view = &views[f];
        size_t tuples = view->member_count + view->nested_count + view->access_count + view->ref_count +
                        view->creator_count + view->owner_count + view->vref_name_count + view->vref_limit_count;
        printf("%s: min %.2f ms median %.2f ms tuples=%zu groups=%zu index_bytes=%zu\n", name, own[0], median, tuples,
               view->group_count, view->index_bytes);
    }
    free(times);
    free(timed);
    free(views);
    free(refusals);
    return 0;
}
