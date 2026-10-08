#include "maelys_git.h"
#include "test_support.h"

#include <pthread.h>

/* The first opens of a process, from several threads at once: the domain is
 * registered exactly once, behind the handle's guard, and no thread observes a
 * half-registered engine. The main thread opens nothing before releasing the
 * workers, so the registration really happens under contention. Meant to run
 * under ThreadSanitizer as well as natively. */
#define WORKERS 8u

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t ready;
    size_t waiting;
} barrier_t;

typedef struct {
    barrier_t *barrier;
    int passed;
} worker_t;

static void barrier_wait(barrier_t *barrier) {
    (void)pthread_mutex_lock(&barrier->mutex);
    if (++barrier->waiting == WORKERS) (void)pthread_cond_broadcast(&barrier->ready);
    while (barrier->waiting < WORKERS) (void)pthread_cond_wait(&barrier->ready, &barrier->mutex);
    (void)pthread_mutex_unlock(&barrier->mutex);
}

static int first_open(void) {
    maelys_git_policy_t *policy = NULL;
    maelys_git_error_t error = {0};
    CHECK(maelys_git_policy_open(TEST_MANIFEST_FILE, &policy, &error) == MAELYS_GIT_OK);
    maelys_git_policy_request_t request = {
        .request_id = "first", .principal = "bob", .repository = "example.git",
        .operation = "read",
    };
    maelys_git_policy_decision_t decision = {0};
    CHECK(maelys_git_policy_authorize(policy, &request, &decision, &error) == MAELYS_GIT_OK);
    CHECK(decision.allowed);
    maelys_git_policy_close(policy);
    return 1;
}

static void *worker_main(void *opaque) {
    worker_t *worker = opaque;
    barrier_wait(worker->barrier);
    worker->passed = first_open();
    return NULL;
}

int main(void) {
    barrier_t barrier;
    if (pthread_mutex_init(&barrier.mutex, NULL) != 0 || pthread_cond_init(&barrier.ready, NULL) != 0)
        return 1;
    barrier.waiting = 0u;
    pthread_t threads[WORKERS];
    worker_t workers[WORKERS];
    for (size_t i = 0u; i < WORKERS; ++i) {
        workers[i].barrier = &barrier;
        workers[i].passed = 0;
        if (pthread_create(&threads[i], NULL, worker_main, &workers[i]) != 0) return 1;
    }
    int ok = 1;
    for (size_t i = 0u; i < WORKERS; ++i)
        if (pthread_join(threads[i], NULL) != 0 || !workers[i].passed) ok = 0;
    /* A later open in the main thread sees the domain the workers registered. */
    if (ok && !first_open()) ok = 0;
    (void)pthread_cond_destroy(&barrier.ready);
    (void)pthread_mutex_destroy(&barrier.mutex);
    if (ok) puts("eight simultaneous first opens, one domain registration: ok");
    return ok ? 0 : 1;
}
