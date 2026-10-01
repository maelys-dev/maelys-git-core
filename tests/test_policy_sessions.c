#include "maelys_git.h"
#include "test_support.h"

#include <limits.h>
#include <pthread.h>

/* The reused sessions of a long-lived handle against a handle opened for this
 * one request: same result code and same decision, field by field. */
static int compare(maelys_git_policy_t *policy, maelys_git_policy_request_t *request) {
    maelys_git_policy_decision_t reused = {0}, fresh = {0};
    maelys_git_error_t error = {0};
    maelys_git_policy_t *single = NULL;
    CHECK(maelys_git_policy_open(TEST_MANIFEST_FILE, &single, &error) == MAELYS_GIT_OK);
    maelys_git_result_t actual = maelys_git_policy_authorize(policy, request, &reused, &error);
    maelys_git_result_t expected = maelys_git_policy_authorize(single, request, &fresh, &error);
    maelys_git_policy_close(single);
    CHECK(actual == expected);
    CHECK(reused.allowed == fresh.allowed && reused.explicit_deny == fresh.explicit_deny);
    CHECK(reused.matched_policy == fresh.matched_policy && !strcmp(reused.reason, fresh.reason));
    CHECK(!strcmp(reused.policy_set_fingerprint, fresh.policy_set_fingerprint));
    CHECK(!strcmp(reused.session_fingerprint, fresh.session_fingerprint));
    return 1;
}

static int sequences(size_t worker) {
    maelys_git_policy_t *policy = NULL;
    maelys_git_error_t error = {0};
    CHECK(maelys_git_policy_open(TEST_MANIFEST_FILE, &policy, &error) == MAELYS_GIT_OK);
    const char *users[] = {"alice", "bob", "mallory"};
    const char *paths[] = {"file.txt", "secrets/production.env"};
    maelys_git_policy_request_t request = {
        .request_id = "A", .principal = "bob", .repository = "example.git",
        .operation = "read",
    };
    maelys_git_policy_decision_t first = {0}, last = {0};
    CHECK(maelys_git_policy_authorize(policy, &request, &first, &error) == MAELYS_GIT_OK);
    CHECK(first.allowed);
    /* Exceed the symbol capacity cumulatively: each solve must start clean. */
    for (size_t i = 0; i < 600u; ++i) {
        char id[64];
        (void)snprintf(id, sizeof(id), "worker-%zu-request-%zu", worker, i);
        request.request_id = id;
        request.principal = users[i % 3u];
        request.operation = i % 2u ? "push" : "read";
        request.ref_name = i % 4u ? "refs/heads/topic" : "refs/heads/main";
        request.paths = paths;
        request.path_count = i % 3u;
        request.has_summary = (int)(i % 2u);
        request.changed_count = i;
        request.has_commit_signed = (int)(i % 2u);
        request.commit_signed = (int)(i % 3u == 0u);
        CHECK(compare(policy, &request));
    }
    /* An error must deny, and must not poison the next authorization. */
    request.request_id = "overflow";
    request.has_summary = 1;
    request.changed_count = ULLONG_MAX;
    CHECK(compare(policy, &request));
    CHECK(maelys_git_policy_authorize(policy, &request, &last, &error) != MAELYS_GIT_OK);
    CHECK(!last.allowed);
    request = (maelys_git_policy_request_t){
        .request_id = "A", .principal = "bob", .repository = "example.git", .operation = "read"};
    CHECK(maelys_git_policy_authorize(policy, &request, &last, &error) == MAELYS_GIT_OK);
    CHECK(last.allowed == first.allowed && last.explicit_deny == first.explicit_deny);
    CHECK(last.matched_policy == first.matched_policy && !strcmp(last.reason, first.reason));
    maelys_git_policy_close(policy);
    return 1;
}

typedef struct { size_t id; int passed; } worker_t;
static void *worker_main(void *opaque) {
    worker_t *worker = opaque;
    worker->passed = sequences(worker->id);
    return NULL;
}

int main(void) {
    if (!sequences(0u)) return 1;
    pthread_t threads[4];
    worker_t workers[4] = {{1u, 0}, {2u, 0}, {3u, 0}, {4u, 0}};
    for (size_t i = 0; i < 4u; ++i)
        if (pthread_create(&threads[i], NULL, worker_main, &workers[i]) != 0) return 1;
    for (size_t i = 0; i < 4u; ++i)
        if (pthread_join(threads[i], NULL) != 0 || !workers[i].passed) return 1;
    puts("reused/fresh handle differential, reset after error, A/B/A and independent workers: ok");
    return 0;
}
