/* The decisions of Git Core on a Gitolite configuration, for the oracle test
 * (tests/test_gitolite_oracle.py): migrates CONF into OUTPUT as grants as
 * data, then reads the queries of tests/gitolite_oracle.pl on stdin,
 *     REPO USER AA REF
 * and prints ALLOW, DENY or ERROR per query. The first line says whether
 * the configuration migrates: MIGRATED and the number of remarks of its
 * plan, each then on its own line, or UNSUPPORTED followed by each refused
 * entry on its own line, and then nothing else.
 *
 * A Gitolite repository REPO is the Git Core repository REPO.git. W is a
 * fast-forward, + a forced update; with the ref "any", W is a write and R
 * a read, without a ref, which Gitolite answers without its deny rules, as
 * Git Core does: gitolite-shell asks R any for upload-pack. */
#include "maelys_git.h"
#include "internal.h"
#include "policy/policy_grants.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *decide(maelys_git_policy_t *policy, const char *repository, const char *user,
                          const char *aa, const char *ref) {
    char repo[256];
    int written = snprintf(repo, sizeof(repo), "%s.git", repository);
    if (written < 0 || (size_t)written >= sizeof(repo)) return "ERROR";
    int any = strcmp(ref, "any") == 0;
    int read = strcmp(aa, "R") == 0;
    if (any ? !read && strcmp(aa, "W") != 0 : read) return "ERROR";
    maelys_git_policy_request_t request = {
        .request_id = "oracle",
        .principal = user,
        .repository = repo,
        .operation = any ? (read ? "read" : "write") : "push",
        .ref_name = any ? NULL : ref,
        .update_kind = any ? NULL : (strcmp(aa, "+") == 0 ? "force" : "fast_forward"),
    };
    maelys_git_policy_decision_t decision;
    maelys_git_error_t error;
    if (maelys_git_policy_authorize(policy, &request, &decision, &error) != MAELYS_GIT_OK) return "ERROR";
    return decision.allowed ? "ALLOW" : "DENY";
}

int main(int argc, char **argv) {
    if (argc != 3) {
        (void)fprintf(stderr, "usage: %s CONF OUTPUT\n", argv[0]);
        return 2;
    }
    maelys_git_gitolite_migration_result_t migration;
    maelys_git_error_t error;
    if (mg_migrate_gitolite_grants(argv[1], argv[2], 0, &migration, &error) != MAELYS_GIT_OK) {
        (void)fprintf(stderr, "plan: %s\n", error.message);
        return 1;
    }
    if (migration.unsupported_count) {
        (void)printf("UNSUPPORTED\n");
        for (size_t i = 0u; i < migration.unsupported_count; ++i) (void)printf("%s\n", migration.unsupported[i]);
        maelys_git_gitolite_migration_result_clear(&migration);
        return 0;
    }
    size_t remark_count = migration.remark_count;
    char **remarks = migration.remarks;
    migration.remarks = NULL;
    migration.remark_count = 0u;
    maelys_git_gitolite_migration_result_clear(&migration);
    if (mg_migrate_gitolite_grants(argv[1], argv[2], 1, &migration, &error) != MAELYS_GIT_OK) {
        (void)fprintf(stderr, "apply: %s\n", error.message);
        return 1;
    }
    maelys_git_gitolite_migration_result_clear(&migration);
    char manifest[4096], snapshot[4096];
    int a = snprintf(manifest, sizeof(manifest), "%s/manifest.json", argv[2]);
    int b = snprintf(snapshot, sizeof(snapshot), "%s/grants.json", argv[2]);
    if (a < 0 || (size_t)a >= sizeof(manifest) || b < 0 || (size_t)b >= sizeof(snapshot)) return 1;
    maelys_git_policy_t *policy = NULL;
    if (mg_policy_open_grants(manifest, snapshot, &policy, &error) != MAELYS_GIT_OK) {
        (void)fprintf(stderr, "open: %s\n", error.message);
        return 1;
    }
    (void)printf("MIGRATED %zu\n", remark_count);
    for (size_t i = 0u; i < remark_count; ++i) {
        (void)printf("%s\n", remarks[i]);
        free(remarks[i]);
    }
    free(remarks);
    char line[1024];
    while (fgets(line, sizeof(line), stdin)) {
        char repository[256], user[256], aa[8], ref[600];
        if (sscanf(line, "%255s %255s %7s %599s", repository, user, aa, ref) != 4) continue;
        (void)printf("%s\n", decide(policy, repository, user, aa, ref));
    }
    maelys_git_policy_close(policy);
    return 0;
}
