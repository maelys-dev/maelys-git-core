/* The budget of a migrated Gitolite policy: one fact per elementary grant,
 * fixed rules restricted to the request, a plan the engine compiles and whose
 * worst cases of execution the generator computes, and the capacities that
 * follow, proven by effective authorizations at their bounds. */
#include "maelys_git.h"
#include "test_support.h"

#include <maelys/cli/digest.h>

#include <stdint.h>

static char g_root[256];

static int write_text(const char *path, const char *text) {
    FILE *file = fopen(path, "w");
    if (!file) return 0;
    int ok = fputs(text, file) >= 0;
    return fclose(file) == 0 && ok;
}

static int read_text(const char *path, char *out, size_t capacity) {
    FILE *file = fopen(path, "r");
    if (!file) return 0;
    size_t length = fread(out, 1u, capacity - 1u, file);
    int complete = feof(file) != 0;
    (void)fclose(file);
    out[length] = '\0';
    return complete;
}

static int output_exists(const char *name) {
    char output[400];
    struct stat status;
    (void)snprintf(output, sizeof(output), "%s/%s", g_root, name);
    return lstat(output, &status) == 0;
}

/* Plans or applies NAME.conf into NAME. */
static maelys_git_result_t migrate(const char *name, const char *configuration, int apply,
                                   maelys_git_gitolite_migration_result_t *migration,
                                   maelys_git_error_t *error) {
    char input[400], output[400];
    (void)snprintf(input, sizeof(input), "%s/%s.conf", g_root, name);
    (void)snprintf(output, sizeof(output), "%s/%s", g_root, name);
    if (!write_text(input, configuration)) return MAELYS_GIT_ERR_IO;
    return maelys_git_migrate_gitolite(input, output, apply, migration, error);
}

static maelys_git_policy_t *open_migrated(const char *name) {
    char manifest[512];
    maelys_git_error_t error;
    maelys_git_policy_t *policy = NULL;
    (void)snprintf(manifest, sizeof(manifest), "%s/%s/manifest.json", g_root, name);
    if (maelys_git_policy_open(manifest, &policy, &error) != MAELYS_GIT_OK)
        (void)fprintf(stderr, "open %s: %s\n", name, error.message);
    return policy;
}

/* Writes NAME/policy.dl and NAME/manifest.json and opens the policy. */
static maelys_git_policy_t *open_written(const char *name, const char *source) {
    char directory[400], policy_path[512], manifest_path[512], manifest[2048];
    char digest[MAELYS_CLI_SHA256_HEX_SIZE];
    (void)snprintf(directory, sizeof(directory), "%s/%s", g_root, name);
    if (mkdir(directory, 0700) != 0) return NULL;
    (void)snprintf(policy_path, sizeof(policy_path), "%s/policy.dl", directory);
    (void)snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.json", directory);
    if (!write_text(policy_path, source)) return NULL;
    maelys_cli_sha256_hex(source, strlen(source), digest);
    (void)snprintf(manifest, sizeof(manifest),
        "{\"policy_set_id\":\"test.%s\",\"policy_set_version\":\"1\",\"manifest_version\":\"1\","
        "\"default_profile\":\"enforce\",\"created_for\":\"maelys-git-core-tests\","
        "\"strict_loading\":true,\"fail_closed\":true,\"capabilities\":[],\"policies\":[{"
        "\"policy_id\":\"test.%s.main\",\"domain\":\"maelys_git\",\"file\":\"policy.dl\","
        "\"sha256\":\"%s\",\"mode\":\"enforce\",\"enabled\":true,\"description\":\"test\","
        "\"queries\":[{\"name\":\"allow\",\"arity\":1},{\"name\":\"deny\",\"arity\":1}]}]}\n",
        name, name, digest);
    if (!write_text(manifest_path, manifest)) return NULL;
    maelys_git_policy_t *policy = NULL;
    maelys_git_error_t error;
    if (maelys_git_policy_open(manifest_path, &policy, &error) != MAELYS_GIT_OK)
        (void)fprintf(stderr, "open %s: %s\n", name, error.message);
    return policy;
}

/* 1 allowed, 0 denied, -1 not decided (the failure is printed). */
static int decision_of(maelys_git_policy_t *policy, const char *user, const char *repository,
                       const char *operation, const char *ref, const char *update_kind) {
    maelys_git_policy_request_t request = {
        .request_id = "t", .principal = user, .repository = repository, .operation = operation,
        .ref_name = ref, .update_kind = update_kind};
    maelys_git_policy_decision_t decision;
    maelys_git_error_t error;
    if (maelys_git_policy_authorize(policy, &request, &decision, &error) != MAELYS_GIT_OK) {
        (void)fprintf(stderr, "authorize %s %s %s: %s\n", user, operation, ref ? ref : "-",
                      error.message);
        return -1;
    }
    return decision.allowed ? 1 : 0;
}

/* A configuration of COUNT lines built by LINE(index) after HEADER. */
static char *configuration(const char *header, size_t count,
                           void (*line)(char *out, size_t size, size_t index)) {
    size_t capacity = strlen(header) + (count + 1u) * 160u;
    char *text = malloc(capacity);
    if (!text) return NULL;
    size_t used = (size_t)snprintf(text, capacity, "%s", header);
    for (size_t i = 1u; i <= count; ++i) {
        char entry[160];
        line(entry, sizeof(entry), i);
        used += (size_t)snprintf(text + used, capacity - used, "%s", entry);
    }
    return text;
}

static void rw_line(char *out, size_t size, size_t i) {
    (void)snprintf(out, size, "    RW = u%zu\n", i);
}

static void prefix_line(char *out, size_t size, size_t i) {
    (void)snprintf(out, size, "    RW+ refs/heads/team%zu/ = u%zu\n", i, i);
}

static void bare_deny_line(char *out, size_t size, size_t i) {
    (void)snprintf(out, size, "    - refs/heads/lock%zu = mallory\n", i);
}

static void member_line(char *out, size_t size, size_t i) {
    (void)snprintf(out, size, "@g%zu = alice\n", i);
}

/* The engine bounds, read from the plan of a minimal configuration. */
static maelys_git_policy_budget_t g_minimal;

static int test_minimal_budget(void) {
    maelys_git_gitolite_migration_result_t migration;
    maelys_git_error_t error;
    CHECK(migrate("minimal", "repo app\n    R = alice\n", 0, &migration, &error) == MAELYS_GIT_OK);
    CHECK(migration.unsupported_count == 0u);
    g_minimal = migration.budget;
    maelys_git_gitolite_migration_result_clear(&migration);
    CHECK(g_minimal.compiled && g_minimal.failure.kind == MAELYS_GIT_FAILURE_NONE);
    CHECK(g_minimal.facts == 1u);
    CHECK(g_minimal.rules > 0u && g_minimal.rules < g_minimal.rule_limit);
    CHECK(g_minimal.predicates > 0u && g_minimal.predicates <= g_minimal.predicate_limit);
    CHECK(g_minimal.fact_limit > 0u && g_minimal.derived_per_predicate == 4u);
    CHECK(g_minimal.derived_per_predicate_limit >= 64u && g_minimal.derived_limit >= 1024u);
    (void)printf("fixed: %zu rules of %zu, %zu predicates of %zu; facts limit %zu; "
                 "derived per predicate limit %zu\n",
                 g_minimal.rules, g_minimal.rule_limit, g_minimal.predicates,
                 g_minimal.predicate_limit, g_minimal.fact_limit,
                 g_minimal.derived_per_predicate_limit);
    return 1;
}

/* The most lines of LINE a plan accepts, searched down from START. */
static size_t largest_accepted(const char *name, const char *header, size_t start,
                               void (*line)(char *, size_t, size_t)) {
    for (size_t count = start; count > 0u; --count) {
        char *text = configuration(header, count, line);
        if (!text) return 0u;
        maelys_git_gitolite_migration_result_t migration;
        maelys_git_error_t error;
        maelys_git_result_t result = migrate(name, text, 0, &migration, &error);
        free(text);
        int accepted = result == MAELYS_GIT_OK && migration.unsupported_count == 0u;
        maelys_git_gitolite_migration_result_clear(&migration);
        if (accepted) return count;
    }
    return 0u;
}

/* A plan accepted at COUNT lines, applied, and refused at COUNT + 1 with
 * BUDGET in the unsupported entry, in budget.failure and in the apply error. */
static int at_bound(const char *name, const char *header, size_t count,
                    void (*line)(char *, size_t, size_t), const char *budget_name) {
    char accepted[64], refused[64];
    (void)snprintf(accepted, sizeof(accepted), "%s-%zu", name, count);
    (void)snprintf(refused, sizeof(refused), "%s-%zu", name, count + 1u);
    maelys_git_gitolite_migration_result_t migration;
    maelys_git_error_t error;
    char *text = configuration(header, count, line);
    CHECK(text != NULL);
    CHECK(migrate(accepted, text, 1, &migration, &error) == MAELYS_GIT_OK);
    free(text);
    CHECK(migration.unsupported_count == 0u && migration.budget.compiled);
    maelys_git_gitolite_migration_result_clear(&migration);

    text = configuration(header, count + 1u, line);
    CHECK(text != NULL);
    CHECK(migrate(refused, text, 0, &migration, &error) == MAELYS_GIT_OK);
    CHECK(migration.unsupported_count == 1u);
    char expected[160];
    (void)snprintf(expected, sizeof(expected), "policy budget exceeded: %s ", budget_name);
    CHECK(strstr(migration.unsupported[0], expected) != NULL);
    const maelys_git_policy_budget_t *budget = &migration.budget;
    CHECK(!budget->compiled && budget->rules == 0u && budget->facts == 0u);
    CHECK(budget->failure.kind == MAELYS_GIT_FAILURE_CAPACITY);
    CHECK(!strcmp(budget->failure.budget, budget_name));
    uint64_t requested = budget->failure.requested, limit = budget->failure.limit;
    CHECK(requested == limit + 1u);
    maelys_git_gitolite_migration_result_clear(&migration);
    /* The apply refuses with the same detail and writes nothing. */
    CHECK(migrate(refused, text, 1, &migration, &error) == MAELYS_GIT_ERR_POLICY);
    free(text);
    maelys_git_gitolite_migration_result_clear(&migration);
    CHECK(error.detail.kind == MAELYS_GIT_FAILURE_CAPACITY);
    CHECK(!strcmp(error.detail.budget, budget_name));
    CHECK(error.detail.requested == requested && error.detail.limit == limit);
    CHECK(!output_exists(refused));
    return 1;
}

/* One RW line on a repository is one fact: the plan that failed at 45 lines
 * now applies up to the fact budget, and every grant authorizes. */
static int test_rw_capacity(void) {
    size_t count = g_minimal.fact_limit;
    CHECK(at_bound("rw", "repo app\n", count, rw_line, "MAX_RULE_FACTS"));
    char name[64];
    (void)snprintf(name, sizeof(name), "rw-%zu", count);
    maelys_git_policy_t *policy = open_migrated(name);
    CHECK(policy != NULL);
    char last[32];
    (void)snprintf(last, sizeof(last), "u%zu", count);
    CHECK(decision_of(policy, "u1", "app.git", "read", NULL, NULL) == 1);
    CHECK(decision_of(policy, "u1", "app.git", "push", "refs/heads/main", "fast_forward") == 1);
    CHECK(decision_of(policy, "u1", "app.git", "push", "refs/heads/main", "force") == 0);
    CHECK(decision_of(policy, last, "app.git", "write", NULL, NULL) == 1);
    CHECK(decision_of(policy, last, "app.git", "push", "refs/heads/main", "create") == 1);
    CHECK(decision_of(policy, "zed", "app.git", "read", NULL, NULL) == 0);
    maelys_git_policy_close(policy);
    (void)printf("capacity: %zu RW lines on one repository\n", count);
    return 1;
}

/* A namespace prefix is one fact, matched through the request's ref_prefix.
 * Distinct subjects and prefixes are two policy atoms a line: the atom budget
 * binds before the fact budget, and the plan names it. */
static int test_prefix_capacity(void) {
    size_t count = largest_accepted("prefix-search", "repo app\n", g_minimal.fact_limit, prefix_line);
    CHECK(count > 14u);
    CHECK(at_bound("prefix", "repo app\n", count, prefix_line, "MAX_POLICY_ATOMS"));
    char name[64], last[32], inside[64], other[64];
    (void)snprintf(name, sizeof(name), "prefix-%zu", count);
    maelys_git_policy_t *policy = open_migrated(name);
    CHECK(policy != NULL);
    (void)snprintf(last, sizeof(last), "u%zu", count);
    (void)snprintf(inside, sizeof(inside), "refs/heads/team%zu/topic/x", count);
    (void)snprintf(other, sizeof(other), "refs/heads/team%zux/topic", count);
    CHECK(decision_of(policy, "u1", "app.git", "push", "refs/heads/team1/x", "force") == 1);
    CHECK(decision_of(policy, "u1", "app.git", "push", "refs/heads/team2/x", "create") == 0);
    CHECK(decision_of(policy, last, "app.git", "push", inside, "delete") == 1);
    CHECK(decision_of(policy, last, "app.git", "push", other, "create") == 0);
    CHECK(decision_of(policy, last, "app.git", "write", NULL, NULL) == 1);
    maelys_git_policy_close(policy);
    (void)printf("capacity: %zu RW+ namespace prefixes for distinct subjects\n", count);
    return 1;
}

/* A bare-literal deny stays a rule: the rules left by the fixed part, at
 * least the 56 that 62778f0 admitted beside its 72 fixed rules. */
static int test_rule_capacity(void) {
    size_t count = g_minimal.rule_limit - (g_minimal.rules);
    CHECK(count >= 56u);
    CHECK(at_bound("bare", "repo app\n    RW = alice\n", count, bare_deny_line, "MAX_RULES"));
    char name[64];
    (void)snprintf(name, sizeof(name), "bare-%zu", count);
    maelys_git_policy_t *policy = open_migrated(name);
    CHECK(policy != NULL);
    CHECK(decision_of(policy, "mallory", "app.git", "push", "refs/heads/lock1-hotfix", "create") == 0);
    CHECK(decision_of(policy, "alice", "app.git", "push", "refs/heads/lock1", "create") == 1);
    maelys_git_policy_close(policy);
    (void)printf("capacity: %zu bare-literal denies\n", count);
    return 1;
}

/* A group of more members than one derived predicate holds was unusable: its
 * membership is now derived for the request's user only. */
static int test_large_group(void) {
    maelys_git_gitolite_migration_result_t migration;
    maelys_git_error_t error;
    size_t members = g_minimal.derived_per_predicate_limit + 1u;
    if (members > 120u) members = 120u;
    char *text = malloc(16384);
    CHECK(text != NULL);
    size_t used = (size_t)snprintf(text, 16384, "@big =");
    for (size_t i = 1u; i <= members; ++i)
        used += (size_t)snprintf(text + used, 16384 - used, " m%zu", i);
    (void)snprintf(text + used, 16384 - used, "\nrepo app\n    RW = @big\n");
    CHECK(migrate("group", text, 1, &migration, &error) == MAELYS_GIT_OK);
    free(text);
    CHECK(migration.unsupported_count == 0u && migration.budget.derived_per_predicate == 4u);
    maelys_git_gitolite_migration_result_clear(&migration);
    maelys_git_policy_t *policy = open_migrated("group");
    CHECK(policy != NULL);
    char last[32];
    (void)snprintf(last, sizeof(last), "m%zu", members);
    CHECK(decision_of(policy, "m1", "app.git", "read", NULL, NULL) == 1);
    CHECK(decision_of(policy, last, "app.git", "push", "refs/heads/main", "create") == 1);
    CHECK(decision_of(policy, "zed", "app.git", "read", NULL, NULL) == 0);
    maelys_git_policy_close(policy);
    return 1;
}

/* The groups of one user are what effective_group_member holds for one
 * request: the plan computes them, through nesting, and refuses beyond the
 * engine's bound; at the bound, the user is authorized. */
static int test_groups_of_a_user(void) {
    size_t limit = g_minimal.derived_per_predicate_limit;
    /* The policy holds one fact per group and one grant: within the fact
     * budget only when the bound is below it, which is the SMALL profile. */
    if (limit + 2u > g_minimal.fact_limit) {
        (void)printf("groups of a user: bound %zu beyond the fact budget, not reachable\n", limit);
        return 1;
    }
    maelys_git_gitolite_migration_result_t migration;
    maelys_git_error_t error;
    char *text = configuration("", limit, member_line);
    CHECK(text != NULL);
    char *full = malloc(strlen(text) + 64u);
    CHECK(full != NULL);
    (void)snprintf(full, strlen(text) + 64u, "%srepo app\n    RW = @g%zu\n", text, limit);
    free(text);
    CHECK(migrate("groups-at", full, 1, &migration, &error) == MAELYS_GIT_OK);
    free(full);
    CHECK(migration.unsupported_count == 0u && migration.budget.derived_per_predicate == limit);
    maelys_git_gitolite_migration_result_clear(&migration);
    maelys_git_policy_t *policy = open_migrated("groups-at");
    CHECK(policy != NULL);
    CHECK(decision_of(policy, "alice", "app.git", "push", "refs/heads/main", "create") == 1);
    maelys_git_policy_close(policy);

    /* One group more, reached through nesting rather than directly. */
    text = configuration("", limit, member_line);
    CHECK(text != NULL);
    full = malloc(strlen(text) + 96u);
    CHECK(full != NULL);
    (void)snprintf(full, strlen(text) + 96u, "%s@outer = @g1\nrepo app\n    RW = @outer\n", text);
    free(text);
    CHECK(migrate("groups-over", full, 0, &migration, &error) == MAELYS_GIT_OK);
    CHECK(migration.unsupported_count == 1u);
    CHECK(strstr(migration.unsupported[0], "policy budget exceeded: MAX_FACTS_PER_PRED") != NULL);
    const maelys_git_failure_detail_t *failure = &migration.budget.failure;
    CHECK(migration.budget.compiled && failure->kind == MAELYS_GIT_FAILURE_CAPACITY);
    CHECK(!strcmp(failure->budget, "MAX_FACTS_PER_PRED"));
    CHECK(!strcmp(failure->diagnostic, "derived:effective_group_member"));
    CHECK(failure->requested == limit + 1u && failure->limit == limit);
    maelys_git_gitolite_migration_result_clear(&migration);
    CHECK(migrate("groups-over", full, 1, &migration, &error) == MAELYS_GIT_ERR_POLICY);
    free(full);
    maelys_git_gitolite_migration_result_clear(&migration);
    CHECK(error.detail.kind == MAELYS_GIT_FAILURE_CAPACITY && error.detail.requested == limit + 1u);
    CHECK(!output_exists("groups-over"));
    return 1;
}

/* A prefix deeper than the request's ref_prefix facts, or longer than an
 * atom, keeps the rule form and decides the same. */
static int test_rule_form_prefixes(void) {
    char deep[256] = "refs/heads/", long_prefix[128] = "refs/heads/", configuration_text[1024];
    for (size_t i = 0u; i < 15u; ++i) (void)strcat(deep, "d/");   /* 17 '/' */
    for (size_t i = 0u; i < 60u; ++i) (void)strcat(long_prefix, "l");
    (void)strcat(long_prefix, "/");
    char shallow[256] = "refs/heads/";
    for (size_t i = 0u; i < 14u; ++i) (void)strcat(shallow, "s/");  /* 16 '/' */
    (void)snprintf(configuration_text, sizeof(configuration_text),
                   "repo app\n    RW %s = alice\n    RW %s = bob\n    RW %s = carol\n",
                   deep, long_prefix, shallow);
    maelys_git_gitolite_migration_result_t migration;
    maelys_git_error_t error;
    CHECK(migrate("forms", configuration_text, 1, &migration, &error) == MAELYS_GIT_OK);
    CHECK(migration.unsupported_count == 0u);
    maelys_git_gitolite_migration_result_clear(&migration);
    char path[512], text[32768], expected[512];
    (void)snprintf(path, sizeof(path), "%s/forms/gitolite-migrated.dl", g_root);
    CHECK(read_text(path, text, sizeof(text)));
    (void)snprintf(expected, sizeof(expected), "starts_with(F, \"%s\")", deep);
    CHECK(strstr(text, expected) != NULL);
    (void)snprintf(expected, sizeof(expected), "starts_with(F, \"%s\")", long_prefix);
    CHECK(strstr(text, expected) != NULL);
    (void)snprintf(expected, sizeof(expected),
                   "gitolite_ref_access(\"carol\", \"app.git\", \"%s\", \"RW\").", shallow);
    CHECK(strstr(text, expected) != NULL);
    maelys_git_policy_t *policy = open_migrated("forms");
    CHECK(policy != NULL);
    char ref[512];
    (void)snprintf(ref, sizeof(ref), "%sx", deep);
    CHECK(decision_of(policy, "alice", "app.git", "push", ref, "create") == 1);
    CHECK(decision_of(policy, "bob", "app.git", "push", ref, "create") == 0);
    (void)snprintf(ref, sizeof(ref), "%sx", long_prefix);
    CHECK(decision_of(policy, "bob", "app.git", "push", ref, "create") == 1);
    (void)snprintf(ref, sizeof(ref), "%sy/z", shallow);
    CHECK(decision_of(policy, "carol", "app.git", "push", ref, "create") == 1);
    CHECK(decision_of(policy, "carol", "app.git", "push", "refs/heads/s/x", "create") == 0);
    CHECK(decision_of(policy, "alice", "app.git", "write", NULL, NULL) == 1);
    maelys_git_policy_close(policy);
    return 1;
}

static void read_line(char *out, size_t size, size_t i) {
    (void)snprintf(out, size, "    R = r%zu\n", i);
}

/* Prefixes as facts spend facts and atoms the rule form did not: when those
 * budgets refuse, the rule form is generated, and kept if it holds. 120 R
 * lines and 10 prefixes, admitted by 62778f0, stay admitted. */
static int test_rule_form_fallback(void) {
    char *text = configuration("repo app\n", 120u, read_line);
    CHECK(text != NULL);
    size_t length = strlen(text);
    char *full = realloc(text, length + 10u * 64u);
    CHECK(full != NULL);
    for (size_t i = 1u; i <= 10u; ++i)
        length += (size_t)snprintf(full + length, 64u, "    RW refs/heads/team%zu/ = w%zu\n", i, i);
    maelys_git_gitolite_migration_result_t migration;
    maelys_git_error_t error;
    CHECK(migrate("fallback", full, 1, &migration, &error) == MAELYS_GIT_OK);
    free(full);
    CHECK(migration.unsupported_count == 0u && migration.budget.compiled);
    CHECK(migration.budget.facts == 120u && migration.budget.rules == g_minimal.rules + 20u);
    maelys_git_gitolite_migration_result_clear(&migration);
    char path[512], policy_text[65536];
    (void)snprintf(path, sizeof(path), "%s/fallback/gitolite-migrated.dl", g_root);
    CHECK(read_text(path, policy_text, sizeof(policy_text)));
    CHECK(strstr(policy_text, "starts_with(F, \"refs/heads/team10/\")") != NULL);
    CHECK(strstr(policy_text, "gitolite_ref_access(\"w") == NULL);
    maelys_git_policy_t *policy = open_migrated("fallback");
    CHECK(policy != NULL);
    CHECK(decision_of(policy, "w10", "app.git", "push", "refs/heads/team10/x", "create") == 1);
    CHECK(decision_of(policy, "w10", "app.git", "push", "refs/heads/team1/x", "create") == 0);
    CHECK(decision_of(policy, "r120", "app.git", "read", NULL, NULL) == 1);
    maelys_git_policy_close(policy);
    return 1;
}

/* A ref of N prefixes: refs/heads/ then "a/" repeated, then "x". */
static void deep_ref(char *out, size_t prefixes) {
    (void)strcpy(out, "refs/heads/");
    for (size_t i = 2u; i < prefixes; ++i) (void)strcat(out, "a/");
    (void)strcat(out, "x");
}

/* The request's ref_prefix facts: the first sixteen '/'-terminated prefixes,
 * never the ref itself, and ref_prefix_count, untruncated; none without a
 * valid ref. */
static int test_ref_prefix_facts(void) {
    char prefix16[128], prefix17[128], source[1024];
    deep_ref(prefix16, 16u);
    prefix16[strlen(prefix16) - 1u] = '\0';  /* "refs/heads/" + 14 "a/": 16 '/' */
    (void)snprintf(prefix17, sizeof(prefix17), "%sa/", prefix16);
    (void)snprintf(source, sizeof(source),
        "allow(R) :- request(R), operation(\"three\"), ref_prefix(\"refs/\"), ref_prefix(\"refs/heads/\"),"
        " ref_prefix(\"refs/heads/a/\"), ref_prefix_count(3).\n"
        "deny(R) :- request(R), ref_prefix(\"refs/heads/a/b\").\n"
        "allow(R) :- request(R), operation(\"deep\"), ref_prefix(\"%s\"), ref_prefix_count(65).\n"
        "deny(R) :- request(R), ref_prefix(\"%s\").\n"
        "allow(R) :- request(R), operation(\"none\").\n"
        "deny(R) :- request(R), operation(\"none\"), ref_prefix_count(_).\n",
        prefix16, prefix17);
    maelys_git_policy_t *policy = open_written("prefix-facts", source);
    CHECK(policy != NULL);
    CHECK(decision_of(policy, "u", "r.git", "three", "refs/heads/a/b", NULL) == 1);
    CHECK(decision_of(policy, "u", "r.git", "three", "refs/heads/a/b/c", NULL) == 0);
    char ref[512];
    deep_ref(ref, 65u);
    CHECK(decision_of(policy, "u", "r.git", "deep", ref, NULL) == 1);
    CHECK(decision_of(policy, "u", "r.git", "none", NULL, NULL) == 1);
    CHECK(decision_of(policy, "u", "r.git", "none", "not-a-ref", NULL) == 1);
    CHECK(decision_of(policy, "u", "r.git", "none", "refs/heads/main", NULL) == 0);
    maelys_git_policy_close(policy);
    return 1;
}

/* The review's counterexample: a policy that reads none of the new facts
 * decides a ref of 65 prefixes, and one of 511 bytes, as before. */
static int test_requests_without_new_predicates(void) {
    maelys_git_policy_t *policy = NULL;
    maelys_git_error_t error;
    CHECK(maelys_git_policy_open(TEST_MANIFEST_FILE, &policy, &error) == MAELYS_GIT_OK);
    char ref[512];
    deep_ref(ref, 65u);
    CHECK(decision_of(policy, "alice", "example.git", "push", ref, "fast_forward") == 1);
    (void)strcpy(ref, "refs/heads/");
    while (strlen(ref) < 509u) (void)strcat(ref, "b/");
    while (strlen(ref) < 511u) (void)strcat(ref, "c");
    CHECK(strlen(ref) == 511u && maelys_git_ref_name_is_valid(ref));
    CHECK(decision_of(policy, "alice", "example.git", "push", ref, "fast_forward") == 1);
    CHECK(decision_of(policy, "mallory", "example.git", "push", ref, "fast_forward") == 0);
    maelys_git_policy_close(policy);
    return 1;
}

/* Every fixed rule that reads a policy fact indexed by a subject binds the
 * subject from the request first: the generator's restriction principle,
 * checked on the text it writes. */
static int test_rules_restricted(void) {
    char path[512], text[32768];
    (void)snprintf(path, sizeof(path), "%s/rw-%zu/gitolite-migrated.dl", g_root, g_minimal.fact_limit);
    CHECK(read_text(path, text, sizeof(text)));
    static const char *const indexed[] = {
        "group_member(", "gitolite_access(", "gitolite_ref_access(", "namespace_creator(",
        "owner_namespace_access(", "vref_deny_name(", "vref_deny_count(",
        "vref_deny_new_count(", "vref_deny_max_new_binary(", "effective_group_member(U, C)"};
    size_t rules = 0u;
    for (char *line = text; line && *line;) {
        char *end = strchr(line, '\n');
        if (end) *end = '\0';
        const char *neck = strstr(line, " :- ");
        if (neck) {
            ++rules;
            int reads = 0;
            for (size_t i = 0u; i < sizeof(indexed) / sizeof(indexed[0]); ++i)
                if (strstr(neck, indexed[i])) reads = 1;
            if (reads && !strstr(neck, "user(")) {
                (void)fprintf(stderr, "unrestricted rule: %s\n", line);
                return 0;
            }
        }
        line = end ? end + 1 : NULL;
    }
    CHECK(rules == g_minimal.rules);
    return 1;
}

int main(void) {
    char template[] = "/tmp/maelys_git_gitolite_budget_XXXXXX";
    char *root = mkdtemp(template);
    if (!root) return 1;
    (void)snprintf(g_root, sizeof(g_root), "%s", root);
    int ok = test_minimal_budget() && test_rw_capacity() && test_prefix_capacity() &&
             test_rule_capacity() && test_large_group() && test_groups_of_a_user() &&
             test_rule_form_prefixes() && test_rule_form_fallback() && test_ref_prefix_facts() &&
             test_requests_without_new_predicates() && test_rules_restricted();
    if (!test_remove_tree(g_root)) ok = 0;
    if (ok) puts("Gitolite policy budget: compilation, execution and capacities: ok");
    return ok ? 0 : 1;
}
