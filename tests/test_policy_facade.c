/* The policy engine as Maelys Git Core uses it: vocabulary local to a policy,
 * engine limits, Gitolite prefixes, explanations and identities. */
#include "maelys_git.h"
#include "internal.h"
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

/* Reads a whole text file into a NUL-terminated buffer; refuses one that
 * does not fit, so a comparison never silently truncates. */
static int read_text(const char *path, char *out, size_t capacity) {
    FILE *file = fopen(path, "r");
    if (!file) return 0;
    size_t length = fread(out, 1u, capacity - 1u, file);
    int complete = feof(file) != 0;
    (void)fclose(file);
    out[length] = '\0';
    return complete;
}

/* Writes NAME/policy.dl and NAME/manifest.json and returns the manifest path. */
static const char *write_policy(const char *name, const char *source) {
    static char manifest_path[512];
    char directory[400], policy_path[512], manifest[2048];
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
    return write_text(manifest_path, manifest) ? manifest_path : NULL;
}

static int decide(maelys_git_policy_t *policy, const char *user, const char *repository,
                  const char *operation, const char *ref, const char *update_kind,
                  maelys_git_policy_decision_t *decision) {
    maelys_git_policy_request_t request = {
        .request_id = "t", .principal = user, .repository = repository, .operation = operation,
        .ref_name = ref, .update_kind = update_kind};
    maelys_git_error_t error;
    maelys_git_result_t result = maelys_git_policy_authorize(policy, &request, decision, &error);
    if (result != MAELYS_GIT_OK) (void)fprintf(stderr, "authorize: %s\n", error.message);
    return result == MAELYS_GIT_OK;
}

static int allowed(maelys_git_policy_t *policy, const char *user, const char *repository,
                   const char *operation, const char *ref, const char *update_kind) {
    maelys_git_policy_decision_t decision;
    return decide(policy, user, repository, operation, ref, update_kind, &decision) && decision.allowed;
}

static int denied_explicitly(maelys_git_policy_t *policy, const char *user, const char *repository,
                             const char *operation, const char *ref, const char *update_kind) {
    maelys_git_policy_decision_t decision;
    return decide(policy, user, repository, operation, ref, update_kind, &decision) &&
           !decision.allowed && decision.explicit_deny;
}

/* ---- vocabulary local to a policy --------------------------------------- */

static const char k_policy_a[] =
    "allow(R) :- request(R), operation(\"push\"), user(\"alice\").\n"
    "deny(R) :- request(R), commit_signature_status(\"unsigned\").\n";
static const char k_policy_b[] =
    "allow(R) :- request(R), operation(\"fetch\"), user(\"bob\").\n"
    "deny(R) :- request(R), repository(\"secret.git\").\n";

static int test_two_vocabularies(void) {
    maelys_git_error_t error;
    maelys_git_policy_t *a = NULL, *b = NULL, *again = NULL;
    char path_a[512], path_b[512], first[65], second[65], third[65];
    const char *path = write_policy("vocab-a", k_policy_a);
    CHECK(path != NULL);
    (void)snprintf(path_a, sizeof(path_a), "%s", path);
    path = write_policy("vocab-b", k_policy_b);
    CHECK(path != NULL);
    (void)snprintf(path_b, sizeof(path_b), "%s", path);
    /* Neither policy's constants are declared anywhere but in its own source. */
    CHECK(maelys_git_policy_open(path_a, &a, &error) == MAELYS_GIT_OK);
    CHECK(maelys_git_policy_open(path_b, &b, &error) == MAELYS_GIT_OK);
    CHECK(allowed(a, "alice", "r.git", "push", NULL, NULL));
    CHECK(!allowed(a, "bob", "r.git", "fetch", NULL, NULL));
    CHECK(allowed(b, "bob", "r.git", "fetch", NULL, NULL));
    CHECK(!allowed(b, "alice", "r.git", "push", NULL, NULL));
    CHECK(denied_explicitly(b, "bob", "secret.git", "fetch", NULL, NULL));
    CHECK(maelys_git_policy_fingerprint(a, first, &error) == MAELYS_GIT_OK);
    CHECK(maelys_git_policy_fingerprint(b, second, &error) == MAELYS_GIT_OK);
    CHECK(strcmp(first, second) != 0);
    /* A, then B, then A again: the same identity. */
    CHECK(maelys_git_policy_open(path_a, &again, &error) == MAELYS_GIT_OK);
    CHECK(maelys_git_policy_fingerprint(again, third, &error) == MAELYS_GIT_OK);
    CHECK(!strcmp(first, third));
    maelys_git_policy_close(again);
    /* Closing the first handle leaves the second one exactly as it was. */
    maelys_git_policy_decision_t before, after;
    CHECK(decide(b, "bob", "r.git", "fetch", NULL, NULL, &before));
    maelys_git_policy_close(a);
    CHECK(decide(b, "bob", "r.git", "fetch", NULL, NULL, &after));
    CHECK(before.allowed == after.allowed && !strcmp(before.reason, after.reason));
    CHECK(!strcmp(before.policy_set_fingerprint, after.policy_set_fingerprint));
    CHECK(!strcmp(before.session_fingerprint, after.session_fingerprint));
    CHECK(denied_explicitly(b, "bob", "secret.git", "fetch", NULL, NULL));
    maelys_git_policy_close(b);
    return 1;
}

/* ---- engine limits ------------------------------------------------------- */

/* A policy with `pairs` facts, each naming two constants no other fact uses,
 * spread over predicates so that none holds too many facts. */
static char *constants_policy(size_t pairs, const char *extra) {
    static const char *const predicates[] = {"grant_read", "grant_write", "grant_push",
                                             "grant_force", "grant_create"};
    size_t capacity = pairs * 64u + strlen(extra) + 256u;
    char *source = malloc(capacity);
    if (!source) return NULL;
    size_t used = 0u;
    for (size_t i = 0u; i < pairs; ++i)
        used += (size_t)snprintf(source + used, capacity - used, "%s(\"u%03zu\", \"r%03zu\").\n",
                                 predicates[i % 5u], i, i);
    (void)snprintf(source + used, capacity - used,
                   "allow(R) :- request(R), user(U), repository(P), grant_read(U, P).\n%s", extra);
    return source;
}

static int test_policy_atom_limits(void) {
    maelys_git_error_t error;
    maelys_git_policy_t *policy = NULL;
    char source[512];
    /* 63 bytes fit an atom; 64 do not. */
    char atom[65];
    memset(atom, 'a', 64u);
    atom[63] = '\0';
    (void)snprintf(source, sizeof(source), "allow(R) :- request(R), user(\"%s\").\n", atom);
    const char *path = write_policy("atom-63", source);
    CHECK(path && maelys_git_policy_open(path, &policy, &error) == MAELYS_GIT_OK);
    CHECK(allowed(policy, atom, "r.git", "read", NULL, NULL));
    maelys_git_policy_close(policy);
    policy = NULL;
    atom[63] = 'a';
    atom[64] = '\0';
    (void)snprintf(source, sizeof(source), "allow(R) :- request(R), user(\"%s\").\n", atom);
    path = write_policy("atom-64", source);
    CHECK(path && maelys_git_policy_open(path, &policy, &error) == MAELYS_GIT_ERR_POLICY);
    CHECK(policy == NULL && strstr(error.message, "64 requested, limit 63") != NULL);
    CHECK(strstr(error.message, "line 1") != NULL);

    /* 256 distinct constants load; the 257th is refused, atomically, and a
     * valid policy loads right after. */
    char *full = constants_policy(128u, "");
    CHECK(full != NULL);
    path = write_policy("atoms-256", full);
    free(full);
    CHECK(path && maelys_git_policy_open(path, &policy, &error) == MAELYS_GIT_OK);
    CHECK(allowed(policy, "u000", "r000", "read", NULL, NULL));
    maelys_git_policy_close(policy);
    policy = NULL;
    char *over = constants_policy(128u, "deny(R) :- request(R), user(\"one-too-many\").\n");
    CHECK(over != NULL);
    path = write_policy("atoms-257", over);
    free(over);
    maelys_git_result_t refused = maelys_git_policy_open(path, &policy, &error);
    CHECK(refused == MAELYS_GIT_ERR_POLICY && policy == NULL);
    CHECK(strstr(error.message, "257 requested, limit 256") != NULL);
    path = write_policy("after-refusal", k_policy_a);
    CHECK(path && maelys_git_policy_open(path, &policy, &error) == MAELYS_GIT_OK);
    CHECK(allowed(policy, "alice", "r.git", "push", NULL, NULL));
    maelys_git_policy_close(policy);
    return 1;
}

static int test_filter_pattern_not_an_atom(void) {
    maelys_git_error_t error;
    maelys_git_policy_t *policy = NULL;
    /* A 200-byte pattern: longer than any atom, and no atom at all. */
    char pattern[201], rule[512], with_atom[640];
    memset(pattern, 'p', 200u);
    memcpy(pattern, "refs/heads/", 11u);
    pattern[200] = '\0';
    (void)snprintf(rule, sizeof(rule),
                   "allow(R) :- request(R), ref(F), starts_with(F, \"%s\").\n", pattern);
    char *full = constants_policy(128u, rule);
    CHECK(full != NULL);
    const char *path = write_policy("pattern-256", full);
    free(full);
    CHECK(path && maelys_git_policy_open(path, &policy, &error) == MAELYS_GIT_OK);
    char ref[240];
    (void)snprintf(ref, sizeof(ref), "%s/x", pattern);
    CHECK(allowed(policy, "zed", "r.git", "push", ref, NULL));
    CHECK(!allowed(policy, "zed", "r.git", "push", "refs/heads/other", NULL));
    maelys_git_policy_close(policy);
    policy = NULL;
    /* The pattern left the 256 constants their whole budget: one more is refused. */
    (void)snprintf(with_atom, sizeof(with_atom),
                   "%sdeny(R) :- request(R), user(\"one-too-many\").\n", rule);
    char *over = constants_policy(128u, with_atom);
    CHECK(over != NULL);
    path = write_policy("pattern-257", over);
    free(over);
    CHECK(path && maelys_git_policy_open(path, &policy, &error) == MAELYS_GIT_ERR_POLICY);
    CHECK(policy == NULL);
    return 1;
}

static int test_refused_manifests(void) {
    /* A manifest that does not load is a policy error with a usable message. */
    maelys_git_error_t error;
    maelys_git_policy_t *policy = NULL;
    const char *path = write_policy("unknown-predicate", "allow(R) :- request(R), nosuch(R).\n");
    CHECK(path && maelys_git_policy_open(path, &policy, &error) == MAELYS_GIT_ERR_POLICY);
    CHECK(policy == NULL && strstr(error.message, "parser_unknown_predicate") != NULL);
    CHECK(strstr(error.message, "line 1 column") != NULL);
    /* Every entry disabled: nothing to evaluate, said plainly. */
    path = write_policy("disabled", k_policy_a);
    CHECK(path != NULL);
    char manifest[2048], patched[2048];
    FILE *file = fopen(path, "r");
    CHECK(file != NULL);
    size_t length = fread(manifest, 1u, sizeof(manifest) - 1u, file);
    (void)fclose(file);
    manifest[length] = '\0';
    char *enabled = strstr(manifest, "\"enabled\":true");
    CHECK(enabled != NULL);
    (void)snprintf(patched, sizeof(patched), "%.*s\"enabled\":false%s",
                   (int)(enabled - manifest), manifest, enabled + 14);
    CHECK(write_text(path, patched));
    CHECK(maelys_git_policy_open(path, &policy, &error) == MAELYS_GIT_ERR_POLICY);
    CHECK(policy == NULL && !strcmp(error.message, "manifest contains no enabled policy file"));
    return 1;
}

/* ---- identities ---------------------------------------------------------- */

static int test_fingerprints_unchanged(void) {
    /* Recorded on the baseline, before the engine API changed. */
    static const struct { const char *manifest; const char *fingerprint; } expected[] = {
        {TEST_MANIFEST_FILE, "ec093d9cf357d8859919ce9458d52185a2d0bc2acc234dcaba772c147057471a"},
        {FIXTURE_DIR "/gitolite-exact/manifest.json",
         "ffb281194cc7529c806830ef51eb58b02609dfad76883318ec8eb6f7a25d2de2"},
        {FIXTURE_DIR "/filters/manifest.json",
         "0a1aabd4f26ed69366e066220f679b6db17e7f6ec611180e2ef759bac5b42bc2"},
    };
    for (size_t i = 0u; i < 3u; ++i) {
        maelys_git_error_t error;
        maelys_git_policy_t *policy = NULL;
        char fingerprint[65];
        CHECK(maelys_git_policy_open(expected[i].manifest, &policy, &error) == MAELYS_GIT_OK);
        CHECK(maelys_git_policy_fingerprint(policy, fingerprint, &error) == MAELYS_GIT_OK);
        CHECK(!strcmp(fingerprint, expected[i].fingerprint));
        maelys_git_policy_close(policy);
    }
    return 1;
}

/* ---- Gitolite prefixes --------------------------------------------------- */

/* Migrates CONFIGURATION into NAME and opens the generated policy. */
static int migrate(const char *name, const char *configuration, int apply,
                   maelys_git_gitolite_migration_result_t *migration,
                   maelys_git_policy_t **out_policy) {
    char input[400], output[400], manifest[512];
    (void)snprintf(input, sizeof(input), "%s/%s.conf", g_root, name);
    (void)snprintf(output, sizeof(output), "%s/%s", g_root, name);
    CHECK(write_text(input, configuration));
    maelys_git_error_t error;
    maelys_git_result_t result = mg_migrate_gitolite_compiled(input, output, apply, migration, &error);
    if (!out_policy) return result == MAELYS_GIT_OK;
    CHECK(result == MAELYS_GIT_OK);
    (void)snprintf(manifest, sizeof(manifest), "%s/manifest.json", output);
    CHECK(maelys_git_policy_open(manifest, out_policy, &error) == MAELYS_GIT_OK);
    return 1;
}

static int output_exists(const char *name) {
    char output[400];
    struct stat status;
    (void)snprintf(output, sizeof(output), "%s/%s", g_root, name);
    return lstat(output, &status) == 0;
}

static int test_gitolite_prefixes(void) {
    maelys_git_gitolite_migration_result_t migration;
    maelys_git_policy_t *policy = NULL;
    CHECK(migrate("prefixes",
                  "@releasers = dave\n"
                  "repo app\n"
                  "    RW refs/heads/release/ = alice\n"
                  "    RW+ refs/tags/release/ = @releasers\n"
                  "    RW refs/heads/main = alice\n"
                  "    RW topic/ = carol\n"
                  "    RW refs/heads/stable$ = bob\n"
                  "    - refs/heads/main = mallory\n"
                  "    RW refs/heads/main = mallory\n",
                  1, &migration, &policy));
    CHECK(migration.unsupported_count == 0u);
    maelys_git_gitolite_migration_result_clear(&migration);

    /* A release branch: the namespace, not its neighbours. */
    CHECK(allowed(policy, "alice", "app.git", "push", "refs/heads/release/1.0", "create"));
    CHECK(allowed(policy, "alice", "app.git", "push", "refs/heads/release/1.0", "fast_forward"));
    CHECK(!allowed(policy, "alice", "app.git", "push", "refs/heads/release", "create"));
    CHECK(!allowed(policy, "alice", "app.git", "push", "refs/heads/releases", "create"));
    CHECK(!allowed(policy, "alice", "app.git", "push", "refs/heads/release-evil", "create"));
    /* RW is not RW+: no rewrite and no deletion. */
    CHECK(!allowed(policy, "alice", "app.git", "push", "refs/heads/release/1.0", "force"));
    CHECK(!allowed(policy, "alice", "app.git", "push", "refs/heads/release/1.0", "delete"));
    CHECK(!allowed(policy, "bob", "app.git", "push", "refs/heads/release/1.0", "create"));

    /* A group, with RW+, on a tag namespace. */
    CHECK(allowed(policy, "dave", "app.git", "push", "refs/tags/release/2.0", "create"));
    CHECK(allowed(policy, "dave", "app.git", "push", "refs/tags/release/2.0", "force"));
    CHECK(allowed(policy, "dave", "app.git", "push", "refs/tags/release/2.0", "delete"));
    CHECK(!allowed(policy, "dave", "app.git", "push", "refs/tags/other/2.0", "create"));
    CHECK(!allowed(policy, "alice", "app.git", "push", "refs/tags/release/2.0", "create"));

    /* A short name is completed by refs/heads/; a final $ is equality. */
    CHECK(allowed(policy, "carol", "app.git", "push", "refs/heads/topic/x", "create"));
    CHECK(!allowed(policy, "carol", "app.git", "push", "refs/heads/topic", "create"));
    CHECK(allowed(policy, "bob", "app.git", "push", "refs/heads/stable", "create"));
    CHECK(!allowed(policy, "bob", "app.git", "push", "refs/heads/stable-2", "create"));

    /* A bare literal grants the exact ref only. */
    CHECK(allowed(policy, "alice", "app.git", "push", "refs/heads/main", "fast_forward"));
    CHECK(!allowed(policy, "alice", "app.git", "push", "refs/heads/main-hotfix", "create"));

    /* A bare literal denies as a prefix, and the deny wins over the grant. */
    CHECK(denied_explicitly(policy, "mallory", "app.git", "push", "refs/heads/main", "fast_forward"));
    CHECK(denied_explicitly(policy, "mallory", "app.git", "push", "refs/heads/main-hotfix", "create"));
    CHECK(!denied_explicitly(policy, "alice", "app.git", "push", "refs/heads/main", "fast_forward"));

    /* Requests that carry no ref keep the access an exact grant gives. */
    CHECK(allowed(policy, "carol", "app.git", "write", NULL, NULL));
    CHECK(allowed(policy, "dave", "app.git", "write", NULL, NULL));
    CHECK(!allowed(policy, "zed", "app.git", "write", NULL, NULL));
    maelys_git_policy_request_t summary = {
        .request_id = "t", .principal = "carol", .repository = "app.git", .operation = "push",
        .has_summary = 1, .changed_count = 1u, .added_count = 1u, .commit_count = 1u};
    maelys_git_policy_decision_t decision;
    maelys_git_error_t error;
    CHECK(maelys_git_policy_authorize(policy, &summary, &decision, &error) == MAELYS_GIT_OK);
    CHECK(decision.allowed);
    maelys_git_policy_close(policy);
    return 1;
}

static int test_exact_refs_one_fact(void) {
    /* An exact ref is one fact per elementary grant, at its Gitolite level. */
    maelys_git_gitolite_migration_result_t migration;
    CHECK(migrate("exact",
                  "repo refs\n"
                  "    RW refs/heads/main = alice\n"
                  "    RW+ refs/heads/release = bob\n",
                  1, &migration, NULL));
    maelys_git_gitolite_migration_result_clear(&migration);
    char path[512], text[16384];
    (void)snprintf(path, sizeof(path), "%s/exact/gitolite-migrated.dl", g_root);
    FILE *file = fopen(path, "r");
    CHECK(file != NULL);
    size_t length = fread(text, 1u, sizeof(text) - 1u, file);
    (void)fclose(file);
    text[length] = '\0';
    static const char expected[] =
        "gitolite_ref_access(\"alice\", \"refs.git\", \"refs/heads/main\", \"RW\").\n"
        "gitolite_ref_access(\"bob\", \"refs.git\", \"refs/heads/release\", \"RW+\").\n\n";
    CHECK(strncmp(text, expected, sizeof(expected) - 1u) == 0);
    CHECK(strstr(text, "starts_with") == NULL);
    return 1;
}

static int unsupported_with(const char *name, const char *rule, const char *reason) {
    char configuration[512];
    (void)snprintf(configuration, sizeof(configuration), "repo app\n    %s\n", rule);
    maelys_git_gitolite_migration_result_t migration;
    /* Planning reports the entry; applying is refused and writes nothing. */
    CHECK(migrate(name, configuration, 0, &migration, NULL));
    CHECK(migration.unsupported_count == 1u);
    CHECK(strstr(migration.unsupported[0], reason) != NULL);
    maelys_git_gitolite_migration_result_clear(&migration);
    CHECK(!migrate(name, configuration, 1, &migration, NULL));
    maelys_git_gitolite_migration_result_clear(&migration);
    CHECK(!output_exists(name));
    return 1;
}

/* A refused /USER/ rule refuses the configuration: the broader grant beside
 * it is never migrated without it. */
static int test_user_refuses_configuration(void) {
    static const char *const configurations[] = {
        "repo app\n    RW+ refs/heads/ = alice\n    - USER/ = alice\n",
        "@devs = alice bob\nrepo app\n    RW+ personal/USER/ = @devs\n    RW refs/heads/main = bob\n",
    };
    for (size_t i = 0u; i < sizeof(configurations) / sizeof(configurations[0]); ++i) {
        char name[32];
        (void)snprintf(name, sizeof(name), "user-conf-%zu", i);
        maelys_git_gitolite_migration_result_t migration;
        CHECK(migrate(name, configurations[i], 0, &migration, NULL));
        CHECK(migration.unsupported_count == 1u);
        CHECK(strstr(migration.unsupported[0], "'/USER/'") != NULL);
        maelys_git_gitolite_migration_result_clear(&migration);
        CHECK(!migrate(name, configurations[i], 1, &migration, NULL));
        maelys_git_gitolite_migration_result_clear(&migration);
        CHECK(!output_exists(name));
    }
    return 1;
}

static int test_unsupported_refex(void) {
    /* A regex is decided by grants as data: the compiled encoding, which
     * this test migrates to, has no form for it. */
    static const char k_needs_grants[] = "migrated as grants as data only";
    CHECK(unsupported_with("alt", "RW refs/heads/(main|dev) = alice", k_needs_grants));
    CHECK(unsupported_with("star", "RW refs/heads/feature/.* = alice", k_needs_grants));
    CHECK(unsupported_with("class", "RW refs/heads/[a-z]+ = alice", k_needs_grants));
    CHECK(unsupported_with("dots", "RW refs/heads/../main = alice", k_needs_grants));
    CHECK(unsupported_with("dot-deny", "- refs/tags/v1.0 = alice", k_needs_grants));
    CHECK(unsupported_with("dot-grant", "RW refs/tags/v1.0$ = alice", k_needs_grants));
    CHECK(unsupported_with("escape-end", "RW refs/heads/a\\$ = alice", k_needs_grants));
    /* Refused whatever the encoding: the restrictions and the subset, by the
     * column of the refex as written; a literal that is not a valid pattern
     * is never read as a regex. */
    CHECK(unsupported_with("caret", "- ^refs/heads/main = alice", "refex refused at column 1: a '^' outside a class"));
    CHECK(unsupported_with("top-alternation", "RW main|dev = alice", "refex refused at column 5: a '|' at the top level"));
    CHECK(unsupported_with("escape", "RW refs/heads/a\\d = alice", "refex refused at column 14"));
    CHECK(unsupported_with("escaped-dots", "RW refs/heads/\\.\\./main = alice", "unsupported refex syntax"));
    CHECK(unsupported_with("anchored-namespace", "RW refs/heads/x/$ = alice", "unsupported refex syntax"));
    CHECK(unsupported_with("vref", "RW+ VREF/NAME/ = alice", "full-ref"));
    /* Gitolite puts each user's name in place of /USER/, once completed. */
    CHECK(unsupported_with("user-grant", "RW+ personal/USER/ = alice", "'/USER/'"));
    CHECK(unsupported_with("user-deny", "- USER/ = alice", "'/USER/'"));
    CHECK(unsupported_with("user-full", "- refs/heads/USER/x = alice", "'/USER/'"));
    CHECK(unsupported_with("user-vref", "- VREF/NAME/USER/secret = alice", "'/USER/'"));
    CHECK(unsupported_with("user-first", "RW USER/(a|b) = alice", "'/USER/'"));
    char rule[400], pattern[300];
    memset(pattern, 'x', sizeof(pattern));
    memcpy(pattern, "refs/heads/", 11u);
    pattern[280] = '/';
    pattern[281] = '\0';
    (void)snprintf(rule, sizeof(rule), "RW %s = alice", pattern);
    CHECK(unsupported_with("long", rule, "ref pattern exceeds 256 bytes"));
    return 1;
}

/* ---- explanations -------------------------------------------------------- */

static const char k_policy_tags[] =
    /* A version tag: a prefix that is not a namespace, written by hand. */
    "allow(R) :- request(R), operation(\"push\"), user(\"dave\"), ref(F), starts_with(F, \"refs/tags/v\").\n"
    "deny(R) :- request(R), ref(F), ends_with(F, \"-rc\"), user(\"dave\").\n";

static int test_explanations(void) {
    maelys_git_error_t error;
    maelys_git_policy_t *policy = NULL;
    const char *path = write_policy("tags", k_policy_tags);
    CHECK(path && maelys_git_policy_open(path, &policy, &error) == MAELYS_GIT_OK);
    char set_fingerprint[65];
    CHECK(maelys_git_policy_fingerprint(policy, set_fingerprint, &error) == MAELYS_GIT_OK);
    CHECK(allowed(policy, "dave", "app.git", "push", "refs/tags/v2.0", "create"));
    CHECK(!allowed(policy, "dave", "app.git", "push", "refs/tags/x1.0", "create"));

    maelys_git_policy_request_t request = {
        .request_id = "t", .principal = "dave", .repository = "app.git", .operation = "push",
        .ref_name = "refs/tags/v2.0"};
    maelys_git_policy_explanation_t explanation;
    char text[4096];

    /* A filtered allow: the witness keeps the filter, its identity and its pattern. */
    CHECK(maelys_git_policy_explain(policy, &request, text, sizeof(text), &explanation, &error) ==
          MAELYS_GIT_OK);
    CHECK(explanation.decision.allowed && explanation.kind == MAELYS_GIT_EXPLANATION_WHY_TRUE);
    CHECK(explanation.status == MAELYS_GIT_EXPLANATION_COMPLETE && !strcmp(explanation.query, "allow"));
    CHECK(explanation.explained_policy == 0u && explanation.text_length == strlen(text));
    CHECK(strncmp(text, "MAELYS-DATALOG-v2\ndocument=why-true\n", 36u) == 0);
    CHECK(strstr(text, "kind=filter-true") && strstr(text, "filter=\"starts_with\""));
    CHECK(strstr(text, "semantic=\"string.starts-with.utf8-bytes-v1\""));
    CHECK(strstr(text, "pattern=\"refs/tags/v\"") && strstr(text, "value=\"refs/tags/v2.0\""));
    CHECK(explanation.filter_matches >= 1u && explanation.filter_cost_units > 0u);
    CHECK(!strcmp(explanation.decision.policy_set_fingerprint, set_fingerprint));
    CHECK(strlen(explanation.decision.session_fingerprint) == 64u);

    /* The size query, then a buffer one byte short: no partial text. */
    maelys_git_policy_explanation_t measured;
    CHECK(maelys_git_policy_explain(policy, &request, NULL, 0u, &measured, &error) == MAELYS_GIT_OK);
    CHECK(measured.text_required == explanation.text_length && measured.text_length == 0u);
    char small[64];
    memset(small, 'x', sizeof(small));
    CHECK(maelys_git_policy_explain(policy, &request, small, sizeof(small), &measured, &error) ==
          MAELYS_GIT_ERR_LIMIT);
    CHECK(small[0] == '\0' && measured.text_required == explanation.text_length);
    char exact[4096];
    CHECK(maelys_git_policy_explain(policy, &request, exact, explanation.text_length, &measured,
                                    &error) == MAELYS_GIT_ERR_LIMIT);
    CHECK(maelys_git_policy_explain(policy, &request, exact, explanation.text_length + 1u,
                                    &measured, &error) == MAELYS_GIT_OK);
    CHECK(!strcmp(exact, text));

    /* A derived deny is witnessed too. */
    request.ref_name = "refs/tags/v2.0-rc";
    CHECK(maelys_git_policy_explain(policy, &request, text, sizeof(text), &explanation, &error) ==
          MAELYS_GIT_OK);
    CHECK(explanation.decision.explicit_deny && explanation.kind == MAELYS_GIT_EXPLANATION_WHY_TRUE);
    CHECK(!strcmp(explanation.query, "deny") && strstr(text, "filter=\"ends_with\""));

    /* A denial by default: a complete why-false whose obstacle is the filter. */
    request.ref_name = "refs/tags/x1.0";
    CHECK(maelys_git_policy_explain(policy, &request, text, sizeof(text), &explanation, &error) ==
          MAELYS_GIT_OK);
    CHECK(!explanation.decision.allowed && !explanation.decision.explicit_deny);
    CHECK(explanation.kind == MAELYS_GIT_EXPLANATION_WHY_FALSE && !strcmp(explanation.query, "allow"));
    CHECK(explanation.status == MAELYS_GIT_EXPLANATION_COMPLETE);
    CHECK(strncmp(text, "MAELYS-DATALOG-v2\ndocument=why-false\n", 37u) == 0);
    CHECK(strstr(text, "obstacle=filter-false") && strstr(text, "pattern=\"refs/tags/v\""));
    CHECK(explanation.decision.session_fingerprint[0] == '\0');
    CHECK(explanation.filter_non_matches >= 1u);
    maelys_git_policy_close(policy);

    /* The identity follows the pattern. */
    char other[sizeof(k_policy_tags)], changed[65];
    memcpy(other, k_policy_tags, sizeof(other));
    char *pattern = strstr(other, "refs/tags/v\"");
    CHECK(pattern != NULL);
    pattern[10] = 'w';
    path = write_policy("tags-w", other);
    CHECK(path && maelys_git_policy_open(path, &policy, &error) == MAELYS_GIT_OK);
    CHECK(maelys_git_policy_fingerprint(policy, changed, &error) == MAELYS_GIT_OK);
    CHECK(strcmp(changed, set_fingerprint) != 0);
    maelys_git_policy_close(policy);
    return 1;
}

static int test_explain_multiple_policies(void) {
    /* The witness comes from the policy that decided, the why-false from the last. */
    maelys_git_error_t error;
    maelys_git_policy_t *policy = NULL;
    CHECK(maelys_git_policy_open(FIXTURE_DIR "/filters/manifest.json", &policy, &error) == MAELYS_GIT_OK);
    maelys_git_policy_request_t request = {
        .request_id = "t", .principal = "alice", .repository = "team/app.git", .operation = "push",
        .ref_name = "refs/heads/release/1.0/frozen"};
    maelys_git_policy_explanation_t explanation;
    char text[4096];
    CHECK(maelys_git_policy_explain(policy, &request, text, sizeof(text), &explanation, &error) ==
          MAELYS_GIT_OK);
    CHECK(explanation.decision.explicit_deny && explanation.decision.matched_policy == 1u);
    CHECK(explanation.explained_policy == 1u && strstr(text, "filter=\"ends_with\""));
    request.ref_name = "refs/heads/release/1.0";
    CHECK(maelys_git_policy_explain(policy, &request, text, sizeof(text), &explanation, &error) ==
          MAELYS_GIT_OK);
    CHECK(explanation.decision.allowed && explanation.explained_policy == 0u);
    request.principal = "zed";
    CHECK(maelys_git_policy_explain(policy, &request, text, sizeof(text), &explanation, &error) ==
          MAELYS_GIT_OK);
    CHECK(explanation.kind == MAELYS_GIT_EXPLANATION_WHY_FALSE && explanation.explained_policy == 1u);
    maelys_git_policy_close(policy);
    return 1;
}

/* ---- refused policies and requests --------------------------------------- */

/* Every refusal the policy layer reports: a manifest that does not load, a
 * request whose facts exceed the engine, a solve the engine rejects. */
typedef struct {
    const char *name;
    maelys_git_result_t result;
    maelys_git_error_t error;
} refusal_t;

/* `count` rules that differ by an integer only, so that no rule adds a
 * constant to the policy. */
static char *rules_policy(size_t count) {
    size_t capacity = count * 72u + 1u;
    char *source = malloc(capacity);
    if (!source) return NULL;
    size_t used = 0u;
    for (size_t i = 0u; i < count; ++i)
        used += (size_t)snprintf(source + used, capacity - used,
                                 "allow(R) :- request(R), changed_count(C), C > %zu.\n", i);
    return source;
}

/* `count` direct policy facts naming the same two constants. */
static char *facts_policy(size_t count) {
    size_t capacity = count * 48u + 128u;
    char *source = malloc(capacity);
    if (!source) return NULL;
    size_t used = 0u;
    for (size_t i = 0u; i < count; ++i)
        used += (size_t)snprintf(source + used, capacity - used,
                                 "vref_deny_count(\"u\", \"r\", %zu).\n", i);
    (void)snprintf(source + used, capacity - used, "allow(R) :- request(R).\n");
    return source;
}

/* A literal string of `length` bytes in a rule. */
static char *literal_policy(size_t length) {
    char *source = malloc(length + 64u);
    if (!source) return NULL;
    int prefix = snprintf(source, length + 64u, "allow(R) :- request(R), user(\"");
    memset(source + prefix, 'a', length);
    (void)snprintf(source + (size_t)prefix + length, length + 64u - ((size_t)prefix + length), "\").\n");
    return source;
}

static int refuse_load(const char *name, const char *source, refusal_t *out) {
    maelys_git_policy_t *policy = NULL;
    const char *path = source ? write_policy(name, source) : NULL;
    if (!path) return 0;
    out->name = name;
    out->result = maelys_git_policy_open(path, &policy, &out->error);
    maelys_git_policy_close(policy);
    return out->result != MAELYS_GIT_OK && policy == NULL;
}

static int refuse_owned(const char *name, char *source, refusal_t *out) {
    int ok = refuse_load(name, source, out);
    free(source);
    return ok;
}

/* Changes a policy after its manifest was written: its source, so that the
 * recorded digest no longer matches, or the manifest, so that no entry is
 * enabled. */
static int refuse_manifest(const char *name, int edit_source, refusal_t *out) {
    const char *path = write_policy(name, k_policy_a);
    char manifest[2048], patched[2048];
    if (!path || !read_text(path, manifest, sizeof(manifest))) return 0;
    if (edit_source) {
        char source_path[512];
        (void)snprintf(source_path, sizeof(source_path), "%s/%s/policy.dl", g_root, name);
        (void)snprintf(patched, sizeof(patched), "%s%s", k_policy_a, "deny(R) :- request(R).\n");
        if (!write_text(source_path, patched)) return 0;
    } else {
        char *at = strstr(manifest, "\"enabled\":true");
        if (!at) return 0;
        (void)snprintf(patched, sizeof(patched), "%.*s\"enabled\":false%s",
                       (int)(at - manifest), manifest, at + 14);
        if (!write_text(path, patched)) return 0;
    }
    maelys_git_policy_t *policy = NULL;
    out->name = name;
    out->result = maelys_git_policy_open(path, &policy, &out->error);
    maelys_git_policy_close(policy);
    return out->result != MAELYS_GIT_OK && policy == NULL;
}

static int refuse_request(const char *name, const char *source,
                          const maelys_git_policy_request_t *request, refusal_t *out) {
    maelys_git_policy_t *policy = NULL;
    const char *path = write_policy(name, source);
    if (!path || maelys_git_policy_open(path, &policy, &out->error) != MAELYS_GIT_OK) return 0;
    maelys_git_policy_decision_t decision;
    out->name = name;
    out->result = maelys_git_policy_authorize(policy, request, &decision, &out->error);
    maelys_git_policy_close(policy);
    return out->result != MAELYS_GIT_OK;
}

/* 300 paths: more than MAX_FACTS_PER_PRED in either profile. */
#define TEST_PATHS 300u

enum {
    REFUSAL_ATOM_BYTES, REFUSAL_POLICY_ATOMS, REFUSAL_RULES, REFUSAL_STRING_BYTES,
    REFUSAL_POLICY_FACTS, REFUSAL_INVALID_TOKEN, REFUSAL_EXPECTED_DOT,
    REFUSAL_UNKNOWN_PREDICATE, REFUSAL_DIGEST, REFUSAL_NONE_ENABLED,
    REFUSAL_PATHS, REFUSAL_INTEGER, REFUSAL_DERIVED, REFUSAL_COUNT
};

static int collect_refusals(refusal_t out[REFUSAL_COUNT]) {
    char atom[65];
    memset(atom, 'a', 64u);
    atom[64] = '\0';
    char source[256];
    (void)snprintf(source, sizeof(source), "allow(R) :- request(R), user(\"%s\").\n", atom);
    CHECK(refuse_load("refused-atom-bytes", source, &out[REFUSAL_ATOM_BYTES]));
    CHECK(refuse_owned("refused-policy-atoms",
                       constants_policy(128u, "deny(R) :- request(R), user(\"one-too-many\").\n"),
                       &out[REFUSAL_POLICY_ATOMS]));
    CHECK(refuse_owned("refused-rules", rules_policy(1024u), &out[REFUSAL_RULES]));
    CHECK(refuse_owned("refused-string-bytes", literal_policy(1025u), &out[REFUSAL_STRING_BYTES]));
    CHECK(refuse_owned("refused-policy-facts", facts_policy(129u), &out[REFUSAL_POLICY_FACTS]));
    CHECK(refuse_load("refused-invalid-token", "allow(R) :- request(R) $.\n",
                      &out[REFUSAL_INVALID_TOKEN]));
    CHECK(refuse_load("refused-expected-dot", "allow(R) :- request(R)\n",
                      &out[REFUSAL_EXPECTED_DOT]));
    CHECK(refuse_load("refused-unknown-predicate", "allow(R) :- request(R), nosuch(R).\n",
                      &out[REFUSAL_UNKNOWN_PREDICATE]));
    CHECK(refuse_manifest("refused-digest", 1, &out[REFUSAL_DIGEST]));
    CHECK(refuse_manifest("refused-none-enabled", 0, &out[REFUSAL_NONE_ENABLED]));

    static char paths[TEST_PATHS][16];
    static const char *path_list[TEST_PATHS];
    for (size_t i = 0u; i < TEST_PATHS; ++i) {
        (void)snprintf(paths[i], sizeof(paths[i]), "f%zu", i);
        path_list[i] = paths[i];
    }
    maelys_git_policy_request_t request = {
        .request_id = "t", .principal = "alice", .repository = "r.git", .operation = "push",
        .paths = path_list, .path_count = TEST_PATHS};
    CHECK(refuse_request("refused-paths", k_policy_a, &request, &out[REFUSAL_PATHS]));
    maelys_git_policy_request_t integer = {
        .request_id = "t", .principal = "alice", .repository = "r.git", .operation = "push",
        .has_summary = 1, .changed_count = SIZE_MAX};
    CHECK(refuse_request("refused-integer", k_policy_a, &integer, &out[REFUSAL_INTEGER]));
    /* 17 by 17 facts joined: 289 derived facts of one predicate, beyond
     * MAX_FACTS_PER_PRED in either profile. */
    char derived[2048];
    size_t used = 0u;
    for (size_t i = 0u; i < 17u; ++i)
        used += (size_t)snprintf(derived + used, sizeof(derived) - used,
                                 "group_member(\"u%zu\", \"g\"). grant_read(\"x\", \"p%zu\").\n", i, i);
    (void)snprintf(derived + used, sizeof(derived) - used,
                   "effective_group_member(U, P) :- group_member(U, G), grant_read(X, P).\n"
                   "allow(R) :- request(R), user(U), effective_group_member(U, \"p0\").\n");
    maelys_git_policy_request_t plain = {
        .request_id = "t", .principal = "u0", .repository = "r.git", .operation = "read"};
    CHECK(refuse_request("refused-derived", derived, &plain, &out[REFUSAL_DERIVED]));
    return 1;
}

/* The message with the temporary root replaced, so that it compares across runs. */
static void portable_message(const char *message, char *out, size_t capacity) {
    size_t root = strlen(g_root), used = 0u;
    for (const char *p = message; *p && used + 1u < capacity;) {
        if (!strncmp(p, g_root, root)) {
            used += (size_t)snprintf(out + used, capacity - used, "ROOT");
            p += root;
        } else {
            out[used++] = *p++;
        }
    }
    out[used < capacity ? used : capacity - 1u] = '\0';
}

/* The result code and message of every refusal are those recorded on the
 * baseline, byte for byte; the message is quoted so that its end shows.
 * MG_RECORD_ERROR_MESSAGES=FILE writes them instead. */
static int test_error_messages_unchanged(const refusal_t refusals[REFUSAL_COUNT]) {
    char lines[REFUSAL_COUNT][MAELYS_GIT_MAX_ERROR + 128u];
    for (size_t i = 0u; i < REFUSAL_COUNT; ++i) {
        char message[MAELYS_GIT_MAX_ERROR + 64u];
        portable_message(refusals[i].error.message, message, sizeof(message));
        (void)snprintf(lines[i], sizeof(lines[i]), "%s\t%s\t\"%s\"\n", refusals[i].name,
                       maelys_git_result_name(refusals[i].result), message);
    }
    const char *record = getenv("MG_RECORD_ERROR_MESSAGES");
    if (record && *record) {
        FILE *file = fopen(record, "w");
        CHECK(file != NULL);
        for (size_t i = 0u; i < REFUSAL_COUNT; ++i) CHECK(fputs(lines[i], file) >= 0);
        CHECK(fclose(file) == 0);
        return 1;
    }
    static char expected[REFUSAL_COUNT * (MAELYS_GIT_MAX_ERROR + 128u)];
    CHECK(read_text(FIXTURE_DIR "/error-messages.tsv", expected, sizeof(expected)));
    const char *cursor = expected;
    for (size_t i = 0u; i < REFUSAL_COUNT; ++i) {
        size_t length = strlen(lines[i]);
        if (strncmp(cursor, lines[i], length) != 0) {
            (void)fprintf(stderr, "message changed: %s", lines[i]);
            return 0;
        }
        cursor += length;
    }
    CHECK(*cursor == '\0');
    return 1;
}

/* A capacity detail names its budget as the engine does, and reports the
 * attempted count and the bound; the policy is located when the engine
 * located it. */
static int capacity_detail(const refusal_t *refusal, const char *budget) {
    const maelys_git_failure_detail_t *detail = &refusal->error.detail;
    CHECK(detail->kind == MAELYS_GIT_FAILURE_CAPACITY);
    CHECK(!strcmp(detail->budget, budget));
    CHECK(detail->limit > 0u && detail->requested > detail->limit);
    return 1;
}

static int located(const refusal_t *refusal) {
    const maelys_git_failure_detail_t *detail = &refusal->error.detail;
    CHECK(detail->line > 0u && detail->column > 0u);
    CHECK(strstr(detail->file, refusal->name) != NULL);
    return 1;
}

static int loads(const char *name, char *source) {
    maelys_git_policy_t *policy = NULL;
    maelys_git_error_t error;
    const char *path = source ? write_policy(name, source) : NULL;
    free(source);
    CHECK(path && maelys_git_policy_open(path, &policy, &error) == MAELYS_GIT_OK);
    CHECK(error.detail.kind == MAELYS_GIT_FAILURE_NONE);
    maelys_git_policy_close(policy);
    return 1;
}

/* Tests 3 to 5, 17 and 20: every budget exceeded at load is named, and the
 * bound is the engine's: a policy at that bound loads. No limit is written
 * here; each is read from the detail. */
static int test_capacity_details(const refusal_t refusals[REFUSAL_COUNT]) {
    const refusal_t *atom = &refusals[REFUSAL_ATOM_BYTES];
    CHECK(capacity_detail(atom, "MAX_POLICY_ATOM_BYTES") && located(atom));
    CHECK(atom->error.detail.requested == 64u && atom->error.detail.limit == 63u);
    size_t limit = (size_t)atom->error.detail.limit;
    char *source = malloc(limit + 64u);
    CHECK(source != NULL);
    int prefix = snprintf(source, limit + 64u, "allow(R) :- request(R), user(\"");
    memset(source + prefix, 'b', limit);
    (void)snprintf(source + (size_t)prefix + limit, limit + 64u - ((size_t)prefix + limit), "\").\n");
    CHECK(loads("bound-atom-bytes", source));

    const refusal_t *atoms = &refusals[REFUSAL_POLICY_ATOMS];
    CHECK(capacity_detail(atoms, "MAX_POLICY_ATOMS") && located(atoms));
    CHECK(atoms->error.detail.requested == atoms->error.detail.limit + 1u);
    CHECK(loads("bound-policy-atoms", constants_policy((size_t)atoms->error.detail.limit / 2u, "")));

    const refusal_t *rules = &refusals[REFUSAL_RULES];
    CHECK(capacity_detail(rules, "MAX_RULES") && located(rules));
    CHECK(rules->error.detail.requested == rules->error.detail.limit + 1u);
    CHECK(loads("bound-rules", rules_policy((size_t)rules->error.detail.limit)));

    const refusal_t *string = &refusals[REFUSAL_STRING_BYTES];
    CHECK(capacity_detail(string, "MAX_STRING_BYTES") && located(string));
    CHECK(string->error.detail.requested == 1025u);

    /* One diagnostic code, three budgets: only the detail tells them apart. */
    CHECK(!strcmp(atom->error.detail.diagnostic, "lexer_string_too_long"));
    CHECK(!strcmp(atoms->error.detail.diagnostic, atom->error.detail.diagnostic));
    CHECK(!strcmp(string->error.detail.diagnostic, atom->error.detail.diagnostic));

    const refusal_t *facts = &refusals[REFUSAL_POLICY_FACTS];
    CHECK(capacity_detail(facts, "MAX_RULE_FACTS") && located(facts));
    CHECK(facts->error.detail.requested == facts->error.detail.limit + 1u);
    CHECK(facts->error.detail.line == facts->error.detail.requested);
    CHECK(loads("bound-policy-facts", facts_policy((size_t)facts->error.detail.limit)));
    return 1;
}

/* Tests 6 to 8: syntax, meaning and manifest, by the engine's code. */
static int test_other_details(const refusal_t refusals[REFUSAL_COUNT]) {
    static const struct { size_t refusal; maelys_git_failure_kind_t kind; const char *code; } expected[] = {
        {REFUSAL_INVALID_TOKEN, MAELYS_GIT_FAILURE_SYNTAX, "lexer_invalid_token"},
        {REFUSAL_EXPECTED_DOT, MAELYS_GIT_FAILURE_SYNTAX, "parser_expected_dot"},
        {REFUSAL_UNKNOWN_PREDICATE, MAELYS_GIT_FAILURE_SEMANTICS, "parser_unknown_predicate"},
        {REFUSAL_DIGEST, MAELYS_GIT_FAILURE_MANIFEST, "manifest_sha_mismatch"},
        {REFUSAL_NONE_ENABLED, MAELYS_GIT_FAILURE_MANIFEST, ""},
    };
    for (size_t i = 0u; i < sizeof(expected) / sizeof(expected[0]); ++i) {
        const refusal_t *refusal = &refusals[expected[i].refusal];
        const maelys_git_failure_detail_t *detail = &refusal->error.detail;
        CHECK(detail->kind == expected[i].kind && !strcmp(detail->diagnostic, expected[i].code));
        CHECK(detail->budget[0] == '\0' && detail->requested == 0u && detail->limit == 0u);
        if (expected[i].kind != MAELYS_GIT_FAILURE_MANIFEST) CHECK(located(refusal));
    }
    CHECK(!strcmp(maelys_git_failure_kind_name(MAELYS_GIT_FAILURE_SEMANTICS), "semantics"));
    return 1;
}

/* The longest valid repository name: 254 segments, one fact each. */
static void deep_repository(char out[MAELYS_GIT_MAX_REPOSITORY]) {
    size_t used = 0u;
    for (size_t i = 0u; i < 253u; ++i) { out[used++] = 'a'; out[used++] = '/'; }
    memcpy(out + used, "x.git", 6u);
}

/* Tests 9, 10, 15 and 16: request facts beyond a bound Git Core checks, and
 * beyond one the engine checks, report the same budget and the same limit:
 * the profile's, read from the engine. A request at that limit passes. */
static int test_request_details(const refusal_t refusals[REFUSAL_COUNT]) {
    const refusal_t *paths = &refusals[REFUSAL_PATHS];
    CHECK(capacity_detail(paths, "MAX_FACTS_PER_PRED"));
    CHECK(paths->error.detail.requested == TEST_PATHS && paths->error.detail.diagnostic[0] == '\0');
    const uint64_t per_predicate = paths->error.detail.limit;
    const refusal_t *derived = &refusals[REFUSAL_DERIVED];
    CHECK(capacity_detail(derived, "MAX_FACTS_PER_PRED"));
    CHECK(!strcmp(derived->error.detail.diagnostic, "solve_idb_overflow"));
    CHECK(derived->error.detail.limit == per_predicate);
    CHECK(derived->error.detail.requested == per_predicate + 1u);
    const maelys_git_failure_detail_t *integer = &refusals[REFUSAL_INTEGER].error.detail;
    CHECK(integer->kind == MAELYS_GIT_FAILURE_VALUE && integer->budget[0] == '\0');

    maelys_git_policy_t *policy = NULL;
    maelys_git_error_t error;
    const char *path = write_policy("request-bounds", k_policy_a);
    CHECK(path && maelys_git_policy_open(path, &policy, &error) == MAELYS_GIT_OK);
    static char names[TEST_PATHS][16];
    static const char *list[TEST_PATHS];
    for (size_t i = 0u; i < TEST_PATHS; ++i) {
        (void)snprintf(names[i], sizeof(names[i]), "g%zu", i);
        list[i] = names[i];
    }
    maelys_git_policy_request_t request = {
        .request_id = "t", .principal = "alice", .repository = "r.git", .operation = "push",
        .paths = list, .path_count = (size_t)per_predicate};
    maelys_git_policy_decision_t decision;
    CHECK(maelys_git_policy_authorize(policy, &request, &decision, &error) == MAELYS_GIT_OK);
    CHECK(decision.allowed && error.detail.kind == MAELYS_GIT_FAILURE_NONE);

    /* A repository name may hold more segments than the SMALL profile admits
     * facts of one predicate: the engine refuses that batch at the solve. */
    char repository[MAELYS_GIT_MAX_REPOSITORY];
    deep_repository(repository);
    maelys_git_policy_request_t deep = {
        .request_id = "t", .principal = "alice", .repository = repository, .operation = "push"};
    maelys_git_result_t result = maelys_git_policy_authorize(policy, &deep, &decision, &error);
    if (per_predicate < 254u) {
        CHECK(result == MAELYS_GIT_ERR_POLICY);
        CHECK(!strncmp(error.message, "policy solve failed: operation_rejected", 39u));
        CHECK(error.detail.kind == MAELYS_GIT_FAILURE_CAPACITY);
        CHECK(!strcmp(error.detail.budget, "MAX_FACTS_PER_PRED"));
        /* The engine counts the attempt that overflowed, not the whole batch. */
        CHECK(error.detail.requested == per_predicate + 1u && error.detail.limit == per_predicate);
    } else {
        CHECK(result == MAELYS_GIT_OK && error.detail.kind == MAELYS_GIT_FAILURE_NONE);
    }
    maelys_git_policy_close(policy);
    return 1;
}

/* Tests 11 and 18: a call that succeeds, or that fails for another reason,
 * leaves no policy detail behind; clearing an error clears its detail. */
static int test_detail_reset(void) {
    maelys_git_policy_t *policy = NULL;
    maelys_git_error_t error;
    const char *path = write_policy("detail-reset", k_policy_a);
    CHECK(path && maelys_git_policy_open(path, &policy, &error) == MAELYS_GIT_OK);
    maelys_git_policy_request_t request = {
        .request_id = "t", .principal = "alice", .repository = "r.git", .operation = "push",
        .has_summary = 1, .changed_count = SIZE_MAX};
    maelys_git_policy_decision_t decision;
    CHECK(maelys_git_policy_authorize(policy, &request, &decision, &error) == MAELYS_GIT_ERR_POLICY);
    CHECK(error.detail.kind == MAELYS_GIT_FAILURE_VALUE);
    request.changed_count = 1u;
    CHECK(maelys_git_policy_authorize(policy, &request, &decision, &error) == MAELYS_GIT_OK);
    CHECK(error.detail.kind == MAELYS_GIT_FAILURE_NONE);

    request.changed_count = SIZE_MAX;
    CHECK(maelys_git_policy_authorize(policy, &request, &decision, &error) == MAELYS_GIT_ERR_POLICY);
    request.principal = NULL;
    CHECK(maelys_git_policy_authorize(policy, &request, &decision, &error) ==
          MAELYS_GIT_ERR_INVALID_ARGUMENT);
    CHECK(error.detail.kind == MAELYS_GIT_FAILURE_NONE && error.detail.diagnostic[0] == '\0');

    request.principal = "alice";
    CHECK(maelys_git_policy_authorize(policy, &request, &decision, &error) == MAELYS_GIT_ERR_POLICY);
    maelys_git_error_clear(&error);
    maelys_git_error_t zero;
    memset(&zero, 0, sizeof(zero));
    CHECK(!memcmp(&error, &zero, sizeof(error)));
    maelys_git_policy_close(policy);
    return 1;
}

static int test_refusals(void) {
    static refusal_t refusals[REFUSAL_COUNT];
    CHECK(collect_refusals(refusals));
    for (size_t i = 0u; i < REFUSAL_COUNT; ++i)
        CHECK(refusals[i].result == MAELYS_GIT_ERR_POLICY);
    CHECK(test_error_messages_unchanged(refusals));
    CHECK(test_capacity_details(refusals));
    CHECK(test_other_details(refusals));
    CHECK(test_request_details(refusals));
    CHECK(test_detail_reset());
    return 1;
}

int main(void) {
    char template[] = "/tmp/maelys_git_policy_XXXXXX";
    char *root = mkdtemp(template);
    if (!root) return 1;
    (void)snprintf(g_root, sizeof(g_root), "%s", root);
    int ok = test_two_vocabularies() && test_policy_atom_limits() &&
             test_filter_pattern_not_an_atom() && test_refused_manifests() &&
             test_fingerprints_unchanged() &&
             test_gitolite_prefixes() && test_exact_refs_one_fact() &&
             test_unsupported_refex() && test_user_refuses_configuration() &&
             test_explanations() && test_explain_multiple_policies() && test_refusals();
    if (!test_remove_tree(g_root)) ok = 0;
    if (ok) puts("local vocabulary, engine limits, Gitolite prefixes, explanations and identities: ok");
    return ok ? 0 : 1;
}
