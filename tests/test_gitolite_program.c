/* The audited Gitolite program and its grants as data (GIT-C06, commit 3):
 * the identity the audited consumer relies on, the routing of the slice,
 * the fixed program, and the parity of its decisions with the compiled
 * encoding of the same configuration, loaded by the same binary. */
#include "maelys_git.h"
#include "internal.h"
#include "policy/grants.h"
#include "policy/policy_grants.h"
#include "policy/policy_reads.h"
#include "policy/program.h"
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

/* The whole file, NUL-terminated, or NULL. */
static char *read_file(const char *path, size_t *out_size) {
    FILE *file = fopen(path, "rb");
    if (!file) return NULL;
    char *bytes = NULL;
    size_t size = 0u, capacity = 0u;
    for (;;) {
        if (size + 4096u + 1u > capacity) {
            capacity = capacity ? capacity * 2u : 8192u;
            char *grown = realloc(bytes, capacity);
            if (!grown) { free(bytes); (void)fclose(file); return NULL; }
            bytes = grown;
        }
        size_t read = fread(bytes + size, 1u, 4096u, file);
        size += read;
        if (read < 4096u) break;
    }
    (void)fclose(file);
    bytes[size] = '\0';
    if (out_size) *out_size = size;
    return bytes;
}

/* NAME/ holding one file per source and a manifest that enables them in
 * order; returns the manifest path (static storage). */
static const char *write_set(const char *name, size_t count, const char *const *sources) {
    static char manifest_path[512];
    char directory[400], path[512], entries[8192] = "", digest[MAELYS_CLI_SHA256_HEX_SIZE];
    (void)snprintf(directory, sizeof(directory), "%s/%s", g_root, name);
    if (mkdir(directory, 0700) != 0) return NULL;
    for (size_t i = 0u; i < count; ++i) {
        (void)snprintf(path, sizeof(path), "%s/p%zu.dl", directory, i);
        if (!write_text(path, sources[i])) return NULL;
        maelys_cli_sha256_hex(sources[i], strlen(sources[i]), digest);
        char entry[1024];
        (void)snprintf(entry, sizeof(entry),
            "%s{\"policy_id\":\"test.%s.p%zu\",\"domain\":\"maelys_git\",\"file\":\"p%zu.dl\","
            "\"sha256\":\"%s\",\"mode\":\"enforce\",\"enabled\":true,\"description\":\"test\","
            "\"queries\":[{\"name\":\"allow\",\"arity\":1},{\"name\":\"deny\",\"arity\":1}]}",
            i ? "," : "", name, i, i, digest);
        (void)strcat(entries, entry);
    }
    char manifest[9216];
    (void)snprintf(manifest, sizeof(manifest),
        "{\"policy_set_id\":\"test.%s\",\"policy_set_version\":\"1\",\"manifest_version\":\"1\","
        "\"default_profile\":\"enforce\",\"created_for\":\"maelys-git-core-tests\","
        "\"strict_loading\":true,\"fail_closed\":true,\"capabilities\":[],\"policies\":[%s]}\n",
        name, entries);
    (void)snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.json", directory);
    return write_text(manifest_path, manifest) ? manifest_path : NULL;
}

/* A snapshot file NAME.json; returns its path (static storage). */
static const char *write_grants(const char *name, const char *json) {
    static char path[512];
    (void)snprintf(path, sizeof(path), "%s/%s.json", g_root, name);
    return write_text(path, json) ? path : NULL;
}

#define EMPTY_GRANTS                                                                                 \
    "{\"access\":[],\"format\":\"maelys-git-grants/1\",\"members\":[],\"namespace_creators\":[],"   \
    "\"nested\":[],\"owner_access\":[],\"refs\":[],\"vref_limits\":[],\"vref_names\":[]}"

/* Migrates CONFIGURATION, written as NAME.conf, in both encodings: the
 * compiled one into NAME-compiled (NULL when its plan refuses it) and the
 * grants as data into NAME-grants, both opened. */
static int migrate_both(const char *name, const char *configuration, maelys_git_policy_t **out_compiled,
                        maelys_git_policy_t **out_grants) {
    char input[400], compiled[400], grants[400], manifest[512], snapshot[512];
    (void)snprintf(input, sizeof(input), "%s/%s.conf", g_root, name);
    (void)snprintf(compiled, sizeof(compiled), "%s/%s-compiled", g_root, name);
    (void)snprintf(grants, sizeof(grants), "%s/%s-grants", g_root, name);
    CHECK(write_text(input, configuration));
    maelys_git_gitolite_migration_result_t migration;
    maelys_git_error_t error;
    *out_compiled = *out_grants = NULL;
    if (maelys_git_migrate_gitolite(input, compiled, 1, &migration, &error) == MAELYS_GIT_OK) {
        (void)snprintf(manifest, sizeof(manifest), "%s/manifest.json", compiled);
        CHECK(maelys_git_policy_open(manifest, out_compiled, &error) == MAELYS_GIT_OK);
    }
    maelys_git_gitolite_migration_result_clear(&migration);
    if (mg_migrate_gitolite_grants(input, grants, 1, &migration, &error) != MAELYS_GIT_OK) {
        (void)fprintf(stderr, "%s: grants migration: %s\n", name, error.message);
        maelys_git_gitolite_migration_result_clear(&migration);
        return 0;
    }
    maelys_git_gitolite_migration_result_clear(&migration);
    (void)snprintf(manifest, sizeof(manifest), "%s/manifest.json", grants);
    (void)snprintf(snapshot, sizeof(snapshot), "%s/grants.json", grants);
    if (mg_policy_open_grants(manifest, snapshot, out_grants, &error) != MAELYS_GIT_OK) {
        (void)fprintf(stderr, "%s: open grants: %s\n", name, error.message);
        return 0;
    }
    return 1;
}

/* The outcome of a request, as the differential test writes it; *capacity
 * when it failed for a capacity. */
static void outcome_of(maelys_git_policy_t *policy, const maelys_git_policy_request_t *request, char *out,
                       size_t size, int *failed, maelys_git_error_t *out_error) {
    maelys_git_policy_decision_t decision;
    maelys_git_error_t error;
    maelys_git_result_t result = maelys_git_policy_authorize(policy, request, &decision, &error);
    *failed = result != MAELYS_GIT_OK;
    if (out_error) *out_error = error;
    if (result != MAELYS_GIT_OK) {
        (void)snprintf(out, size, "error=%s kind=%s budget=%s", maelys_git_result_name(result),
                       maelys_git_failure_kind_name(error.detail.kind), error.detail.budget);
        return;
    }
    (void)snprintf(out, size, "allowed=%d explicit=%d reason=%s", decision.allowed, decision.explicit_deny,
                   decision.reason);
}

/* ---- identity ------------------------------------------------------------ */

/* Test 1, the preflight: the session fingerprint of a policy is the SHA-256
 * of its source bytes, for a written policy and for the program. */
static int test_identity(void) {
    static const char source[] = "allow(R) :- request(R), user(\"alice\").\n";
    const char *const sources[] = {source};
    const char *manifest = write_set("identity", 1u, sources);
    maelys_git_policy_t *policy = NULL;
    maelys_git_error_t error;
    CHECK(manifest && maelys_git_policy_open(manifest, &policy, &error) == MAELYS_GIT_OK);
    maelys_git_policy_request_t request = {.request_id = "i", .principal = "alice", .repository = "a.git",
                                           .operation = "read"};
    maelys_git_policy_decision_t decision;
    CHECK(maelys_git_policy_authorize(policy, &request, &decision, &error) == MAELYS_GIT_OK && decision.allowed);
    char digest[MAELYS_CLI_SHA256_HEX_SIZE];
    maelys_cli_sha256_hex(source, strlen(source), digest);
    CHECK(!strcmp(decision.session_fingerprint, digest));
    maelys_git_policy_close(policy);

    size_t length = 0u;
    const char *program = mg_gitolite_program_text(&length);
    CHECK(length == strlen(program) && strstr(program, MG_GITOLITE_PROGRAM_FORMAT));
    maelys_cli_sha256_hex(program, length, digest);
    CHECK(!strcmp(digest, mg_gitolite_program_sha256()));
    const char *const program_only[] = {program};
    manifest = write_set("identity-program", 1u, program_only);
    const char *grants = write_grants("identity-grants",
        "{\"access\":[[\"user\",\"alice\",\"a.git\",\"R\"]],\"format\":\"maelys-git-grants/1\",\"members\":[],"
        "\"namespace_creators\":[],\"nested\":[],\"owner_access\":[],\"refs\":[],\"vref_limits\":[],\"vref_names\":[]}");
    CHECK(manifest && grants && mg_policy_open_grants(manifest, grants, &policy, &error) == MAELYS_GIT_OK);
    CHECK(maelys_git_policy_authorize(policy, &request, &decision, &error) == MAELYS_GIT_OK && decision.allowed);
    CHECK(!strcmp(decision.session_fingerprint, mg_gitolite_program_sha256()));
    maelys_git_policy_close(policy);
    return 1;
}

/* ---- the audited consumer -------------------------------------------------- */

static const char k_reads_slice[] =
    "allow(R) :- request(R), user(U), repository(P), slice_access(U, P, \"R\").\n";
static const char k_hand_deny_bob[] = "deny(R) :- request(R), user(\"bob\").\n";
static const char k_hand_allow_carol[] = "allow(R) :- request(R), user(\"carol\"), operation(\"read\").\n";

static int open_refused(const char *manifest, const char *grants, const char *expected) {
    maelys_git_policy_t *policy = NULL;
    maelys_git_error_t error;
    maelys_git_result_t result = grants ? mg_policy_open_grants(manifest, grants, &policy, &error)
                                        : maelys_git_policy_open(manifest, &policy, &error);
    CHECK(result == MAELYS_GIT_ERR_POLICY && policy == NULL);
    if (!strstr(error.message, expected)) {
        (void)fprintf(stderr, "refusal: %s\n", error.message);
        return 0;
    }
    return 1;
}

static const char *g_failing_name;

static maelys_datalog_status_t failing_reads(const maelys_datalog_policy_t *policy, size_t index,
                                             const char *name, size_t arity, int *out_reads) {
    if (!strcmp(name, g_failing_name)) {
        *out_reads = 0;
        return MAELYS_DATALOG_STATUS_INTERNAL;
    }
    return maelys_datalog_policy_reads_predicate(policy, index, name, arity, out_reads);
}

/* Tests 2 and 13: who may read slice_*, and with what. */
static int test_audited_consumer(void) {
    const char *grants = write_grants("consumer-grants", EMPTY_GRANTS);
    CHECK(grants);
    size_t length = 0u;
    const char *program = mg_gitolite_program_text(&length);
    /* A written policy that reads slice_access, with or without a snapshot. */
    const char *const reader[] = {k_reads_slice};
    const char *manifest = write_set("consumer-reader", 1u, reader);
    CHECK(manifest && open_refused(manifest, grants, "is not the audited Gitolite program"));
    CHECK(open_refused(manifest, NULL, "is not the audited Gitolite program"));
    /* The program changed by one byte. */
    char *changed = strdup(program);
    CHECK(changed);
    changed[2] = changed[2] == 'm' ? 'M' : 'm';
    const char *const changed_only[] = {changed};
    manifest = write_set("consumer-changed", 1u, changed_only);
    free(changed);
    CHECK(manifest && open_refused(manifest, grants, "is not the audited Gitolite program"));
    /* The program: accepted with a snapshot, refused without one, naming
     * --grants; beside a written policy that does not read slice_*. */
    const char *const mixed[] = {program, k_hand_deny_bob};
    manifest = write_set("consumer-mixed", 2u, mixed);
    maelys_git_policy_t *policy = NULL;
    maelys_git_error_t error;
    CHECK(manifest && mg_policy_open_grants(manifest, grants, &policy, &error) == MAELYS_GIT_OK);
    CHECK(mg_policy_grants_sha256(policy) && strlen(mg_policy_grants_sha256(policy)) == 64u);
    maelys_git_policy_close(policy);
    CHECK(open_refused(manifest, NULL, "--grants"));
    /* A snapshot for a set without the program. */
    const char *const hand[] = {k_hand_deny_bob};
    manifest = write_set("consumer-hand", 1u, hand);
    CHECK(manifest && open_refused(manifest, grants, "no policy of the set is the audited Gitolite program"));
    CHECK(maelys_git_policy_open(manifest, &policy, &error) == MAELYS_GIT_OK);
    maelys_git_policy_close(policy);
    /* A failed answer of the engine reads: the written policy is refused. */
    g_failing_name = "slice_vref_name";
    CHECK(mg_policy_open_with(manifest, NULL, failing_reads, &policy, &error) == MAELYS_GIT_ERR_POLICY);
    CHECK(strstr(error.message, "is not the audited Gitolite program"));
    return 1;
}

/* Test 2bis: the program and a written policy in one manifest. Their
 * decisions combine as before, the written deny wins, and the written
 * policy receives the context alone. */
static int test_mixed_routing(void) {
    const char *grants = write_grants("mixed-grants",
        "{\"access\":[[\"user\",\"alice\",\"a.git\",\"RW\"],[\"user\",\"bob\",\"a.git\",\"RW\"]],"
        "\"format\":\"maelys-git-grants/1\",\"members\":[[\"alice\",\"devs\"]],\"namespace_creators\":[],"
        "\"nested\":[],\"owner_access\":[],\"refs\":[],\"vref_limits\":[],\"vref_names\":[]}");
    const char *program = mg_gitolite_program_text(NULL);
    const char *const sources[] = {program, k_hand_deny_bob, k_hand_allow_carol};
    const char *manifest = write_set("mixed", 3u, sources);
    const char *const hand_sources[] = {k_hand_deny_bob, k_hand_allow_carol};
    char hand_manifest[512];
    CHECK(grants && manifest);
    (void)snprintf(hand_manifest, sizeof(hand_manifest), "%s", manifest);
    const char *hand_only = write_set("mixed-hand", 2u, hand_sources);
    CHECK(hand_only);
    maelys_git_policy_t *policy = NULL, *hand = NULL;
    maelys_git_error_t error;
    CHECK(mg_policy_open_grants(hand_manifest, grants, &policy, &error) == MAELYS_GIT_OK);
    CHECK(maelys_git_policy_open(hand_only, &hand, &error) == MAELYS_GIT_OK);
    maelys_git_policy_request_t request = {.request_id = "m", .principal = "alice", .repository = "a.git",
                                           .operation = "write"};
    maelys_git_policy_decision_t decision;
    CHECK(maelys_git_policy_authorize(policy, &request, &decision, &error) == MAELYS_GIT_OK);
    CHECK(decision.allowed && decision.matched_policy == 0u);
    size_t context = 0u, slice = 0u;
    mg_policy_slice_counts(policy, &context, &slice);
    CHECK(context > 0u && slice == 2u); /* slice_member and slice_access */
    CHECK(mg_policy_entry_facts(policy, 0u) == context + slice);
    CHECK(mg_policy_entry_facts(policy, 1u) == context && mg_policy_entry_facts(policy, 2u) == context);
    /* The receipt counts the context, as for the written policies alone. */
    maelys_git_receipt_t receipt, hand_receipt;
    CHECK(maelys_git_policy_authorize_receipt(policy, &request, MAELYS_GIT_EXPLAIN_NEVER, NULL, 0u, &decision,
                                              &receipt, &error) == MAELYS_GIT_OK);
    CHECK(maelys_git_policy_authorize_receipt(hand, &request, MAELYS_GIT_EXPLAIN_NEVER, NULL, 0u, &decision,
                                              &hand_receipt, &error) == MAELYS_GIT_OK);
    CHECK(receipt.edb_facts == context && hand_receipt.edb_facts == context);
    /* bob: the program allows, the written policy denies, and wins. */
    request.principal = "bob";
    CHECK(maelys_git_policy_authorize(policy, &request, &decision, &error) == MAELYS_GIT_OK);
    CHECK(!decision.allowed && decision.explicit_deny && decision.matched_policy == 1u);
    /* carol: nothing in the snapshot, a written allow. */
    request.principal = "carol";
    request.operation = "read";
    CHECK(maelys_git_policy_authorize(policy, &request, &decision, &error) == MAELYS_GIT_OK);
    CHECK(decision.allowed && decision.matched_policy == 2u);
    mg_policy_slice_counts(policy, &context, &slice);
    CHECK(slice == 0u);
    maelys_git_policy_close(policy);
    maelys_git_policy_close(hand);
    return 1;
}

/* ---- the fixed program ------------------------------------------------------ */

/* Test 3: two configurations that differ only by their grants give the same
 * program, the same manifest and the same fingerprints; their snapshots
 * differ. Every rule of the program that reads slice_* binds the user. */
static int test_fixed_program(void) {
    maelys_git_policy_t *compiled = NULL, *first = NULL, *second = NULL;
    CHECK(migrate_both("fixed-1", "@devs = alice\nrepo a\n    RW = @devs\n", &compiled, &first));
    maelys_git_policy_close(compiled);
    CHECK(migrate_both("fixed-2", "repo b c\n    R = bob\n    RW+ refs/heads/x = carol\n", &compiled, &second));
    maelys_git_policy_close(compiled);
    char a[65], b[65];
    maelys_git_error_t error;
    CHECK(maelys_git_policy_fingerprint(first, a, &error) == MAELYS_GIT_OK);
    CHECK(maelys_git_policy_fingerprint(second, b, &error) == MAELYS_GIT_OK);
    CHECK(!strcmp(a, b));
    CHECK(strcmp(mg_policy_grants_sha256(first), mg_policy_grants_sha256(second)) != 0);
    maelys_git_policy_close(first);
    maelys_git_policy_close(second);
    static const char *const files[] = {"gitolite-migrated.dl", "manifest.json"};
    for (size_t i = 0u; i < 2u; ++i) {
        char path[512];
        (void)snprintf(path, sizeof(path), "%s/fixed-1-grants/%s", g_root, files[i]);
        char *one = read_file(path, NULL);
        (void)snprintf(path, sizeof(path), "%s/fixed-2-grants/%s", g_root, files[i]);
        char *two = read_file(path, NULL);
        int same = one && two && !strcmp(one, two);
        if (i == 0u) same = same && !strcmp(one, mg_gitolite_program_text(NULL));
        free(one);
        free(two);
        CHECK(same);
    }
    /* The restriction principle, on the program's text. */
    char *text = strdup(mg_gitolite_program_text(NULL));
    CHECK(text);
    size_t readers = 0u;
    for (char *line = text; line && *line;) {
        char *end = strchr(line, '\n');
        if (end) *end = '\0';
        const char *neck = strstr(line, " :- ");
        if (neck && strstr(neck, "slice_")) {
            ++readers;
            if (!strstr(neck, "user(U)")) {
                (void)fprintf(stderr, "unrestricted rule: %s\n", line);
                free(text);
                return 0;
            }
        }
        line = end ? end + 1 : NULL;
    }
    free(text);
    CHECK(readers == 27u);
    return 1;
}

/* The snapshot a migration writes: canonical bytes the reader accepts, the
 * tuples of every kind of grant, nothing of the compiled form. */
static int test_written_snapshot(void) {
    maelys_git_policy_t *compiled = NULL, *grants = NULL;
    CHECK(migrate_both("written",
        "@juniors = alice\n@devs = @juniors bob\n@creators = carol\n"
        "repo app\n    R = guest\n    RW+ = @devs\n    RW refs/heads/release/ = dave\n"
        "    - refs/heads/main = mallory\n    RW refs/heads/main$ = erin\n"
        "    - VREF/NAME/Makefile = @juniors\n    - VREF/COUNT/5 = alice\n"
        "    - VREF/COUNT/2/NEWFILES = @juniors\n    - VREF/MAX_NEWBIN_SIZE/1024 = bob\n"
        "repo users/CREATOR/..*\n    C = @creators\n    RW+ = CREATOR\n", &compiled, &grants));
    maelys_git_policy_close(compiled);
    maelys_git_policy_close(grants);
    char path[512];
    (void)snprintf(path, sizeof(path), "%s/written-grants/grants.json", g_root);
    size_t size = 0u;
    char *bytes = read_file(path, &size);
    CHECK(bytes);
    static const char expected[] =
        "{\"access\":[[\"group\",\"devs\",\"app.git\",\"RW+\"],[\"user\",\"guest\",\"app.git\",\"R\"]],"
        "\"format\":\"maelys-git-grants/1\","
        "\"members\":[[\"alice\",\"juniors\"],[\"bob\",\"devs\"],[\"carol\",\"creators\"]],"
        "\"namespace_creators\":[[\"group\",\"creators\",\"users\"]],"
        "\"nested\":[[\"juniors\",\"devs\"]],"
        "\"owner_access\":[[\"users\",\"RW+\"]],"
        "\"refs\":[[\"user\",\"dave\",\"app.git\",\"prefix\",\"refs/heads/release/\",\"RW\"],"
        "[\"user\",\"erin\",\"app.git\",\"exact\",\"refs/heads/main\",\"RW\"],"
        "[\"user\",\"mallory\",\"app.git\",\"prefix\",\"refs/heads/main\",\"-\"]],"
        "\"vref_limits\":[[\"group\",\"juniors\",\"app.git\",\"new_count\",2],"
        "[\"user\",\"alice\",\"app.git\",\"count\",5],[\"user\",\"bob\",\"app.git\",\"max_new_binary\",1024]],"
        "\"vref_names\":[[\"group\",\"juniors\",\"app.git\",\"Makefile\"]]}";
    int same = size == sizeof(expected) - 1u && !memcmp(bytes, expected, size);
    if (!same) (void)fprintf(stderr, "written snapshot:\n%s\n", bytes);
    mg_grants_t *parsed = NULL;
    maelys_git_error_t error;
    CHECK(same && mg_grants_parse(bytes, size, &parsed, &error) == MAELYS_GIT_OK);
    mg_grants_free(parsed);
    free(bytes);
    return 1;
}

/* ---- parity with the compiled encoding --------------------------------------- */

typedef struct {
    size_t compared, both_failed, disagreements, allowed, explicit_denials;
} parity_t;

static int compare_request(const char *label, maelys_git_policy_t *compiled, maelys_git_policy_t *grants,
                           const maelys_git_policy_request_t *request, parity_t *parity) {
    char a[512], b[512];
    int a_failed = 0, b_failed = 0;
    outcome_of(compiled, request, a, sizeof(a), &a_failed, NULL);
    outcome_of(grants, request, b, sizeof(b), &b_failed, NULL);
    if (a_failed || b_failed) {
        /* Parity holds where both encodings decide. */
        ++parity->both_failed;
        return 1;
    }
    ++parity->compared;
    parity->allowed += strncmp(a, "allowed=1", 9u) == 0;
    parity->explicit_denials += strstr(a, "explicit=1") != NULL;
    if (strcmp(a, b) != 0) {
        ++parity->disagreements;
        (void)fprintf(stderr, "%s %s %s %s %s: compiled %s, grants %s\n", label, request->principal,
                      request->repository, request->operation, request->ref_name ? request->ref_name : "-", a, b);
        return 0;
    }
    return 1;
}

static const char *const k_users[] = {"u0", "u1", "u2", "u3", "u4", "u5", "zed", NULL};
static const char *const k_repositories[] = {"r0.git", "r1.git", "r2.git", "users/u0/x.git",
                                             "users/u1/x.git", "users/u0/x/y.git", NULL};
static const char *const k_refs[] = {
    "-", "refs/heads/main", "refs/heads/main2", "refs/heads/release", "refs/heads/release/1.0",
    "refs/heads/releases", "refs/tags/v1", "refs/heads/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/x", NULL};

/* Every request of the grid on both encodings. */
static int compare_grid(const char *label, maelys_git_policy_t *compiled, maelys_git_policy_t *grants,
                        const char *const *users, const char *const *repositories, const char *const *refs,
                        parity_t *parity) {
    static const char *const plain[] = {"read", "write", "create"};
    static const char *const on_ref[] = {"merge", "update-ref"};
    static const char *const kinds[] = {"create", "fast_forward", "force", "delete"};
    for (const char *const *user = users; *user; ++user) {
        for (const char *const *repository = repositories; *repository; ++repository) {
            for (size_t o = 0u; o < 3u; ++o) {
                maelys_git_policy_request_t request = {.request_id = "p", .principal = *user,
                                                       .repository = *repository, .operation = plain[o]};
                CHECK(compare_request(label, compiled, grants, &request, parity));
            }
            maelys_git_policy_request_t summary = {
                .request_id = "p", .principal = *user, .repository = *repository, .operation = "push",
                .has_summary = 1, .changed_count = 3u, .added_count = 2u, .modified_count = 1u, .commit_count = 1u};
            CHECK(compare_request(label, compiled, grants, &summary, parity));
            for (const char *const *ref = refs; *ref; ++ref) {
                const char *ref_name = strcmp(*ref, "-") ? *ref : NULL;
                for (size_t o = 0u; o < 2u; ++o) {
                    maelys_git_policy_request_t request = {.request_id = "p", .principal = *user,
                                                           .repository = *repository, .operation = on_ref[o],
                                                           .ref_name = ref_name};
                    CHECK(compare_request(label, compiled, grants, &request, parity));
                }
                for (size_t k = 0u; k < 4u; ++k) {
                    maelys_git_policy_request_t request = {.request_id = "p", .principal = *user,
                                                           .repository = *repository, .operation = "push",
                                                           .ref_name = ref_name, .update_kind = kinds[k],
                                                           .ref_kind = ref_name ? "branch" : NULL};
                    CHECK(compare_request(label, compiled, grants, &request, parity));
                }
            }
            static const char *const paths[] = {"Makefile", "src/a.c", "a.bin"};
            for (size_t p = 0u; p < 3u; ++p) {
                const char *path[1] = {paths[p]};
                maelys_git_policy_request_t request = {
                    .request_id = "p", .principal = *user, .repository = *repository, .operation = "push",
                    .ref_name = "refs/heads/main", .update_kind = "fast_forward", .paths = path,
                    .path_count = 1u, .has_change_details = 1, .change_kind = "added", .change_binary = p == 2u,
                    .change_blob_size = p == 2u ? 4096u : 10u};
                CHECK(compare_request(label, compiled, grants, &request, parity));
            }
        }
    }
    return 1;
}

static uint64_t g_seed;

static unsigned next_random(unsigned bound) {
    g_seed = g_seed * 6364136223846793005ull + 1442695040888963407ull;
    return (unsigned)((g_seed >> 33) % bound);
}

static void append(char *text, size_t size, const char *piece) {
    size_t used = strlen(text);
    (void)snprintf(text + used, size - used, "%s", piece);
}

/* A configuration of the supported subset: nested groups, plain grants,
 * exact and prefix refs, bare and anchored denies, VREFs, and a CREATOR
 * namespace. */
static void random_configuration(char *text, size_t size) {
    static const char *const users[] = {"u0", "u1", "u2", "u3", "u4", "u5"};
    static const char *const levels[] = {"R", "RW", "RW+", "C"};
    static const char *const ref_rules[] = {
        "RW refs/heads/main", "RW+ refs/heads/main", "RW refs/heads/release/", "RW+ refs/heads/release/",
        "RW refs/tags/", "RW refs/heads/main$", "- refs/heads/main", "- refs/heads/release/",
        "- refs/heads/release", "- refs/heads/main$", "RW refs/heads/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/",
        "- VREF/NAME/Makefile", "- VREF/COUNT/2", "- VREF/COUNT/1/NEWFILES", "- VREF/MAX_NEWBIN_SIZE/100"};
    char line[256], subject[16];
    text[0] = '\0';
    for (unsigned g = 0u; g < 4u; ++g) {
        (void)snprintf(line, sizeof(line), "@g%u =", g);
        append(text, size, line);
        for (unsigned k = 0u, n = 1u + next_random(3u); k < n; ++k) {
            if (g > 0u && next_random(3u) == 0u) (void)snprintf(line, sizeof(line), " @g%u", next_random(g));
            else (void)snprintf(line, sizeof(line), " %s", users[next_random(6u)]);
            append(text, size, line);
        }
        append(text, size, "\n");
    }
    for (unsigned r = 0u; r < 3u; ++r) {
        (void)snprintf(line, sizeof(line), "repo r%u\n", r);
        append(text, size, line);
        for (unsigned k = 0u, n = 2u + next_random(5u); k < n; ++k) {
            if (next_random(2u)) (void)snprintf(subject, sizeof(subject), "@g%u", next_random(4u));
            else (void)snprintf(subject, sizeof(subject), "%s", users[next_random(6u)]);
            const char *right = next_random(2u) ? levels[next_random(4u)] : ref_rules[next_random(15u)];
            (void)snprintf(line, sizeof(line), "    %s = %s\n", right, subject);
            append(text, size, line);
        }
    }
    if (next_random(2u)) {
        (void)snprintf(line, sizeof(line), "repo users/CREATOR/..*\n    C = @g%u\n    %s = CREATOR\n",
                       next_random(4u), levels[next_random(3u)]);
        append(text, size, line);
    }
}

/* Test 4: the decisions of the grants as data equal those of the compiled
 * encoding, on random configurations at a fixed seed, wherever both decide;
 * and on the corpus of ref patterns at their boundaries (test 5). */
static int test_parity(void) {
    parity_t parity = {0};
    g_seed = 20261022u;
    size_t configurations = 0u;
    for (unsigned i = 0u; i < 40u; ++i) {
        char text[8192], name[32];
        random_configuration(text, sizeof(text));
        (void)snprintf(name, sizeof(name), "random-%u", i);
        maelys_git_policy_t *compiled = NULL, *grants = NULL;
        CHECK(migrate_both(name, text, &compiled, &grants));
        if (compiled) {
            ++configurations;
            if (!compare_grid(name, compiled, grants, k_users, k_repositories, k_refs, &parity)) {
                (void)fprintf(stderr, "configuration %s:\n%s", name, text);
                return 0;
            }
        }
        maelys_git_policy_close(compiled);
        maelys_git_policy_close(grants);
    }
    /* Ref patterns at their boundaries: '/' boundaries, a prefix equal to
     * the ref, deep and long prefixes the compiled form writes as rules. */
    char deep[300] = "refs/heads/", long_prefix[300] = "refs/heads/";
    for (int i = 0; i < 17; ++i) (void)strcat(deep, "d/");
    while (strlen(long_prefix) < 255u) (void)strcat(long_prefix, "l");
    (void)strcat(long_prefix, "/");
    char boundaries[2048];
    (void)snprintf(boundaries, sizeof(boundaries),
        "repo r0\n    RW refs/heads/release/ = u0\n    RW+ %s = u1\n    RW %s = u2\n"
        "    - refs/heads/rel = u3\n    RW+ = u3\n    RW refs/heads/main = u4\n    - refs/heads/main$ = u5\n"
        "    RW+ = u5\n", deep, long_prefix);
    char deep_ref[320], long_ref[320];
    (void)snprintf(deep_ref, sizeof(deep_ref), "%sx", deep);
    (void)snprintf(long_ref, sizeof(long_ref), "%sx", long_prefix);
    const char *const refs[] = {"-", "refs/heads/release/1", "refs/heads/release", "refs/heads/releases",
                                "refs/heads/rel", "refs/heads/rel/x", "refs/heads/main", "refs/heads/main/x",
                                "refs/heads/mainx", deep_ref, long_ref, NULL};
    const char *const repositories[] = {"r0.git", NULL};
    maelys_git_policy_t *compiled = NULL, *grants = NULL;
    CHECK(migrate_both("boundaries", boundaries, &compiled, &grants) && compiled);
    CHECK(compare_grid("boundaries", compiled, grants, k_users, repositories, refs, &parity));
    maelys_git_policy_close(compiled);
    maelys_git_policy_close(grants);
    CHECK(configurations >= 30u && parity.disagreements == 0u && parity.compared > 50000u);
    /* Both kinds of decision are exercised, not only denials by default. */
    CHECK(parity.allowed > parity.compared / 20u && parity.explicit_denials > parity.compared / 200u);
    (void)printf("parity: %zu configurations, %zu requests decided alike (%zu allowed, %zu explicitly denied), "
                 "%zu not decided by both\n", configurations + 1u, parity.compared, parity.allowed,
                 parity.explicit_denials, parity.both_failed);
    return 1;
}

/* ---- counterexamples ------------------------------------------------------------- */

static mg_slice_predicate_t g_dropped;
static const char *g_dropped_level;

static int drop_predicate(const mg_slice_fact_t *fact, void *context) {
    (void)context;
    if (fact->predicate != g_dropped) return 1;
    return g_dropped_level && strcmp(fact->text[2], g_dropped_level) != 0;
}

/* The outcome of REQUEST on GRANTS with and without the facts the filter
 * drops; the oracle is the compiled encoding. */
static int counterexample(const char *name, const char *configuration, const maelys_git_policy_request_t *request,
                          mg_slice_predicate_t dropped, const char *level) {
    maelys_git_policy_t *compiled = NULL, *grants = NULL;
    CHECK(migrate_both(name, configuration, &compiled, &grants) && compiled);
    char expected[512], whole[512], damaged[512];
    int failed = 0;
    outcome_of(compiled, request, expected, sizeof(expected), &failed, NULL);
    CHECK(!failed);
    outcome_of(grants, request, whole, sizeof(whole), &failed, NULL);
    CHECK(!failed && !strcmp(whole, expected));
    g_dropped = dropped;
    g_dropped_level = level;
    mg_policy_set_slice_filter(grants, drop_predicate, NULL);
    outcome_of(grants, request, damaged, sizeof(damaged), &failed, NULL);
    CHECK(!failed && strcmp(damaged, expected) != 0);
    maelys_git_policy_close(compiled);
    maelys_git_policy_close(grants);
    return 1;
}

/* §5.3: each slice that misses what the definition puts in it decides
 * otherwise than the compiled encoding. */
static int test_counterexamples(void) {
    /* Without slice_ref_level, a ref grant no longer gives write. */
    maelys_git_policy_request_t write = {.request_id = "c", .principal = "alice", .repository = "app.git",
                                         .operation = "write"};
    CHECK(counterexample("cx-level", "repo app\n    RW refs/heads/x = alice\n", &write, MG_SLICE_REF_LEVEL, NULL));
    /* Without the matching deny, a denied push passes. */
    maelys_git_policy_request_t push = {.request_id = "c", .principal = "mallory", .repository = "app.git",
                                        .operation = "push", .ref_name = "refs/heads/main",
                                        .update_kind = "fast_forward", .ref_kind = "branch"};
    CHECK(counterexample("cx-deny", "repo app\n    RW+ = mallory\n    - refs/heads/main = mallory\n", &push,
                         MG_SLICE_REF_MATCH, "-"));
    /* Without the VREF name of a pushed path, a denied path passes. */
    const char *path[1] = {"Makefile"};
    maelys_git_policy_request_t vref = {.request_id = "c", .principal = "alice", .repository = "app.git",
                                        .operation = "push", .ref_name = "refs/heads/main",
                                        .update_kind = "fast_forward", .paths = path, .path_count = 1u,
                                        .has_change_details = 1, .change_kind = "modified"};
    CHECK(counterexample("cx-vref", "@juniors = alice\nrepo app\n    RW = alice\n    - VREF/NAME/Makefile = @juniors\n",
                         &vref, MG_SLICE_GROUP_VREF_NAME, NULL));
    /* Without the nesting edges, a group of a group gives nothing. */
    maelys_git_policy_request_t read = {.request_id = "c", .principal = "alice", .repository = "app.git",
                                        .operation = "read"};
    CHECK(counterexample("cx-nested", "@juniors = alice\n@devs = @juniors\nrepo app\n    R = @devs\n", &read,
                         MG_SLICE_NESTED, NULL));
    return 1;
}

/* ---- capacity ------------------------------------------------------------------- */

/* Tests 6bis and 6: the quotas of a user and of its groups stay separate,
 * as in the compiled encoding; one beyond the facts of a predicate is
 * refused whole, with the engine's budget and the predicate, never
 * truncated. */
static int test_quotas(void) {
    maelys_git_policy_budget_t budget;
    maelys_git_error_t error;
    CHECK(mg_policy_budget(NULL, &budget, &error) == MAELYS_GIT_OK);
    size_t limit = budget.derived_per_predicate_limit; /* MAX_FACTS_PER_PRED */
    size_t own = limit / 2u, group = limit - own + 1u;
    size_t size = 64u + (own + group + limit + 1u) * 48u;
    char *text = malloc(size);
    CHECK(text);
    /* own + group thresholds: more than a predicate holds, in two forms. */
    (void)snprintf(text, size, "@juniors = alice\nrepo app\n    RW = alice\n");
    for (size_t i = 0u; i < own; ++i)
        (void)snprintf(text + strlen(text), size - strlen(text), "    - VREF/COUNT/%zu = alice\n", 100u + i);
    for (size_t i = 0u; i < group; ++i)
        (void)snprintf(text + strlen(text), size - strlen(text), "    - VREF/COUNT/%zu = @juniors\n", 100u + i);
    maelys_git_policy_t *compiled = NULL, *grants = NULL;
    CHECK(migrate_both("quotas", text, &compiled, &grants));
    maelys_git_policy_request_t push = {.request_id = "q", .principal = "alice", .repository = "app.git",
                                        .operation = "push", .has_summary = 1, .changed_count = 3u,
                                        .added_count = 1u, .commit_count = 1u};
    maelys_git_policy_decision_t decision;
    CHECK(maelys_git_policy_authorize(grants, &push, &decision, &error) == MAELYS_GIT_OK && decision.allowed);
    size_t context = 0u, slice = 0u;
    mg_policy_slice_counts(grants, &context, &slice);
    CHECK(slice == 1u + 1u + own + group); /* member, access, both thresholds */
    if (compiled) {
        CHECK(maelys_git_policy_authorize(compiled, &push, &decision, &error) == MAELYS_GIT_OK && decision.allowed);
    }
    maelys_git_policy_close(compiled);
    maelys_git_policy_close(grants);
    /* limit + 1 thresholds of alice alone. */
    (void)snprintf(text, size, "repo app\n    RW = alice\n");
    for (size_t i = 0u; i <= limit; ++i)
        (void)snprintf(text + strlen(text), size - strlen(text), "    - VREF/COUNT/%zu = alice\n", 100u + i);
    CHECK(migrate_both("quotas-over", text, &compiled, &grants));
    free(text);
    CHECK(maelys_git_policy_authorize(grants, &push, &decision, &error) == MAELYS_GIT_ERR_POLICY);
    CHECK(error.detail.kind == MAELYS_GIT_FAILURE_CAPACITY && !strcmp(error.detail.budget, "MAX_FACTS_PER_PRED"));
    CHECK(!strcmp(error.detail.diagnostic, "input:slice_vref_count"));
    CHECK(error.detail.requested == limit + 1u && error.detail.limit == limit);
    maelys_git_receipt_t receipt;
    CHECK(maelys_git_policy_authorize_receipt(grants, &push, MAELYS_GIT_EXPLAIN_NEVER, NULL, 0u, &decision,
                                              &receipt, &error) == MAELYS_GIT_ERR_POLICY);
    CHECK(receipt.decision == MAELYS_GIT_RECEIPT_DENY_ERROR && !strcmp(receipt.error_budget, "MAX_FACTS_PER_PRED"));
    /* The compiled encoding holds the whole configuration when it fits. */
    if (limit + 2u <= budget.fact_limit) {
        CHECK(compiled != NULL);
        CHECK(maelys_git_policy_authorize(compiled, &push, &decision, &error) == MAELYS_GIT_OK && decision.allowed);
    }
    /* Another repository: the thresholds are not in its slice. */
    push.repository = "other.git";
    CHECK(maelys_git_policy_authorize(grants, &push, &decision, &error) == MAELYS_GIT_OK && !decision.allowed);
    maelys_git_policy_close(compiled);
    maelys_git_policy_close(grants);
    return 1;
}

/* The engine's own bounds on a slice: strings it cannot pool are a
 * capacity failure of the solve that names its budget, never a truncated
 * slice. */
static int test_engine_bounds(void) {
    char *json = malloc(200000u);
    CHECK(json);
    (void)strcpy(json, "{\"access\":[");
    char name[1001];
    for (int i = 0; i < 64; ++i) {
        (void)snprintf(name, sizeof(name), "%02d", i);
        memset(name + 2, 'g', 997);
        name[999] = '\0';
        (void)snprintf(json + strlen(json), 200000u - strlen(json), "%s[\"group\",\"%s\",\"app.git\",\"R\"]",
                       i ? "," : "", name);
    }
    (void)strcat(json, "],\"format\":\"maelys-git-grants/1\",\"members\":[");
    for (int i = 0; i < 64; ++i) {
        (void)snprintf(name, sizeof(name), "%02d", i);
        memset(name + 2, 'g', 997);
        name[999] = '\0';
        (void)snprintf(json + strlen(json), 200000u - strlen(json), "%s[\"alice\",\"%s\"]", i ? "," : "", name);
    }
    (void)strcat(json, "],\"namespace_creators\":[],\"nested\":[],\"owner_access\":[],\"refs\":[],"
                       "\"vref_limits\":[],\"vref_names\":[]}");
    const char *grants_path = write_grants("pool", json);
    free(json);
    const char *const program[] = {mg_gitolite_program_text(NULL)};
    const char *manifest = write_set("pool-set", 1u, program);
    maelys_git_policy_t *policy = NULL;
    maelys_git_error_t error;
    CHECK(grants_path && manifest && mg_policy_open_grants(manifest, grants_path, &policy, &error) == MAELYS_GIT_OK);
    maelys_git_policy_request_t read = {.request_id = "b", .principal = "alice", .repository = "app.git",
                                        .operation = "read"};
    maelys_git_policy_decision_t decision;
    maelys_git_result_t result = maelys_git_policy_authorize(policy, &read, &decision, &error);
    size_t context = 0u, slice = 0u;
    mg_policy_slice_counts(policy, &context, &slice);
    CHECK(slice == 128u); /* whole: 64 memberships, 64 group grants */
    /* 64 names of 999 bytes do not fit the engine's pool of input text: the
     * request is refused whole, as a capacity that names the bound, the
     * attempted bytes above it (engine 0.26.0). */
    size_t pool = 0u;
    CHECK(maelys_datalog_limit_get(MAELYS_DATALOG_LIMIT_STRING_POOL_BYTES, &pool) == MAELYS_DATALOG_STATUS_OK);
    CHECK(pool < 64u * 1000u);
    CHECK(result == MAELYS_GIT_ERR_POLICY && error.detail.kind == MAELYS_GIT_FAILURE_CAPACITY);
    CHECK(!strcmp(error.detail.budget, "STRING_POOL_BYTES"));
    CHECK(error.detail.limit == pool && error.detail.requested > pool);
    maelys_git_receipt_t receipt;
    CHECK(maelys_git_policy_authorize_receipt(policy, &read, MAELYS_GIT_EXPLAIN_NEVER, NULL, 0u, &decision,
                                              &receipt, &error) == MAELYS_GIT_ERR_POLICY);
    CHECK(receipt.decision == MAELYS_GIT_RECEIPT_DENY_ERROR && !strcmp(receipt.error_kind, "capacity") &&
          !strcmp(receipt.error_budget, "STRING_POOL_BYTES"));
    maelys_git_policy_close(policy);
    return 1;
}

/* Test 7: the stress fixture vref-65 decides, and its slice holds the VREF
 * names of the pushed paths only. */
static int test_vref_filtering(void) {
    char text[4096] = "@juniors = alice\nrepo app\n    RW = alice\n";
    for (int i = 1; i <= 65; ++i)
        (void)snprintf(text + strlen(text), sizeof(text) - strlen(text), "    - VREF/NAME/file%d = @juniors\n", i);
    maelys_git_policy_t *compiled = NULL, *grants = NULL;
    CHECK(migrate_both("vref-65", text, &compiled, &grants));
    const char *path[2] = {"file65", "other"};
    maelys_git_policy_request_t push = {.request_id = "v", .principal = "alice", .repository = "app.git",
                                        .operation = "push", .ref_name = "refs/heads/main",
                                        .update_kind = "fast_forward", .paths = path, .path_count = 2u,
                                        .has_change_details = 1, .change_kind = "modified"};
    maelys_git_policy_decision_t decision;
    maelys_git_error_t error;
    CHECK(maelys_git_policy_authorize(grants, &push, &decision, &error) == MAELYS_GIT_OK && decision.explicit_deny);
    size_t context = 0u, slice = 0u;
    mg_policy_slice_counts(grants, &context, &slice);
    CHECK(slice == 3u); /* member, access, one VREF name */
    push.paths = path + 1;
    push.path_count = 1u;
    CHECK(maelys_git_policy_authorize(grants, &push, &decision, &error) == MAELYS_GIT_OK && decision.allowed);
    maelys_git_policy_close(compiled);
    maelys_git_policy_close(grants);
    return 1;
}

/* §5.4: a configuration beyond the compiled encoding's facts decides as
 * grants; a snapshot beyond its bounds is an unsupported entry. */
static int test_admission(void) {
    char *text = malloc(2u * 1024u * 1024u);
    CHECK(text);
    (void)strcpy(text, "repo app\n");
    for (int i = 1; i <= 129; ++i) (void)snprintf(text + strlen(text), 64u, "    RW = u%d\n", i);
    maelys_git_policy_budget_t budget;
    maelys_git_error_t error;
    CHECK(mg_policy_budget(NULL, &budget, &error) == MAELYS_GIT_OK);
    maelys_git_policy_t *compiled = NULL, *grants = NULL;
    CHECK(migrate_both("admission", text, &compiled, &grants));
    CHECK(budget.fact_limit >= 129u || compiled == NULL);
    maelys_git_policy_close(compiled);
    maelys_git_policy_request_t write = {.request_id = "a", .principal = "u129", .repository = "app.git",
                                         .operation = "write"};
    maelys_git_policy_decision_t decision;
    CHECK(maelys_git_policy_authorize(grants, &write, &decision, &error) == MAELYS_GIT_OK && decision.allowed);
    maelys_git_policy_close(grants);
    /* 65 537 grants: one more than a snapshot holds. */
    (void)strcpy(text, "repo app\n");
    size_t used = strlen(text);
    for (unsigned i = 0u; i <= MG_GRANTS_MAX_TUPLES; ++i)
        used += (size_t)snprintf(text + used, 64u, "    R = u%u\n", i);
    char input[400], output[400];
    (void)snprintf(input, sizeof(input), "%s/too-many.conf", g_root);
    (void)snprintf(output, sizeof(output), "%s/too-many", g_root);
    CHECK(write_text(input, text));
    free(text);
    maelys_git_gitolite_migration_result_t migration;
    CHECK(mg_migrate_gitolite_grants(input, output, 0, &migration, &error) == MAELYS_GIT_OK);
    CHECK(migration.unsupported_count == 1u && strstr(migration.unsupported[0], "grants snapshot refused"));
    maelys_git_gitolite_migration_result_clear(&migration);
    CHECK(mg_migrate_gitolite_grants(input, output, 1, &migration, &error) == MAELYS_GIT_ERR_PROTOCOL);
    maelys_git_gitolite_migration_result_clear(&migration);
    struct stat status;
    CHECK(lstat(output, &status) != 0);
    return 1;
}

int main(void) {
    char template[] = "/tmp/maelys_git_gitolite_program_XXXXXX";
    char *root = mkdtemp(template);
    if (!root) return 1;
    (void)snprintf(g_root, sizeof(g_root), "%s", root);
    int ok = test_identity() && test_audited_consumer() && test_mixed_routing() && test_fixed_program() &&
             test_written_snapshot() && test_counterexamples() && test_quotas() && test_engine_bounds() &&
             test_vref_filtering() && test_admission() && test_parity();
    if (!test_remove_tree(g_root)) ok = 0;
    if (ok) puts("audited Gitolite program: identity, consumer, routing, parity: ok");
    return ok ? 0 : 1;
}
