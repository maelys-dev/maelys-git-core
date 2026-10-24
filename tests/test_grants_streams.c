/* A snapshot of grants in use (GIT-C06, D4 and 4.4): read again before each
 * command of a stream, one generation per command, and the precondition of
 * pr merge on the grants its plan saw.
 *   test 9   a stream sees a replacement, an in-place rewrite of the same
 *            length and date, refuses a file changed while it was read and
 *            an invalid one, until a reading succeeds, never the former one;
 *   test 10  a push of several refs decides on the snapshot read before it;
 *   test 11  pr merge refuses grants changed since its plan, applies when
 *            they did not change, and the entry points that predate grants
 *            refuse to apply with them. */
#include "agent/agent_internal.h"
#include "maelys_git.h"
#include "policy/grants.h"
#include "policy/policy_grants.h"
#include "policy/program.h"
#include "test_json.h"
#include "test_support.h"

#include <maelys/cli/digest.h>

#include <sys/time.h>

static char g_root[256];
static char g_manifest[512], g_grants[512];

static int write_file(const char *path, const char *text) {
    FILE *file = fopen(path, "w");
    if (!file) return 0;
    int ok = fputs(text, file) >= 0;
    return fclose(file) == 0 && ok;
}

/* A snapshot giving each principal of USERS (comma-separated) RW on r.git,
 * in its canonical form. */
static void snapshot_text(const char *users, char *out, size_t size) {
    char access[1024] = "";
    char copy[256];
    (void)snprintf(copy, sizeof(copy), "%s", users);
    for (char *save = NULL, *user = strtok_r(copy, ",", &save); user; user = strtok_r(NULL, ",", &save)) {
        size_t used = strlen(access);
        (void)snprintf(access + used, sizeof(access) - used, "%s[\"user\",\"%s\",\"r.git\",\"RW\"]",
                       used ? "," : "", user);
    }
    (void)snprintf(out, size,
                   "{\"access\":[%s],\"format\":\"maelys-git-grants/1\",\"members\":[],\"namespace_creators\":[],"
                   "\"nested\":[],\"owner_access\":[],\"refs\":[],\"vref_limits\":[],\"vref_names\":[]}",
                   access);
}

/* Publishes a snapshot as the contract says: a new file renamed over the
 * published one. */
static int publish(const char *text) {
    char temporary[600];
    (void)snprintf(temporary, sizeof(temporary), "%s.new", g_grants);
    return write_file(temporary, text) && rename(temporary, g_grants) == 0;
}

static int publish_users(const char *users) {
    char text[2048];
    snapshot_text(users, text, sizeof(text));
    return publish(text);
}

static void sha_of(const char *text, char out[65]) {
    maelys_cli_sha256_hex(text, strlen(text), out);
}

static int setup(void) {
    char path[512], manifest[2048], digest[MAELYS_CLI_SHA256_HEX_SIZE];
    size_t length = 0u;
    const char *program = mg_gitolite_program_text(&length);
    maelys_cli_sha256_hex(program, length, digest);
    (void)snprintf(path, sizeof(path), "%s/program.dl", g_root);
    CHECK(write_file(path, program));
    (void)snprintf(manifest, sizeof(manifest),
        "{\"policy_set_id\":\"test.streams\",\"policy_set_version\":\"1\",\"manifest_version\":\"1\","
        "\"default_profile\":\"enforce\",\"created_for\":\"maelys-git-core-tests\",\"strict_loading\":true,"
        "\"fail_closed\":true,\"capabilities\":[],\"policies\":[{\"policy_id\":\"maelys-git.gitolite.authorization\","
        "\"domain\":\"maelys_git\",\"file\":\"program.dl\",\"sha256\":\"%s\",\"mode\":\"enforce\","
        "\"enabled\":true,\"description\":\"test\","
        "\"queries\":[{\"name\":\"allow\",\"arity\":1},{\"name\":\"deny\",\"arity\":1}]}]}\n", digest);
    (void)snprintf(g_manifest, sizeof(g_manifest), "%s/manifest.json", g_root);
    (void)snprintf(g_grants, sizeof(g_grants), "%s/grants.json", g_root);
    CHECK(write_file(g_manifest, manifest));
    return publish_users("alice");
}

/* ---- test 9: a stream ---------------------------------------------------------- */

/* One authorize command of alice on r.git through the executor: its status,
 * whether it was allowed and the grants its receipt names. */
typedef struct {
    char status[16];
    int allowed;
    char grants[65];
    char message[512];
} outcome_t;

static int run_command(maelys_git_policy_t *policy, int number, outcome_t *out) {
    char id[32];
    (void)snprintf(id, sizeof(id), "c%d", number);
    mg_json_t json;
    mg_json_begin(&json, MG_JSON_DATA);
    mg_json_object(&json, NULL);
    mg_json_string(&json, "protocol", MAELYS_GIT_AGENT_PROTOCOL);
    mg_json_string(&json, "message_id", id);
    mg_json_string(&json, "agent_id", "agent-1");
    mg_json_string(&json, "type", "command");
    mg_json_string(&json, "command", "authorize");
    mg_json_string(&json, "principal", "alice");
    mg_json_string(&json, "repository", "r.git");
    mg_json_i64(&json, "issued_at_ms", (int64_t)mg_now_ms());
    mg_json_i64(&json, "expires_at_ms", (int64_t)(mg_now_ms() + 60000));
    mg_json_object(&json, "payload");
    mg_json_string(&json, "operation", "write");
    mg_json_end_object(&json);
    mg_json_end_object(&json);
    char *raw = NULL;
    CHECK(mg_json_finish(&json, &raw, NULL) == MAELYS_JSON_OK);
    mg_agent_message_t message;
    maelys_git_error_t error = {0};
    CHECK(mg_protocol_parse(raw, strlen(raw), &message, &error) == MAELYS_GIT_OK);
    free(raw);
    char *result = NULL;
    CHECK(mg_executor_execute(policy, "/usr/bin/git", g_root, &message, MAELYS_GIT_EXPLAIN_NEVER, &result,
                              &error) == MAELYS_GIT_OK);
    mg_protocol_message_clear(&message);
    maelys_json_document_t *document = tj_parse(result);
    free(result);
    CHECK(document != NULL);
    memset(out, 0, sizeof(*out));
    const char *status = tj_string(document, "status");
    CHECK(status != NULL);
    (void)snprintf(out->status, sizeof(out->status), "%s", status);
    out->allowed = tj_boolean(document, "payload.allowed") == 1;
    const char *grants = tj_string(document, "payload.receipt.grants.sha256");
    if (grants) (void)snprintf(out->grants, sizeof(out->grants), "%s", grants);
    const char *text = tj_string(document, "payload.message");
    if (text) (void)snprintf(out->message, sizeof(out->message), "%s", text);
    tj_release(document);
    return 1;
}

static char g_during_read[2048];

/* Rewrites the snapshot in place, its inode kept, while it is being read. */
static void rewrite_in_place(const char *path) {
    FILE *file = fopen(path, "w");
    if (file) {
        (void)fputs(g_during_read, file);
        (void)fclose(file);
    }
}

static int test_stream(void) {
    char text[2048], expected[65];
    CHECK(publish_users("alice"));
    maelys_git_policy_t *policy = NULL;
    maelys_git_error_t error;
    CHECK(maelys_git_policy_open_grants(g_manifest, g_grants, &policy, &error) == MAELYS_GIT_OK);
    outcome_t outcome;
    int n = 0;
    snapshot_text("alice", text, sizeof(text));
    sha_of(text, expected);
    CHECK(run_command(policy, ++n, &outcome) && outcome.allowed && !strcmp(outcome.grants, expected));

    /* A replacement by rename applies to the next command. */
    CHECK(publish_users("bob"));
    snapshot_text("bob", text, sizeof(text));
    sha_of(text, expected);
    CHECK(run_command(policy, ++n, &outcome) && !strcmp(outcome.status, "denied") && !outcome.allowed);
    CHECK(!strcmp(outcome.grants, expected));

    /* An in-place rewrite, finished, of the same length and the same dates:
     * the bytes are what decides, not the metadata. */
    struct stat before;
    CHECK(stat(g_grants, &before) == 0);
    snapshot_text("alice,dan", text, sizeof(text));
    char same_length[2048];
    snapshot_text("alice,bob", same_length, sizeof(same_length));
    CHECK(publish(same_length));
    CHECK(stat(g_grants, &before) == 0);
    CHECK(strlen(text) == strlen(same_length));
    CHECK(write_file(g_grants, text));
    struct timeval times[2] = {{before.st_atime, 0}, {before.st_mtime, 0}};
#ifdef __APPLE__
    times[1].tv_usec = (int)(before.st_mtimespec.tv_nsec / 1000);
#else
    times[1].tv_usec = (suseconds_t)(before.st_mtim.tv_nsec / 1000);
#endif
    CHECK(utimes(g_grants, times) == 0);
    struct stat after;
    CHECK(stat(g_grants, &after) == 0 && after.st_size == before.st_size && after.st_ino == before.st_ino);
    sha_of(text, expected);
    CHECK(run_command(policy, ++n, &outcome) && outcome.allowed && !strcmp(outcome.grants, expected));

    /* A file changed while it is read is refused for that command. */
    snapshot_text("alice,erin", g_during_read, sizeof(g_during_read));
    mg_grants_test_between_reads = rewrite_in_place;
    CHECK(run_command(policy, ++n, &outcome) && !strcmp(outcome.status, "failed"));
    CHECK(strstr(outcome.message, "changed while it was read") != NULL);
    mg_grants_test_between_reads = NULL;
    sha_of(g_during_read, expected);
    CHECK(run_command(policy, ++n, &outcome) && outcome.allowed && !strcmp(outcome.grants, expected));

    /* An invalid file refuses this command and the next, never deciding on
     * the snapshot read before; a corrected file resumes. The slice of the
     * last decision goes with the snapshot its strings belonged to. */
    CHECK(mg_policy_slice_held(policy) > 0u);
    CHECK(publish("{\"format\":\"maelys-git-grants/1\"}"));
    CHECK(run_command(policy, ++n, &outcome) && !strcmp(outcome.status, "failed") && !outcome.allowed);
    CHECK(strncmp(outcome.message, "grants snapshot unavailable: ", 29u) == 0);
    CHECK(mg_policy_slice_held(policy) == 0u);
    CHECK(run_command(policy, ++n, &outcome) && !strcmp(outcome.status, "failed"));
    maelys_git_policy_request_t request = {.request_id = "s", .principal = "alice", .repository = "r.git",
                                           .operation = "write"};
    maelys_git_policy_decision_t decision;
    CHECK(maelys_git_policy_authorize(policy, &request, &decision, &error) == MAELYS_GIT_ERR_POLICY);
    CHECK(publish_users("alice"));
    snapshot_text("alice", text, sizeof(text));
    sha_of(text, expected);
    CHECK(run_command(policy, ++n, &outcome) && outcome.allowed && !strcmp(outcome.grants, expected));
    /* A missing file too. */
    CHECK(unlink(g_grants) == 0);
    CHECK(run_command(policy, ++n, &outcome) && !strcmp(outcome.status, "failed"));
    CHECK(publish_users("alice"));
    CHECK(run_command(policy, ++n, &outcome) && outcome.allowed);
    maelys_git_policy_close(policy);
    return 1;
}

/* GIT-C06 test 12, on the executor's side: a handle given the digest of its
 * snapshot, as the agent starts an executor on a file of its store, refuses
 * other bytes at its opening and at every reading, until the bytes are those. */
static int test_expected_grants(void) {
    char text[2048], alice[65], both[65];
    snapshot_text("alice", text, sizeof(text));
    sha_of(text, alice);
    snapshot_text("alice,bob", text, sizeof(text));
    sha_of(text, both);
    CHECK(publish_users("alice"));
    maelys_git_policy_t *policy = NULL;
    maelys_git_error_t error;
    CHECK(maelys_git_policy_open_grants(g_manifest, g_grants, &policy, &error) == MAELYS_GIT_OK);
    CHECK(mg_policy_expect_grants(policy, both, &error) == MAELYS_GIT_ERR_PROCESS);
    CHECK(strstr(error.message, "is not the expected one") != NULL);
    outcome_t outcome;
    int n = 100;
    CHECK(run_command(policy, ++n, &outcome) && !strcmp(outcome.status, "failed") && !outcome.allowed);
    CHECK(strncmp(outcome.message, "grants snapshot unavailable: ", 29u) == 0);
    CHECK(strstr(outcome.message, "is not the expected one") != NULL);
    CHECK(publish_users("alice,bob"));
    CHECK(run_command(policy, ++n, &outcome) && outcome.allowed && !strcmp(outcome.grants, both));
    /* Other bytes later: refused, the slice of the last decision gone. */
    CHECK(mg_policy_slice_held(policy) > 0u);
    CHECK(publish_users("alice"));
    CHECK(run_command(policy, ++n, &outcome) && !strcmp(outcome.status, "failed") && !outcome.allowed);
    CHECK(strstr(outcome.message, "is not the expected one") != NULL);
    CHECK(mg_policy_slice_held(policy) == 0u);
    /* Only lowercase digests, and only on a handle with a snapshot. */
    CHECK(mg_policy_expect_grants(policy, "ABCDEF", &error) == MAELYS_GIT_ERR_INVALID_ARGUMENT);
    maelys_git_policy_close(policy);
    CHECK(maelys_git_policy_open_grants(g_manifest, g_grants, &policy, &error) == MAELYS_GIT_OK);
    CHECK(mg_policy_expect_grants(policy, alice, &error) == MAELYS_GIT_OK);
    CHECK(run_command(policy, ++n, &outcome) && outcome.allowed && !strcmp(outcome.grants, alice));
    maelys_git_policy_close(policy);
    return 1;
}

static int g_readings;

static void count_reading(const char *path) {
    (void)path;
    ++g_readings;
}

/* A pinned handle decides its first command on the reading its pin
 * verified, without reading the file again; every later command reads it
 * again and refuses other bytes. An unpinned handle reads again before its
 * first command too (D4). */
static int test_pinned_first_read(void) {
    char text[2048], alice[65];
    snapshot_text("alice", text, sizeof(text));
    sha_of(text, alice);
    outcome_t outcome;
    int n = 200;
    for (int pinned = 0; pinned < 2; ++pinned) {
        CHECK(publish_users("alice"));
        maelys_git_policy_t *policy = NULL;
        maelys_git_error_t error;
        CHECK(maelys_git_policy_open_grants(g_manifest, g_grants, &policy, &error) == MAELYS_GIT_OK);
        if (pinned) CHECK(mg_policy_expect_grants(policy, alice, &error) == MAELYS_GIT_OK);
        /* Other bytes published between the opening and the first command. */
        CHECK(publish_users("bob"));
        g_readings = 0;
        mg_grants_test_between_reads = count_reading;
        int first = run_command(policy, ++n, &outcome);
        int first_readings = g_readings;
        outcome_t second;
        int again = run_command(policy, ++n, &second);
        mg_grants_test_between_reads = NULL;
        CHECK(first && again);
        if (pinned) {
            CHECK(first_readings == 0 && outcome.allowed && !strcmp(outcome.grants, alice));
            CHECK(g_readings == 1 && !strcmp(second.status, "failed"));
            CHECK(strstr(second.message, "is not the expected one") != NULL);
        } else {
            CHECK(first_readings == 1 && !strcmp(outcome.status, "denied") && !outcome.allowed);
            CHECK(g_readings == 2);
        }
        maelys_git_policy_close(policy);
    }
    return 1;
}

/* ---- tests 10 and 11: a repository ---------------------------------------------- */

static int git(const char *command, char *out, size_t size) {
    char line[4096];
    (void)snprintf(line, sizeof(line), "GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null %s", command);
    FILE *pipe = popen(line, "r");
    if (!pipe) return 0;
    if (out && size) {
        out[0] = '\0';
        if (fgets(out, (int)size, pipe)) out[strcspn(out, "\n")] = '\0';
    }
    return pclose(pipe) == 0;
}

/* r.git with main at a base commit, and two more commits: topic-a and
 * topic-b, each adding a file; their OIDs. */
static int repository(char base[64], char a[64], char b[64]) {
    char command[1024];
    (void)snprintf(command, sizeof(command), "git init -q --bare %s/r.git", g_root);
    CHECK(git(command, NULL, 0u));
    (void)snprintf(command, sizeof(command), "git --git-dir=%s/r.git fast-import --quiet", g_root);
    FILE *import = popen(command, "w");
    CHECK(import != NULL);
    (void)fprintf(import,
        "blob\nmark :1\ndata 2\nx\n\n"
        "commit refs/heads/main\nmark :2\ncommitter T <t@example.invalid> 1767225600 +0000\n"
        "data 4\nbase\nM 100644 :1 base.txt\n\n"
        "commit refs/import/a\nmark :3\ncommitter T <t@example.invalid> 1767225601 +0000\n"
        "data 2\na\nfrom :2\nM 100644 :1 a.txt\n\n"
        "commit refs/import/b\nmark :4\ncommitter T <t@example.invalid> 1767225602 +0000\n"
        "data 2\nb\nfrom :2\nM 100644 :1 b.txt\n\n");
    CHECK(pclose(import) == 0);
    static const char *const refs[] = {"refs/heads/main", "refs/import/a", "refs/import/b"};
    char *const outs[] = {base, a, b};
    for (size_t i = 0u; i < 3u; ++i) {
        (void)snprintf(command, sizeof(command), "git --git-dir=%s/r.git rev-parse %s", g_root, refs[i]);
        CHECK(git(command, outs[i], 64u) && strlen(outs[i]) == 40u);
    }
    return 1;
}

static int g_inspected;

/* At the first change of the push, the grants are revoked. */
static maelys_git_result_t revoke_on_first(const maelys_git_receive_update_t *update,
                                           const maelys_git_change_t *change, void *context,
                                           maelys_git_error_t *error) {
    (void)update;
    (void)change;
    (void)context;
    (void)error;
    if (g_inspected++ == 0) (void)publish_users("bob");
    return MAELYS_GIT_OK;
}

/* Test 10: a push of two refs, the grants revoked while the first is
 * inspected: both decide on the snapshot read before the push. */
static int test_one_generation(const char *a, const char *b) {
    CHECK(publish_users("alice"));
    maelys_git_policy_t *policy = NULL;
    maelys_git_error_t error;
    CHECK(maelys_git_policy_open_grants(g_manifest, g_grants, &policy, &error) == MAELYS_GIT_OK);
    char path[512], input[512];
    (void)snprintf(path, sizeof(path), "%s/r.git", g_root);
    (void)snprintf(input, sizeof(input),
                   "0000000000000000000000000000000000000000 %s refs/heads/topic-a\n"
                   "0000000000000000000000000000000000000000 %s refs/heads/topic-b\n", a, b);
    FILE *stream = fmemopen(input, strlen(input), "r");
    CHECK(stream != NULL);
    const maelys_git_inspector_t inspector = {.name = "revoke", .inspect = revoke_on_first};
    g_inspected = 0;
    maelys_git_result_t result =
        maelys_git_pre_receive_ex(policy, "/usr/bin/git", path, "r.git", "alice", &inspector, 1u, stream, stderr,
                                  &error);
    (void)fclose(stream);
    if (result != MAELYS_GIT_OK) (void)fprintf(stderr, "push: %s\n", error.message);
    CHECK(result == MAELYS_GIT_OK && g_inspected >= 2);
    maelys_git_policy_close(policy);
    /* The revocation applies to the next push. */
    CHECK(maelys_git_policy_open_grants(g_manifest, g_grants, &policy, &error) == MAELYS_GIT_OK);
    stream = fmemopen(input, strlen(input), "r");
    CHECK(stream != NULL);
    result = maelys_git_pre_receive(policy, "/usr/bin/git", path, "r.git", "alice", stream, stderr, &error);
    (void)fclose(stream);
    CHECK(result == MAELYS_GIT_ERR_DENIED);
    maelys_git_policy_close(policy);
    return 1;
}

/* Test 11: pr merge and the grants of its plan. */
static int test_pr_merge(const char *base, const char *head) {
    CHECK(publish_users("alice"));
    char path[512];
    (void)snprintf(path, sizeof(path), "%s/r.git", g_root);
    const maelys_git_pr_gates_t gates = {.approvals = 1u, .required_approvals = 1u, .status_checks_passed = 1};
    maelys_git_policy_t *policy = NULL;
    maelys_git_error_t error;
    CHECK(maelys_git_policy_open_grants(g_manifest, g_grants, &policy, &error) == MAELYS_GIT_OK);
    maelys_git_pr_check_result_t plan;
    CHECK(maelys_git_pr_merge_grants("/usr/bin/git", path, "r.git", "refs/heads/main", base, head,
                                     MAELYS_GIT_MERGE_FAST_FORWARD, NULL, "alice", &gates, policy, NULL, NULL, NULL,
                                     NULL, NULL, NULL, 0, &plan, &error) == MAELYS_GIT_OK);
    char text[2048], expected[65];
    snapshot_text("alice", text, sizeof(text));
    sha_of(text, expected);
    CHECK(!strcmp(plan.grants_fingerprint, expected));
    maelys_git_pr_check_result_t applied;
    /* The entry points that predate grants plan, and refuse to apply. */
    CHECK(maelys_git_pr_merge("/usr/bin/git", path, "r.git", "refs/heads/main", base, head,
                              MAELYS_GIT_MERGE_FAST_FORWARD, NULL, "alice", &gates, policy, NULL, NULL, NULL, NULL, 0,
                              &applied, &error) == MAELYS_GIT_OK);
    maelys_git_pr_check_result_clear(&applied);
    CHECK(maelys_git_pr_merge("/usr/bin/git", path, "r.git", "refs/heads/main", base, head,
                              MAELYS_GIT_MERGE_FAST_FORWARD, NULL, "alice", &gates, policy, NULL,
                              plan.target_identity, plan.prepared_oid, plan.policy_fingerprint, 1, &applied,
                              &error) == MAELYS_GIT_ERR_INVALID_ARGUMENT);
    CHECK(strstr(error.message, "maelys_git_pr_merge_grants") != NULL);
    /* Without the grants fingerprint, apply is refused. */
    CHECK(maelys_git_pr_merge_grants("/usr/bin/git", path, "r.git", "refs/heads/main", base, head,
                                     MAELYS_GIT_MERGE_FAST_FORWARD, NULL, "alice", &gates, policy, NULL, NULL,
                                     plan.target_identity, plan.prepared_oid, plan.policy_fingerprint, NULL, 1,
                                     &applied, &error) == MAELYS_GIT_ERR_INVALID_ARGUMENT);
    maelys_git_policy_close(policy);
    /* Grants changed since the plan (alice keeps her right): refused. */
    CHECK(publish_users("alice,bob"));
    CHECK(maelys_git_policy_open_grants(g_manifest, g_grants, &policy, &error) == MAELYS_GIT_OK);
    CHECK(maelys_git_pr_merge_grants("/usr/bin/git", path, "r.git", "refs/heads/main", base, head,
                                     MAELYS_GIT_MERGE_FAST_FORWARD, NULL, "alice", &gates, policy, NULL, NULL,
                                     plan.target_identity, plan.prepared_oid, plan.policy_fingerprint,
                                     plan.grants_fingerprint, 1, &applied, &error) == MAELYS_GIT_ERR_PROCESS);
    CHECK(strstr(error.message, "grants changed; run a new pull request plan") != NULL);
    maelys_git_policy_close(policy);
    /* The same grants: applied, after the authorization is repeated. */
    CHECK(publish_users("alice"));
    CHECK(maelys_git_policy_open_grants(g_manifest, g_grants, &policy, &error) == MAELYS_GIT_OK);
    maelys_git_result_t result = maelys_git_pr_merge_grants(
        "/usr/bin/git", path, "r.git", "refs/heads/main", base, head, MAELYS_GIT_MERGE_FAST_FORWARD, NULL, "alice",
        &gates, policy, NULL, NULL, plan.target_identity, plan.prepared_oid, plan.policy_fingerprint,
        plan.grants_fingerprint, 1, &applied, &error);
    if (result != MAELYS_GIT_OK) (void)fprintf(stderr, "apply: %s\n", error.message);
    CHECK(result == MAELYS_GIT_OK && !strcmp(applied.grants_fingerprint, expected));
    maelys_git_pr_check_result_clear(&applied);
    maelys_git_pr_check_result_clear(&plan);
    maelys_git_policy_close(policy);
    char command[1024], main_oid[64];
    (void)snprintf(command, sizeof(command), "git --git-dir=%s/r.git rev-parse refs/heads/main", g_root);
    CHECK(git(command, main_oid, sizeof(main_oid)) && !strcmp(main_oid, head));
    return 1;
}

int main(void) {
    char template[] = "/tmp/maelys_git_grants_streams_XXXXXX";
    char *root = mkdtemp(template);
    if (!root) return 1;
    (void)snprintf(g_root, sizeof(g_root), "%s", root);
    char base[64], a[64], b[64];
    int ok = setup() && test_stream() && test_expected_grants() && test_pinned_first_read() && repository(base, a, b) && test_one_generation(a, b) &&
             test_pr_merge(base, a);
    if (!test_remove_tree(g_root)) ok = 0;
    if (ok) puts("grants in use: streams, expected grants, pinned first read, one generation per command, pr merge: ok");
    return ok ? 0 : 1;
}
