/* Authorization receipts: the corpus of reference receipts, their contract
 * and their canonical bytes, the explanation summary read from the engine's
 * views, and the authorization path without a receipt.
 *
 *   test-maelys-git-receipt                       compare with the corpus
 *   MG_RECORD_RECEIPTS=FILE test-maelys-git-receipt   write the corpus to FILE
 *
 * The corpus is the byte contract of receipt version 1; version 2, the
 * receipt of a decision that used a snapshot of grants, is held by
 * test_version_two. The corpus is regenerated
 * only in a commit that explains every line it changes; an engine upgrade
 * that changes a fingerprint regenerates it in a commit of its own, never in
 * the commit of a feature. */
#include "internal.h"
#include "maelys_git_receipt.h"
#include "policy/policy_grants.h"
#include "policy/program.h"
#include "receipt/receipt_internal.h"
#include "test_support.h"

#include <maelys/cli/digest.h>
#include <maelys/json.h>

#include <stdint.h>

#define TEXT_CAPACITY (64u * 1024u)
#define MANY_PATHS 300u

typedef struct {
    const char *name;
    const char *manifest;
    maelys_git_policy_request_t request;
} receipt_case_t;

static const char *g_paths[MANY_PATHS];
static char g_path_names[MANY_PATHS][16];

/* The requests of the corpus: each decision on the example policy, both
 * failures of a request, the filters' two-policy set and a truncated
 * why-false on the migrated Gitolite fixture. */
static receipt_case_t g_cases[] = {
    {"example-allow", TEST_MANIFEST_FILE,
     {.request_id = "t", .principal = "alice", .repository = "example.git", .operation = "push",
      .ref_name = "refs/heads/feature"}},
    {"example-deny-explicit", TEST_MANIFEST_FILE,
     {.request_id = "t", .principal = "mallory", .repository = "example.git", .operation = "push",
      .ref_name = "refs/heads/main"}},
    {"example-deny-default", TEST_MANIFEST_FILE,
     {.request_id = "t", .principal = "nobody", .repository = "example.git", .operation = "read"}},
    {"example-deny-error-value", TEST_MANIFEST_FILE,
     {.request_id = "t", .principal = "alice", .repository = "example.git", .operation = "push",
      .has_summary = 1, .changed_count = SIZE_MAX}},
    {"example-deny-error-capacity", TEST_MANIFEST_FILE,
     {.request_id = "t", .principal = "alice", .repository = "example.git", .operation = "push",
      .path_count = MANY_PATHS}},
    {"filters-allow", FIXTURE_DIR "/filters/manifest.json",
     {.request_id = "t", .principal = "alice", .repository = "team/app.git", .operation = "push",
      .ref_name = "refs/heads/release/1.0"}},
    {"filters-deny-explicit", FIXTURE_DIR "/filters/manifest.json",
     {.request_id = "t", .principal = "alice", .repository = "team/app.git", .operation = "push",
      .ref_name = "refs/heads/release/1.0/frozen"}},
    {"filters-deny-default", FIXTURE_DIR "/filters/manifest.json",
     {.request_id = "t", .principal = "zed", .repository = "team/app.git", .operation = "push",
      .ref_name = "refs/heads/x"}},
    {"filters-deny-error-value", FIXTURE_DIR "/filters/manifest.json",
     {.request_id = "t", .principal = "alice", .repository = "team/app.git", .operation = "push",
      .has_summary = 1, .changed_count = SIZE_MAX}},
    {"gitolite-deny-default", FIXTURE_DIR "/gitolite-exact/manifest.json",
     {.request_id = "t", .principal = "zed", .repository = "refs.git", .operation = "push",
      .ref_name = "refs/heads/x"}},
};
#define CASE_COUNT (sizeof(g_cases) / sizeof(g_cases[0]))

static const maelys_git_explain_mode_t k_modes[] = {
    MAELYS_GIT_EXPLAIN_NEVER, MAELYS_GIT_EXPLAIN_ON_DENIAL, MAELYS_GIT_EXPLAIN_ALWAYS};
static const char *const k_mode_names[] = {"never", "on-denial", "always"};

static maelys_git_policy_t *open_policy(const char *manifest) {
    maelys_git_policy_t *policy = NULL;
    maelys_git_error_t error;
    if (maelys_git_policy_open(manifest, &policy, &error) != MAELYS_GIT_OK) {
        (void)fprintf(stderr, "open %s: %s\n", manifest, error.message);
        return NULL;
    }
    return policy;
}

/* One receipt, serialized; the text, when rendered, in `text`. */
typedef struct {
    maelys_git_result_t result;
    maelys_git_policy_decision_t decision;
    maelys_git_receipt_t receipt;
    maelys_git_error_t error;
    char *bytes;
    size_t size;
    char sha256[65];
} produced_t;

static int produce(maelys_git_policy_t *policy, const maelys_git_policy_request_t *request,
                   maelys_git_explain_mode_t mode, char *text, size_t capacity, produced_t *out) {
    memset(out, 0, sizeof(*out));
    out->result = maelys_git_policy_authorize_receipt(policy, request, mode, text, capacity,
                                                      &out->decision, &out->receipt, &out->error);
    if (out->result != MAELYS_GIT_OK && out->receipt.decision != MAELYS_GIT_RECEIPT_DENY_ERROR) return 0;
    maelys_git_error_t error;
    return maelys_git_receipt_serialize(&out->receipt, &out->bytes, &out->size, out->sha256, &error) ==
           MAELYS_GIT_OK;
}

static int canonical(const char *bytes, size_t size) {
    maelys_json_document_t *document = NULL;
    if (maelys_json_document_parse(bytes, size, MAELYS_JSON_PROFILE_RFC8259, NULL, &document, NULL) !=
        MAELYS_JSON_OK)
        return 0;
    int is_canonical = 0;
    int ok = maelys_json_document_is_canonical(document, 0u, &is_canonical) == MAELYS_JSON_OK && is_canonical;
    maelys_json_document_release(document);
    return ok;
}

/* ---- tests 2, 5 and 8: the corpus ------------------------------------------- */

static int test_corpus(void) {
    static char lines[CASE_COUNT * 3u][MAELYS_GIT_RECEIPT_MAX_BYTES + 160u];
    static char text[TEXT_CAPACITY];
    size_t count = 0u;
    for (size_t c = 0u; c < CASE_COUNT; ++c) {
        maelys_git_policy_t *policy = open_policy(g_cases[c].manifest);
        CHECK(policy != NULL);
        for (size_t m = 0u; m < 3u; ++m) {
            produced_t produced;
            CHECK(produce(policy, &g_cases[c].request, k_modes[m], text, sizeof(text), &produced));
            /* Canonical, verified, and free of the explanation text. */
            char verified[65];
            maelys_git_error_t error;
            CHECK(canonical(produced.bytes, produced.size));
            CHECK(maelys_git_receipt_verify(produced.bytes, produced.size, verified, &error) == MAELYS_GIT_OK);
            CHECK(!strcmp(verified, produced.sha256));
            CHECK(strstr(produced.bytes, "MAELYS-DATALOG-v2") == NULL);
            if (produced.receipt.explanation.has_text) {
                char digest[MAELYS_CLI_SHA256_HEX_SIZE];
                maelys_cli_sha256_hex(text, strlen(text), digest);
                CHECK(strlen(text) == produced.receipt.explanation.text_bytes);
                CHECK(!strcmp(digest, produced.receipt.explanation.text_sha256));
            }
            (void)snprintf(lines[count++], sizeof(lines[0]), "%s/%s\t%s\t%s\n", g_cases[c].name,
                           k_mode_names[m], produced.sha256, produced.bytes);
            free(produced.bytes);
        }
        maelys_git_policy_close(policy);
    }
    const char *record = getenv("MG_RECORD_RECEIPTS");
    if (record && *record) {
        FILE *file = fopen(record, "w");
        CHECK(file != NULL);
        for (size_t i = 0u; i < count; ++i) CHECK(fputs(lines[i], file) >= 0);
        CHECK(fclose(file) == 0);
        return 1;
    }
    FILE *file = fopen(RECEIPT_FIXTURES "/receipts.tsv", "r");
    CHECK(file != NULL);
    static char expected[MAELYS_GIT_RECEIPT_MAX_BYTES + 160u];
    for (size_t i = 0u; i < count; ++i) {
        CHECK(fgets(expected, sizeof(expected), file) != NULL);
        if (strcmp(expected, lines[i]) != 0) {
            (void)fprintf(stderr, "receipt changed:\n  expected %s  actual   %s", expected, lines[i]);
            (void)fclose(file);
            return 0;
        }
    }
    CHECK(fgets(expected, sizeof(expected), file) == NULL);
    (void)fclose(file);
    return 1;
}

/* ---- test 3: the four decisions --------------------------------------------- */

static int test_decisions(void) {
    maelys_git_policy_t *policy = open_policy(TEST_MANIFEST_FILE);
    CHECK(policy != NULL);
    static char text[TEXT_CAPACITY];
    produced_t produced;

    CHECK(produce(policy, &g_cases[0].request, MAELYS_GIT_EXPLAIN_ALWAYS, text, sizeof(text), &produced));
    const maelys_git_receipt_t *receipt = &produced.receipt;
    CHECK(receipt->decision == MAELYS_GIT_RECEIPT_ALLOW && receipt->matched);
    CHECK(!strcmp(receipt->matched_policy_id, "maelys-git.example.authorization"));
    CHECK(!strcmp(receipt->matched_session_fingerprint, produced.decision.session_fingerprint));
    CHECK(!strcmp(receipt->policy_set_fingerprint, produced.decision.policy_set_fingerprint));
    CHECK(receipt->error_code[0] == '\0' && receipt->error_kind[0] == '\0');
    CHECK(receipt->explanation.kind == MAELYS_GIT_EXPLANATION_WHY_TRUE);
    CHECK(!strcmp(receipt->explanation.query, "allow"));
    CHECK(strstr(produced.bytes, "\"errorCode\":null") && strstr(produced.bytes, "\"ref\":\"refs/heads/feature\""));
    free(produced.bytes);

    CHECK(produce(policy, &g_cases[1].request, MAELYS_GIT_EXPLAIN_ON_DENIAL, text, sizeof(text), &produced));
    CHECK(produced.receipt.decision == MAELYS_GIT_RECEIPT_DENY_EXPLICIT && produced.receipt.matched);
    CHECK(!strcmp(produced.receipt.explanation.query, "deny"));
    free(produced.bytes);

    CHECK(produce(policy, &g_cases[2].request, MAELYS_GIT_EXPLAIN_ALWAYS, text, sizeof(text), &produced));
    CHECK(produced.receipt.decision == MAELYS_GIT_RECEIPT_DENY_DEFAULT && !produced.receipt.matched);
    CHECK(strstr(produced.bytes, "\"matched\":null") && strstr(produced.bytes, "\"ref\":null"));
    CHECK(produced.receipt.explanation.kind == MAELYS_GIT_EXPLANATION_WHY_FALSE);
    free(produced.bytes);

    /* A failure is a deny_error receipt that names its kind; the result code
     * stays that of maelys_git_policy_authorize, and nothing is explained. */
    CHECK(produce(policy, &g_cases[3].request, MAELYS_GIT_EXPLAIN_ALWAYS, text, sizeof(text), &produced));
    CHECK(produced.result == MAELYS_GIT_ERR_POLICY);
    CHECK(produced.receipt.decision == MAELYS_GIT_RECEIPT_DENY_ERROR && !produced.receipt.matched);
    CHECK(!strcmp(produced.receipt.error_code, "policy_error"));
    CHECK(!strcmp(produced.receipt.error_kind, "value") && produced.receipt.error_budget[0] == '\0');
    CHECK(produced.receipt.explanation.kind == MAELYS_GIT_EXPLANATION_NONE);
    CHECK(strstr(produced.bytes, "\"status\":\"not_requested\""));
    free(produced.bytes);

    CHECK(produce(policy, &g_cases[4].request, MAELYS_GIT_EXPLAIN_NEVER, text, sizeof(text), &produced));
    CHECK(produced.result == MAELYS_GIT_ERR_POLICY);
    CHECK(!strcmp(produced.receipt.error_kind, "capacity"));
    CHECK(!strcmp(produced.receipt.error_budget, "MAX_FACTS_PER_PRED"));
    CHECK(produced.receipt.request.path_count == MANY_PATHS);
    free(produced.bytes);

    /* A refused call is no decision, and no receipt. */
    maelys_git_policy_request_t invalid = {.request_id = "t", .principal = "alice", .repository = "example.git"};
    CHECK(maelys_git_policy_authorize_receipt(policy, &invalid, MAELYS_GIT_EXPLAIN_NEVER, NULL, 0u,
                                              &produced.decision, &produced.receipt, &produced.error) ==
          MAELYS_GIT_ERR_INVALID_ARGUMENT);
    maelys_git_policy_close(policy);
    return 1;
}

/* ---- test 4: determinism ---------------------------------------------------- */

static int test_determinism(void) {
    maelys_git_policy_t *policy = open_policy(TEST_MANIFEST_FILE);
    CHECK(policy != NULL);
    static char text[TEXT_CAPACITY];
    produced_t a, b, again;
    CHECK(produce(policy, &g_cases[1].request, MAELYS_GIT_EXPLAIN_ALWAYS, text, sizeof(text), &a));
    char *second = NULL;
    size_t second_size = 0u;
    char second_sha[65];
    maelys_git_error_t error;
    CHECK(maelys_git_receipt_serialize(&a.receipt, &second, &second_size, second_sha, &error) == MAELYS_GIT_OK);
    CHECK(second_size == a.size && !memcmp(second, a.bytes, a.size) && !strcmp(second_sha, a.sha256));
    CHECK(produce(policy, &g_cases[2].request, MAELYS_GIT_EXPLAIN_ALWAYS, text, sizeof(text), &b));
    CHECK(produce(policy, &g_cases[1].request, MAELYS_GIT_EXPLAIN_ALWAYS, text, sizeof(text), &again));
    CHECK(again.size == a.size && !memcmp(again.bytes, a.bytes, a.size));
    free(second); free(a.bytes); free(b.bytes); free(again.bytes);
    maelys_git_policy_close(policy);
    return 1;
}

/* ---- test 6: the byte budget ------------------------------------------------ */

static void fill(char *out, size_t capacity, char value) {
    memset(out, value, capacity - 1u);
    out[capacity - 1u] = '\0';
}

static int test_budget(void) {
    maelys_git_receipt_t receipt;
    memset(&receipt, 0, sizeof(receipt));
    receipt.decision = MAELYS_GIT_RECEIPT_DENY_ERROR;
    fill(receipt.error_code, sizeof(receipt.error_code), 'c');
    (void)snprintf(receipt.error_kind, sizeof(receipt.error_kind), "semantics");
    fill(receipt.error_budget, sizeof(receipt.error_budget), 'B');
    fill(receipt.policy_set_fingerprint, sizeof(receipt.policy_set_fingerprint), 'a');
    receipt.matched = 1;
    receipt.matched_policy_index = SIZE_MAX;
    fill(receipt.matched_policy_id, sizeof(receipt.matched_policy_id), 'p');
    fill(receipt.matched_session_fingerprint, sizeof(receipt.matched_session_fingerprint), 'b');
    fill(receipt.request.id, sizeof(receipt.request.id), 'i');
    fill(receipt.request.principal, sizeof(receipt.request.principal), 'u');
    fill(receipt.request.repository, sizeof(receipt.request.repository), 'r');
    fill(receipt.request.operation, sizeof(receipt.request.operation), 'o');
    fill(receipt.request.ref, sizeof(receipt.request.ref), 'f');
    receipt.request.path_count = SIZE_MAX;
    receipt.edb_facts = SIZE_MAX;
    receipt.evaluated_policies = SIZE_MAX;
    maelys_git_receipt_explanation_t *explanation = &receipt.explanation;
    explanation->kind = MAELYS_GIT_EXPLANATION_WHY_FALSE;
    explanation->status = MAELYS_GIT_RECEIPT_STATUS_NOT_APPLICABLE;
    explanation->policy_index = SIZE_MAX;
    (void)snprintf(explanation->query, sizeof(explanation->query), "allow");
    explanation->has_rule = 1;
    explanation->rule_id = explanation->step_count = explanation->premise_count = SIZE_MAX;
    explanation->has_counts = 1;
    explanation->candidate_rules = explanation->diagnostics = SIZE_MAX;
    explanation->filter_cost_units = explanation->substitutions = SIZE_MAX;
    explanation->limit_hits = 31u;
    explanation->has_text = 1;
    explanation->text_bytes = SIZE_MAX;
    fill(explanation->text_sha256, sizeof(explanation->text_sha256), 'e');
    receipt.grants.present = 1;
    receipt.grants.facts = SIZE_MAX;
    fill(receipt.grants.sha256, sizeof(receipt.grants.sha256), 'f');
    char *bytes = NULL;
    size_t size = 0u;
    char sha[65];
    maelys_git_error_t error;
    CHECK(maelys_git_receipt_serialize(&receipt, &bytes, &size, sha, &error) == MAELYS_GIT_OK);
    CHECK(size <= MAELYS_GIT_RECEIPT_MAX_BYTES);
    CHECK(maelys_git_receipt_verify(bytes, size, NULL, &error) == MAELYS_GIT_OK);
    (void)printf("largest receipt: %zu bytes of %u\n", size, MAELYS_GIT_RECEIPT_MAX_BYTES);
    char *short_bytes = NULL;
    size_t short_size = 7u;
    CHECK(mg_receipt_serialize_within(&receipt, size - 1u, &short_bytes, &short_size, sha, &error) ==
          MAELYS_GIT_ERR_LIMIT);
    CHECK(short_bytes == NULL && short_size == 7u);
    CHECK(mg_receipt_serialize_within(&receipt, size, &short_bytes, &short_size, sha, &error) == MAELYS_GIT_OK);
    CHECK(short_size == size);
    free(short_bytes);
    free(bytes);
    return 1;
}

/* ---- test 7: strict verification -------------------------------------------- */

/* `bytes` with the first occurrence of `from` replaced by `to`. */
static char *replaced(const char *bytes, const char *from, const char *to) {
    const char *at = strstr(bytes, from);
    if (!at) return NULL;
    size_t size = strlen(bytes) - strlen(from) + strlen(to);
    char *out = malloc(size + 1u);
    if (!out) return NULL;
    (void)snprintf(out, size + 1u, "%.*s%s%s", (int)(at - bytes), bytes, to, at + strlen(from));
    return out;
}

static int refused(const char *bytes, const char *from, const char *to) {
    char *altered = replaced(bytes, from, to);
    if (!altered) {
        (void)fprintf(stderr, "no %s in the receipt\n", from);
        return 0;
    }
    maelys_git_error_t error;
    int ok = maelys_git_receipt_verify(altered, strlen(altered), NULL, &error) == MAELYS_GIT_ERR_PROTOCOL;
    if (!ok) (void)fprintf(stderr, "accepted: %s\n", altered);
    free(altered);
    return ok;
}

static int test_strict_verification(void) {
    maelys_git_policy_t *policy = open_policy(TEST_MANIFEST_FILE);
    CHECK(policy != NULL);
    static char text[TEXT_CAPACITY];
    produced_t produced;
    CHECK(produce(policy, &g_cases[1].request, MAELYS_GIT_EXPLAIN_ALWAYS, text, sizeof(text), &produced));
    const char *bytes = produced.bytes;
    char fingerprint[128];
    (void)snprintf(fingerprint, sizeof(fingerprint), "\"policySetFingerprint\":\"%.63s",
                   produced.receipt.policy_set_fingerprint);
    char full[128];
    (void)snprintf(full, sizeof(full), "\"policySetFingerprint\":\"%s", produced.receipt.policy_set_fingerprint);
    CHECK(refused(bytes, "{\"decision\"", "{ \"decision\""));                                /* blank */
    CHECK(refused(bytes, "\"decision\":\"deny_explicit\",\"errorBudget\":null",
                  "\"errorBudget\":null,\"decision\":\"deny_explicit\""));                   /* order */
    CHECK(refused(bytes, "\"version\":1}", "\"version\":1,\"zzz\":1}"));                    /* unknown key */
    CHECK(refused(bytes, ",\"version\":1}", "}"));                                           /* missing key */
    CHECK(refused(bytes, "\"deny_explicit\"", "\"deny_maybe\""));                           /* enumeration */
    CHECK(refused(bytes, full, fingerprint));                                                /* 63 digits */
    CHECK(refused(bytes, "\"pathCount\":0", "\"pathCount\":-1"));                           /* negative */
    CHECK(refused(bytes, "\"version\":1}", "\"version\":1.0}"));                            /* fraction */
    CHECK(refused(bytes, "\"version\":1}", "\"version\":1e0}"));                            /* exponent */
    CHECK(refused(bytes, "\"errorCode\":null", "\"errorCode\":\"policy_error\""));          /* error without deny_error */
    maelys_git_error_t error;
    CHECK(maelys_git_receipt_verify(bytes, produced.size, NULL, &error) == MAELYS_GIT_OK);
    free(produced.bytes);
    maelys_git_policy_close(policy);
    return 1;
}

/* ---- test 9: the caller's text buffer --------------------------------------- */

static int test_text_buffer(void) {
    maelys_git_policy_t *policy = open_policy(TEST_MANIFEST_FILE);
    CHECK(policy != NULL);
    produced_t none, short_buffer, exact;
    CHECK(produce(policy, &g_cases[2].request, MAELYS_GIT_EXPLAIN_ALWAYS, NULL, 0u, &none));
    size_t size = none.receipt.explanation.text_bytes;
    CHECK(none.receipt.explanation.has_text && size > 0u);
    char *text = malloc(size + 1u);
    CHECK(text != NULL);
    memset(text, 'x', size + 1u);
    CHECK(produce(policy, &g_cases[2].request, MAELYS_GIT_EXPLAIN_ALWAYS, text, size, &short_buffer));
    CHECK(text[0] == '\0' && text[1] == 'x');
    CHECK(produce(policy, &g_cases[2].request, MAELYS_GIT_EXPLAIN_ALWAYS, text, size + 1u, &exact));
    CHECK(strlen(text) == size && !strncmp(text, "MAELYS-DATALOG-v2\n", 18u));
    CHECK(none.size == exact.size && !memcmp(none.bytes, exact.bytes, none.size));
    CHECK(short_buffer.size == exact.size && !memcmp(short_buffer.bytes, exact.bytes, exact.size));
    free(text); free(none.bytes); free(short_buffer.bytes); free(exact.bytes);
    maelys_git_policy_close(policy);
    return 1;
}

/* ---- test 10: the summary is the engine's, never the text's ----------------- */

/* The test, and only the test, reads the document: a header line's value. */
static int header_value(const char *text, const char *key, char *out, size_t capacity) {
    char needle[64];
    (void)snprintf(needle, sizeof(needle), "\n%s=", key);
    const char *at = strstr(text, needle);
    if (!at) return 0;
    at += strlen(needle);
    size_t length = strcspn(at, " \n");
    if (length >= capacity) return 0;
    memcpy(out, at, length);
    out[length] = '\0';
    return 1;
}

static int test_summary(void) {
    static char text[TEXT_CAPACITY];
    char value[64], needle[160];
    maelys_git_policy_t *example = open_policy(TEST_MANIFEST_FILE);
    CHECK(example != NULL);
    produced_t produced;
    CHECK(produce(example, &g_cases[1].request, MAELYS_GIT_EXPLAIN_ALWAYS, text, sizeof(text), &produced));
    const maelys_git_receipt_explanation_t *explanation = &produced.receipt.explanation;
    CHECK(explanation->status == MAELYS_GIT_RECEIPT_STATUS_COMPLETE && explanation->has_rule);
    CHECK(header_value(text, "result-step", value, sizeof(value)));
    (void)snprintf(needle, sizeof(needle), "\nstep=%s rule=%zu ", value, explanation->rule_id);
    CHECK(strstr(text, needle) != NULL);
    (void)snprintf(needle, sizeof(needle), "\nsteps=%zu premises=%zu\n", explanation->step_count,
                   explanation->premise_count);
    CHECK(strstr(text, needle) != NULL);
    free(produced.bytes);

    CHECK(produce(example, &g_cases[2].request, MAELYS_GIT_EXPLAIN_ALWAYS, text, sizeof(text), &produced));
    CHECK(explanation->status == MAELYS_GIT_RECEIPT_STATUS_COMPLETE && explanation->has_counts);
    CHECK(!explanation->has_rule && explanation->limit_hits == 0u);
    CHECK(header_value(text, "status", value, sizeof(value)) && !strcmp(value, "complete"));
    (void)snprintf(needle, sizeof(needle), "\nlimit-hits=none candidate-rules=%zu substitutions=%zu "
                   "diagnostics=%zu filter-cost=%zu\n", explanation->candidate_rules,
                   explanation->substitutions, explanation->diagnostics, explanation->filter_cost_units);
    CHECK(strstr(text, needle) != NULL);
    CHECK(strstr(produced.bytes, "\"limitHits\":[]"));
    free(produced.bytes);

    /* A request value that imitates a header line changes nothing. */
    maelys_git_policy_request_t forged = g_cases[2].request;
    forged.principal = "x\nstatus=truncated";
    CHECK(produce(example, &forged, MAELYS_GIT_EXPLAIN_ALWAYS, text, sizeof(text), &produced));
    CHECK(explanation->status == MAELYS_GIT_RECEIPT_STATUS_COMPLETE);
    free(produced.bytes);
    maelys_git_policy_close(example);

    maelys_git_policy_t *gitolite = open_policy(FIXTURE_DIR "/gitolite-exact/manifest.json");
    CHECK(gitolite != NULL);
    CHECK(produce(gitolite, &g_cases[9].request, MAELYS_GIT_EXPLAIN_ALWAYS, text, sizeof(text), &produced));
    CHECK(explanation->status == MAELYS_GIT_RECEIPT_STATUS_TRUNCATED && explanation->limit_hits != 0u);
    CHECK(header_value(text, "status", value, sizeof(value)) && !strcmp(value, "truncated"));
    CHECK(header_value(text, "limit-hits", value, sizeof(value)) && !strcmp(value, "diagnostics"));
    CHECK(explanation->limit_hits == MAELYS_GIT_RECEIPT_LIMIT_DIAGNOSTICS);
    CHECK(strstr(produced.bytes, "\"limitHits\":[\"diagnostics\"]"));
    free(produced.bytes);
    maelys_git_policy_close(gitolite);
    return 1;
}

/* ---- test 21: one explanation path ------------------------------------------ */

static int test_single_path(void) {
    static char text[TEXT_CAPACITY];
    for (size_t c = 0u; c < CASE_COUNT; ++c) {
        if (strstr(g_cases[c].name, "error")) continue;
        maelys_git_policy_t *policy = open_policy(g_cases[c].manifest);
        CHECK(policy != NULL);
        produced_t produced;
        CHECK(produce(policy, &g_cases[c].request, MAELYS_GIT_EXPLAIN_ALWAYS, NULL, 0u, &produced));
        maelys_git_policy_explanation_t explanation;
        maelys_git_error_t error;
        CHECK(maelys_git_policy_explain(policy, &g_cases[c].request, text, sizeof(text), &explanation,
                                        &error) == MAELYS_GIT_OK);
        char digest[MAELYS_CLI_SHA256_HEX_SIZE];
        maelys_cli_sha256_hex(text, explanation.text_length, digest);
        CHECK(!strcmp(digest, produced.receipt.explanation.text_sha256));
        free(produced.bytes);
        maelys_git_policy_close(policy);
    }
    return 1;
}

/* ---- GIT-C06 test 15: receipt version 2 ------------------------------------- */

static int write_file(const char *path, const char *text) {
    FILE *file = fopen(path, "w");
    if (!file) return 0;
    int ok = fputs(text, file) >= 0;
    return fclose(file) == 0 && ok;
}

/* The audited program and a snapshot in DIRECTORY, opened. */
static maelys_git_policy_t *open_program(const char *directory) {
    char path[512], manifest[2048], digest[MAELYS_CLI_SHA256_HEX_SIZE];
    size_t length = 0u;
    const char *program = mg_gitolite_program_text(&length);
    maelys_cli_sha256_hex(program, length, digest);
    (void)snprintf(path, sizeof(path), "%s/program.dl", directory);
    if (!write_file(path, program)) return NULL;
    (void)snprintf(manifest, sizeof(manifest),
        "{\"policy_set_id\":\"test.receipt-v2\",\"policy_set_version\":\"1\",\"manifest_version\":\"1\","
        "\"default_profile\":\"enforce\",\"created_for\":\"maelys-git-core-tests\",\"strict_loading\":true,"
        "\"fail_closed\":true,\"capabilities\":[],\"policies\":[{\"policy_id\":\"test.receipt-v2.program\","
        "\"domain\":\"maelys_git\",\"file\":\"program.dl\",\"sha256\":\"%s\",\"mode\":\"enforce\","
        "\"enabled\":true,\"description\":\"test\","
        "\"queries\":[{\"name\":\"allow\",\"arity\":1},{\"name\":\"deny\",\"arity\":1}]}]}\n", digest);
    (void)snprintf(path, sizeof(path), "%s/manifest.json", directory);
    if (!write_file(path, manifest)) return NULL;
    char grants[512];
    (void)snprintf(grants, sizeof(grants), "%s/grants.json", directory);
    if (!write_file(grants,
            "{\"access\":[[\"group\",\"devs\",\"app.git\",\"RW\"]],\"format\":\"maelys-git-grants/1\","
            "\"members\":[[\"alice\",\"devs\"]],\"namespace_creators\":[],\"nested\":[],\"owner_access\":[],"
            "\"refs\":[],\"vref_limits\":[],\"vref_names\":[]}"))
        return NULL;
    maelys_git_policy_t *policy = NULL;
    maelys_git_error_t error;
    if (mg_policy_open_grants(path, grants, &policy, &error) != MAELYS_GIT_OK) {
        (void)fprintf(stderr, "open program: %s\n", error.message);
        return NULL;
    }
    return policy;
}

/* A decision of the audited program carries grants, in version 2; the
 * receipt verifies, is rewritten from an envelope and written as a line;
 * version 2 without grants, or grants in version 1, do not verify. */
static int test_version_two(void) {
    char template[] = "/tmp/maelys_git_receipt_v2_XXXXXX";
    char *root = mkdtemp(template);
    CHECK(root);
    maelys_git_policy_t *policy = open_program(root);
    CHECK(policy != NULL);
    maelys_git_policy_request_t write = {.request_id = "v2", .principal = "alice", .repository = "app.git",
                                         .operation = "write"};
    produced_t produced;
    CHECK(produce(policy, &write, MAELYS_GIT_EXPLAIN_NEVER, NULL, 0u, &produced));
    CHECK(produced.result == MAELYS_GIT_OK && produced.receipt.decision == MAELYS_GIT_RECEIPT_ALLOW);
    const maelys_git_receipt_grants_t *grants = &produced.receipt.grants;
    CHECK(grants->present && grants->facts == 2u && !strcmp(grants->sha256, mg_policy_grants_sha256(policy)));
    char expected[512];
    (void)snprintf(expected, sizeof(expected),
                   "\"grants\":{\"facts\":2,\"format\":\"maelys-git-grants/1\","
                   "\"program\":\"maelys-git-gitolite-program/1\",\"sha256\":\"%s\","
                   "\"slice\":\"maelys-git-slice/1\"},\"matched\":", grants->sha256);
    CHECK(strstr(produced.bytes, expected) != NULL);
    CHECK(produced.size > 12u && !strcmp(produced.bytes + produced.size - 12u, "\"version\":2}"));
    CHECK(canonical(produced.bytes, produced.size));
    maelys_git_error_t error;
    char sha[65];
    CHECK(maelys_git_receipt_verify(produced.bytes, produced.size, sha, &error) == MAELYS_GIT_OK);
    CHECK(!strcmp(sha, produced.sha256));
    /* The paths of the agent and the audit (a receipt read inside another
     * document), and of the hook (a line). */
    maelys_json_document_t *document = NULL;
    CHECK(maelys_json_document_parse(produced.bytes, produced.size, MAELYS_JSON_PROFILE_RFC8259, NULL, &document,
                                     NULL) == MAELYS_JSON_OK);
    char *rewritten = NULL;
    size_t rewritten_size = 0u;
    mg_receipt_text_t vouched;
    CHECK(mg_receipt_rewrite(document, maelys_json_document_root(document), &rewritten, &rewritten_size, sha,
                             &vouched, &error) == MAELYS_GIT_OK);
    CHECK(rewritten_size == produced.size && !memcmp(rewritten, produced.bytes, produced.size));
    free(rewritten);
    maelys_json_document_release(document);
    char *line = NULL;
    size_t line_size = 0u;
    FILE *stream = open_memstream(&line, &line_size);
    CHECK(stream && mg_receipt_write_line(stream, &produced.receipt, NULL, &error) == MAELYS_GIT_OK);
    CHECK(fclose(stream) == 0 && strstr(line, expected) != NULL);
    free(line);
    /* Strict: each member of grants, and grants against the version. */
    const char *bytes = produced.bytes;
    char sha63[80];
    (void)snprintf(sha63, sizeof(sha63), "\"sha256\":\"%.63s\"", grants->sha256);
    char sha64[80];
    (void)snprintf(sha64, sizeof(sha64), "\"sha256\":\"%s\"", grants->sha256);
    CHECK(refused(bytes, "\"version\":2}", "\"version\":1}"));                             /* grants in v1 */
    CHECK(refused(bytes, "\"version\":2}", "\"version\":3}"));                             /* unknown version */
    CHECK(refused(bytes, "\"facts\":2", "\"facts\":-2"));                                   /* negative */
    CHECK(refused(bytes, "\"facts\":2", "\"facts\":2.0"));                                  /* fraction */
    CHECK(refused(bytes, "\"maelys-git-grants/1\"", "\"maelys-git-grants/2\""));            /* format */
    CHECK(refused(bytes, "\"maelys-git-slice/1\"", "\"maelys-git-slice/2\""));              /* slice */
    CHECK(refused(bytes, "\"maelys-git-gitolite-program/1\"", "\"maelys-git-gitolite-program/2\""));
    CHECK(refused(bytes, sha64, sha63));                                                     /* 63 digits */
    CHECK(refused(bytes, "\"slice\":\"maelys-git-slice/1\"}",
                  "\"slice\":\"maelys-git-slice/1\",\"zzz\":1}"));                          /* unknown key */
    char *without = replaced(bytes, expected, "\"matched\":");
    CHECK(without != NULL);
    CHECK(maelys_git_receipt_verify(without, strlen(without), NULL, &error) == MAELYS_GIT_ERR_PROTOCOL);
    free(without);
    free(produced.bytes);
    /* A request refused before its slice is a deny_error of version 2 that
     * counts no fact: more paths than a predicate holds, in either profile. */
    maelys_git_policy_request_t push = {.request_id = "v2", .principal = "alice", .repository = "app.git",
                                        .operation = "push", .paths = g_paths, .path_count = MANY_PATHS};
    CHECK(produce(policy, &push, MAELYS_GIT_EXPLAIN_NEVER, NULL, 0u, &produced));
    CHECK(produced.receipt.decision == MAELYS_GIT_RECEIPT_DENY_ERROR && produced.receipt.grants.present);
    CHECK(produced.receipt.grants.facts == 0u);
    CHECK(maelys_git_receipt_verify(produced.bytes, produced.size, NULL, &error) == MAELYS_GIT_OK);
    free(produced.bytes);
    maelys_git_policy_close(policy);
    /* A policy without slice_* keeps version 1. */
    policy = open_policy(TEST_MANIFEST_FILE);
    CHECK(policy && produce(policy, &g_cases[0].request, MAELYS_GIT_EXPLAIN_NEVER, NULL, 0u, &produced));
    CHECK(!produced.receipt.grants.present && strstr(produced.bytes, "\"grants\"") == NULL);
    CHECK(!strcmp(produced.bytes + produced.size - 12u, "\"version\":1}"));
    free(produced.bytes);
    maelys_git_policy_close(policy);
    CHECK(test_remove_tree(root));
    return 1;
}

/* ---- test 22: the path without a receipt ------------------------------------ */

static int test_hot_path(void) {
    maelys_git_policy_t *policy = open_policy(TEST_MANIFEST_FILE);
    CHECK(policy != NULL);
    maelys_git_policy_decision_t decision;
    maelys_git_receipt_t receipt;
    maelys_git_error_t error;
    for (size_t i = 0u; i < 1000u; ++i) {
        CHECK(maelys_git_policy_authorize(policy, &g_cases[2].request, &decision, &error) == MAELYS_GIT_OK);
        CHECK(maelys_git_policy_authorize_receipt(policy, &g_cases[1].request, MAELYS_GIT_EXPLAIN_NEVER,
                                                  NULL, 0u, &decision, &receipt, &error) == MAELYS_GIT_OK);
        CHECK(maelys_git_policy_authorize_receipt(policy, &g_cases[0].request, MAELYS_GIT_EXPLAIN_ON_DENIAL,
                                                  NULL, 0u, &decision, &receipt, &error) == MAELYS_GIT_OK);
    }
    CHECK(mg_policy_explanation_storage_bytes(policy) == 0u);
    CHECK(maelys_git_policy_authorize_receipt(policy, &g_cases[2].request, MAELYS_GIT_EXPLAIN_ON_DENIAL,
                                              NULL, 0u, &decision, &receipt, &error) == MAELYS_GIT_OK);
    (void)printf("explanation storage after a why-false: %zu bytes\n", mg_policy_explanation_storage_bytes(policy));
    CHECK(mg_policy_explanation_storage_bytes(policy) > 0u);
    maelys_git_policy_close(policy);
    return 1;
}

int main(void) {
    for (size_t i = 0u; i < MANY_PATHS; ++i) {
        (void)snprintf(g_path_names[i], sizeof(g_path_names[i]), "f%zu", i);
        g_paths[i] = g_path_names[i];
    }
    g_cases[4].request.paths = g_paths;
    int ok = test_corpus() && test_decisions() && test_determinism() && test_budget() &&
             test_strict_verification() && test_text_buffer() && test_summary() &&
             test_single_path() && test_hot_path() && test_version_two();
    if (ok)
        puts("receipts: corpus, decisions, canonical form, budget, verification, summary, hot path and "
             "version 2: ok");
    return ok ? 0 : 1;
}
