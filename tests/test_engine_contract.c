/* What Maelys Git Core relies on from the engine and no request of Git Core
 * can reach: the capacity section of a solve refused for its input symbols.
 * The section names the bound Git Core reports as the budget of a denial;
 * its pool of text is reached end to end (test_gitolite_program), its count
 * of symbols is not: a slice holds about two hundred distinct strings, a
 * written policy 256 atoms, and the engine holds 512 symbols. Both are held
 * here on a domain of this test, through the engine's public API. */
#include <maelys/cli/digest.h>
#include <maelys/datalog.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        return 0; \
    } \
} while (0)

#define PREDICATES 8u

static const maelys_datalog_predicate_t k_predicates[] = {
    MAELYS_DATALOG_EDB("request", 1u),
    MAELYS_DATALOG_EDB("q0", 4u), MAELYS_DATALOG_EDB("q1", 4u), MAELYS_DATALOG_EDB("q2", 4u),
    MAELYS_DATALOG_EDB("q3", 4u), MAELYS_DATALOG_EDB("q4", 4u), MAELYS_DATALOG_EDB("q5", 4u),
    MAELYS_DATALOG_EDB("q6", 4u), MAELYS_DATALOG_EDB("q7", 4u),
    MAELYS_DATALOG_IDB_QUERY("allow", 1u), MAELYS_DATALOG_IDB_QUERY("deny", 1u),
};
static const char *const k_names[PREDICATES] = {"q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7"};

static maelys_datalog_session_t *open_session(maelys_datalog_policy_t **out_policy) {
    static const maelys_datalog_domain_t domain =
        MAELYS_DATALOG_DOMAIN_NO_ATOMS("maelys_git_engine_contract", k_predicates);
    if (maelys_datalog_domain_register(&domain) != MAELYS_DATALOG_STATUS_OK) return NULL;
    static const char source[] = "allow(R) :- request(R).\n";
    char digest[MAELYS_CLI_SHA256_HEX_SIZE], manifest[1024];
    maelys_cli_sha256_hex(source, sizeof(source) - 1u, digest);
    int length = snprintf(manifest, sizeof(manifest),
        "{\"policy_set_id\":\"test.engine-contract\",\"policy_set_version\":\"1\",\"manifest_version\":\"1\","
        "\"default_profile\":\"enforce\",\"created_for\":\"maelys-git-core-tests\",\"strict_loading\":true,"
        "\"fail_closed\":true,\"capabilities\":[],\"policies\":[{\"policy_id\":\"test.engine-contract.main\","
        "\"domain\":\"maelys_git_engine_contract\",\"file\":\"policy.dl\",\"sha256\":\"%s\",\"mode\":\"enforce\","
        "\"enabled\":true,\"description\":\"test\","
        "\"queries\":[{\"name\":\"allow\",\"arity\":1},{\"name\":\"deny\",\"arity\":1}]}]}", digest);
    const maelys_datalog_policy_bundle_entry_t bundle = {
        .policy_id = "test.engine-contract.main", .src = source, .src_len = sizeof(source) - 1u};
    maelys_datalog_diagnostic_t diagnostic = MAELYS_DATALOG_DIAGNOSTIC_INIT;
    maelys_datalog_session_t *session = NULL;
    if (length < 0 || (size_t)length >= sizeof(manifest) ||
        maelys_datalog_policy_load_manifest_buffer(manifest, (size_t)length, &bundle, 1u, 0u, out_policy,
                                                   &diagnostic) != MAELYS_DATALOG_STATUS_OK ||
        maelys_datalog_session_create(*out_policy, 0u, &session) != MAELYS_DATALOG_STATUS_OK)
        return NULL;
    return session;
}

/* COUNT distinct symbols of LENGTH bytes, four per fact, spread over the
 * predicates within the facts each one holds; then the solve. */
static maelys_datalog_status_t solve_symbols(maelys_datalog_session_t *session, size_t count, size_t length,
                                             maelys_datalog_diagnostic_t *diagnostic) {
    size_t per_predicate = 0u, facts_limit = 0u;
    if (maelys_datalog_limit_get(MAELYS_DATALOG_LIMIT_MAX_FACTS_PER_PRED, &per_predicate) != MAELYS_DATALOG_STATUS_OK ||
        maelys_datalog_limit_get(MAELYS_DATALOG_LIMIT_MAX_EDB_FACTS, &facts_limit) != MAELYS_DATALOG_STATUS_OK)
        return MAELYS_DATALOG_STATUS_INTERNAL;
    size_t facts = 1u + (count + 3u) / 4u;
    if (facts > facts_limit || (count + 3u) / 4u > per_predicate * PREDICATES || length < 6u)
        return MAELYS_DATALOG_STATUS_INTERNAL;
    char *texts = calloc(count, length + 1u);
    maelys_datalog_fact_t *batch = calloc(facts, sizeof(*batch));
    if (!texts || !batch) {
        free(texts);
        free(batch);
        return MAELYS_DATALOG_STATUS_INTERNAL;
    }
    for (size_t i = 0u; i < count; ++i) {
        char *text = texts + i * (length + 1u);
        memset(text, 's', length);
        (void)snprintf(text, 6u, "%05zu", i);
        text[5] = 's';
        text[length] = '\0';
    }
    batch[0].predicate = "request";
    batch[0].arity = 1u;
    batch[0].terms[0] = (maelys_datalog_value_t){.kind = MAELYS_DATALOG_VALUE_SYMBOL, .as.symbol = "r"};
    for (size_t f = 1u; f < facts; ++f) {
        maelys_datalog_fact_t *fact = &batch[f];
        fact->predicate = k_names[(f - 1u) / per_predicate];
        fact->arity = 4u;
        for (size_t t = 0u; t < 4u; ++t) {
            size_t index = (f - 1u) * 4u + t;
            if (index >= count) index = count - 1u; /* repeats add no symbol */
            fact->terms[t] = (maelys_datalog_value_t){.kind = MAELYS_DATALOG_VALUE_SYMBOL,
                                                      .as.symbol = texts + index * (length + 1u)};
        }
    }
    maelys_datalog_result_t *result = NULL;
    maelys_datalog_status_t status = maelys_datalog_session_solve(session, batch, facts, &result, diagnostic);
    if (result) (void)maelys_datalog_result_free(result);
    free(texts);
    free(batch);
    return status;
}

/* The section a refusal carries: its bound by name, the attempted count
 * above the bound, the bound the engine reads out. */
static int capacity(const maelys_datalog_diagnostic_t *diagnostic, maelys_datalog_limit_t kind) {
    size_t bound = 0u;
    CHECK(maelys_datalog_limit_get(kind, &bound) == MAELYS_DATALOG_STATUS_OK);
    CHECK((diagnostic->present & MAELYS_DATALOG_DIAGNOSTIC_CAPACITY) != 0u);
    CHECK(diagnostic->limit_kind == kind && diagnostic->limit == bound);
    CHECK(diagnostic->observed_count > diagnostic->limit);
    return 1;
}

int main(void) {
    maelys_datalog_policy_t *policy = NULL;
    maelys_datalog_session_t *session = open_session(&policy);
    if (!session) {
        (void)fprintf(stderr, "FAIL: the contract policy does not open\n");
        return 1;
    }
    int ok = 1;
    size_t symbols = 0u, pool = 0u;
    if (maelys_datalog_limit_get(MAELYS_DATALOG_LIMIT_MAX_SYMBOLS, &symbols) != MAELYS_DATALOG_STATUS_OK ||
        maelys_datalog_limit_get(MAELYS_DATALOG_LIMIT_STRING_POOL_BYTES, &pool) != MAELYS_DATALOG_STATUS_OK)
        ok = 0;
    /* One symbol more than the engine holds, each short. */
    maelys_datalog_diagnostic_t diagnostic = MAELYS_DATALOG_DIAGNOSTIC_INIT;
    if (ok && (solve_symbols(session, symbols + 1u, 6u, &diagnostic) != MAELYS_DATALOG_STATUS_PAYLOAD_TOO_LARGE ||
               !capacity(&diagnostic, MAELYS_DATALOG_LIMIT_MAX_SYMBOLS)))
        ok = 0;
    /* Few symbols, beyond the pool of text: 999 bytes each. */
    size_t long_symbols = pool / 1000u + 1u;
    (void)maelys_datalog_diagnostic_clear(&diagnostic);
    if (ok && (solve_symbols(session, long_symbols, 999u, &diagnostic) != MAELYS_DATALOG_STATUS_PAYLOAD_TOO_LARGE ||
               !capacity(&diagnostic, MAELYS_DATALOG_LIMIT_STRING_POOL_BYTES)))
        ok = 0;
    /* A refused batch leaves the session usable: a small one decides. */
    (void)maelys_datalog_diagnostic_clear(&diagnostic);
    if (ok && solve_symbols(session, 8u, 6u, &diagnostic) != MAELYS_DATALOG_STATUS_OK) ok = 0;
    (void)maelys_datalog_session_free(session);
    (void)maelys_datalog_policy_free(policy);
    if (ok)
        (void)printf("engine contract: input symbols beyond %zu and text beyond %zu bytes are named capacities: ok\n",
                     symbols, pool);
    return ok ? 0 : 1;
}
