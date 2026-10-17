/* A consumer of the installed Maelys Datalog SDK and of nothing else: it is
 * compiled against the prefix `cmake --install` produced, never against the
 * engine tree. It holds what Maelys Git Core relies on but does not use
 * itself: the closed mode a manifest gets without the permission, and a
 * registered domain that cannot be changed. */
#include <maelys/datalog.h>

#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

int main(int argc, char **argv) {
    if (argc != 2) {
        (void)fprintf(stderr, "usage: %s MANIFEST\n", argv[0]);
        return 2;
    }
    CHECK(MAELYS_DATALOG_PUBLIC_API_VERSION == 2u);
    /* The predicates the filter fixture uses, declared with the SDK builders. */
    static const maelys_datalog_predicate_t predicates[] = {
        MAELYS_DATALOG_EDB("request", 1u), MAELYS_DATALOG_EDB("user", 1u),
        MAELYS_DATALOG_EDB("repository", 1u), MAELYS_DATALOG_EDB("operation", 1u),
        MAELYS_DATALOG_EDB("ref", 1u), MAELYS_DATALOG_EDB("path", 1u),
        MAELYS_DATALOG_IDB_QUERY("allow", 1u), MAELYS_DATALOG_IDB_QUERY("deny", 1u),
    };
    static const maelys_datalog_domain_t domain =
        MAELYS_DATALOG_DOMAIN_NO_ATOMS("maelys_git", predicates);
    CHECK(maelys_datalog_domain_register(&domain) == MAELYS_DATALOG_STATUS_OK);

    /* Without the permission a policy constant must be declared by the domain. */
    maelys_datalog_diagnostic_t diagnostic = MAELYS_DATALOG_DIAGNOSTIC_INIT;
    maelys_datalog_policy_t *policy = NULL;
    maelys_datalog_status_t status = maelys_datalog_policy_load_manifest(
        argv[1], MAELYS_DATALOG_PUBLIC_ALLOW_NONE, &policy, &diagnostic);
    CHECK(status != MAELYS_DATALOG_STATUS_OK && policy == NULL);
    CHECK(diagnostic.code == MAELYS_DATALOG_DIAG_PARSER_UNKNOWN_ATOM);
    CHECK(!strcmp(maelys_datalog_diag_code_name(diagnostic.code), "parser_unknown_atom"));

    /* With it the same manifest loads, and the constants stay in the policy. */
    CHECK(maelys_datalog_diagnostic_clear(&diagnostic) == MAELYS_DATALOG_STATUS_OK);
    status = maelys_datalog_policy_load_manifest(
        argv[1], MAELYS_DATALOG_PUBLIC_ALLOW_UNDECLARED_POLICY_ATOMS, &policy, &diagnostic);
    CHECK(status == MAELYS_DATALOG_STATUS_OK && policy != NULL);
    size_t count = 0u;
    CHECK(maelys_datalog_policy_count(policy, &count) == MAELYS_DATALOG_STATUS_OK && count == 2u);
    CHECK(maelys_datalog_policy_free(policy) == MAELYS_DATALOG_STATUS_OK);
    policy = NULL;
    /* The permission of one load is not kept for the next. */
    status = maelys_datalog_policy_load_manifest(
        argv[1], MAELYS_DATALOG_PUBLIC_ALLOW_NONE, &policy, &diagnostic);
    CHECK(status != MAELYS_DATALOG_STATUS_OK && policy == NULL);
    /* An unknown permission bit is refused, never ignored. */
    status = maelys_datalog_policy_load_manifest(argv[1], 1u << 7, &policy, &diagnostic);
    CHECK(status == MAELYS_DATALOG_STATUS_INVALID_ARGUMENT && policy == NULL);

    /* A registered domain accepts itself again and nothing else. */
    CHECK(maelys_datalog_domain_register(&domain) == MAELYS_DATALOG_STATUS_OK);
    static const maelys_datalog_predicate_t other[] = {MAELYS_DATALOG_EDB("request", 1u)};
    static const maelys_datalog_domain_t divergent =
        MAELYS_DATALOG_DOMAIN_NO_ATOMS("maelys_git", other);
    CHECK(maelys_datalog_domain_register(&divergent) == MAELYS_DATALOG_STATUS_INVALID_FIELD);
    static const char *const atoms[] = {"alice"};
    static const maelys_datalog_domain_t extended =
        MAELYS_DATALOG_DOMAIN_WITH_ATOMS("maelys_git", predicates, atoms);
    CHECK(maelys_datalog_domain_register(&extended) == MAELYS_DATALOG_STATUS_INVALID_FIELD);

    /* The capacities Maelys Git Core reads exist and are positive. */
    static const maelys_datalog_limit_t limits[] = {
        MAELYS_DATALOG_LIMIT_MAX_EDB_FACTS, MAELYS_DATALOG_LIMIT_MAX_FACTS_PER_PRED,
        MAELYS_DATALOG_LIMIT_MAX_RULES, MAELYS_DATALOG_LIMIT_MAX_POLICY_ATOMS,
        MAELYS_DATALOG_LIMIT_MAX_POLICY_ATOM_BYTES};
    for (size_t i = 0u; i < sizeof(limits) / sizeof(limits[0]); ++i) {
        size_t value = 0u;
        CHECK(maelys_datalog_limit_get(limits[i], &value) == MAELYS_DATALOG_STATUS_OK && value > 0u);
    }
    (void)puts("installed SDK consumer: closed mode, permission scope and immutable domain: ok");
    return 0;
}
