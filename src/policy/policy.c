#include "internal.h"

#include "include/maelys_datalog.h"

#include <stdbool.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct maelys_git_policy {
    maelys_datalog_policy_set_t set;
};

static char s_policy_atoms[MAELYS_DATALOG_MAX_ATOMS][64];
static size_t s_policy_atom_count;
static atomic_flag s_policy_load_lock = ATOMIC_FLAG_INIT;

static const maelys_datalog_predicate_def_t k_git_domain[] = {
    {.name = "request", .arity = 1, .kind_flags = MAELYS_DATALOG_PRED_KIND_EDB},
    {.name = "user", .arity = 1, .kind_flags = MAELYS_DATALOG_PRED_KIND_EDB},
    {.name = "repository", .arity = 1, .kind_flags = MAELYS_DATALOG_PRED_KIND_EDB},
    {.name = "operation", .arity = 1, .kind_flags = MAELYS_DATALOG_PRED_KIND_EDB},
    {.name = "ref", .arity = 1, .kind_flags = MAELYS_DATALOG_PRED_KIND_EDB},
    {.name = "path", .arity = 1, .kind_flags = MAELYS_DATALOG_PRED_KIND_EDB},
    {.name = "ssh_key", .arity = 1, .kind_flags = MAELYS_DATALOG_PRED_KIND_EDB},
    {.name = "remote_address", .arity = 1, .kind_flags = MAELYS_DATALOG_PRED_KIND_EDB},
    {.name = "group_member", .arity = 2, .kind_flags = MAELYS_DATALOG_PRED_KIND_POLICY_FACT},
    {.name = "grant_read", .arity = 2, .kind_flags = MAELYS_DATALOG_PRED_KIND_POLICY_FACT},
    {.name = "grant_write", .arity = 2, .kind_flags = MAELYS_DATALOG_PRED_KIND_POLICY_FACT},
    {.name = "grant_push", .arity = 2, .kind_flags = MAELYS_DATALOG_PRED_KIND_POLICY_FACT},
    {.name = "grant_create", .arity = 2, .kind_flags = MAELYS_DATALOG_PRED_KIND_POLICY_FACT},
    {.name = "group_grant_read", .arity = 2, .kind_flags = MAELYS_DATALOG_PRED_KIND_POLICY_FACT},
    {.name = "group_grant_write", .arity = 2, .kind_flags = MAELYS_DATALOG_PRED_KIND_POLICY_FACT},
    {.name = "group_grant_push", .arity = 2, .kind_flags = MAELYS_DATALOG_PRED_KIND_POLICY_FACT},
    {.name = "group_grant_create", .arity = 2, .kind_flags = MAELYS_DATALOG_PRED_KIND_POLICY_FACT},
    {.name = "admin", .arity = 1, .kind_flags = MAELYS_DATALOG_PRED_KIND_POLICY_FACT},
    {.name = "protected_ref", .arity = 1, .kind_flags = MAELYS_DATALOG_PRED_KIND_POLICY_FACT},
    {.name = "protected_path", .arity = 1, .kind_flags = MAELYS_DATALOG_PRED_KIND_POLICY_FACT},
    {.name = "allow",
     .arity = 1,
     .kind_flags = MAELYS_DATALOG_PRED_KIND_IDB | MAELYS_DATALOG_PRED_KIND_QUERY},
    {.name = "deny",
     .arity = 1,
     .kind_flags = MAELYS_DATALOG_PRED_KIND_IDB | MAELYS_DATALOG_PRED_KIND_QUERY},
};

static maelys_result_t install_git_domain(maelys_datalog_predicate_registry_t *registry) {
    maelys_result_t result = MAELYS_OK;
    for (size_t i = 0u; result == MAELYS_OK && i < sizeof(k_git_domain) / sizeof(k_git_domain[0]); ++i) {
        result = maelys_datalog_predicate_registry_add_domain(registry,
                                                               k_git_domain[i].name,
                                                               k_git_domain[i].arity,
                                                               k_git_domain[i].kind_flags);
    }
    for (size_t i = 0u; result == MAELYS_OK && i < s_policy_atom_count; ++i) {
        result = maelys_datalog_predicate_registry_add_atom(registry, s_policy_atoms[i]);
    }
    return result;
}

static maelys_result_t register_git_domain(void) {
    static const maelys_datalog_domain_def_t definition = {
        .domain_name = "maelys_git",
        .predicates = NULL,
        .predicate_count = 0u,
        .description = "Git authorization requests, grants, groups, refs and paths",
        .install_predicates = install_git_domain,
    };
    return maelys_datalog_domain_registry_register(&definition);
}

static int add_policy_atom(const char *value, size_t length) {
    if (length == 0u || length >= sizeof(s_policy_atoms[0])) return 0;
    for (size_t i = 0u; i < s_policy_atom_count; ++i) {
        if (strlen(s_policy_atoms[i]) == length && memcmp(s_policy_atoms[i], value, length) == 0) return 1;
    }
    if (s_policy_atom_count >= MAELYS_DATALOG_MAX_ATOMS) return 0;
    memcpy(s_policy_atoms[s_policy_atom_count], value, length);
    s_policy_atoms[s_policy_atom_count][length] = '\0';
    ++s_policy_atom_count;
    return 1;
}

static int collect_source_atoms(const char *source, maelys_git_error_t *error) {
    for (const char *cursor = source; *cursor; ++cursor) {
        if (*cursor != '"') continue;
        ++cursor;
        char value[64];
        size_t used = 0u;
        while (*cursor && *cursor != '"') {
            unsigned char ch = (unsigned char)*cursor++;
            if (ch == '\\') {
                char escaped = *cursor++;
                switch (escaped) {
                    case '"': ch = '"'; break;
                    case '\\': ch = '\\'; break;
                    case 'n': ch = '\n'; break;
                    case 'r': ch = '\r'; break;
                    case 't': ch = '\t'; break;
                    default:
                        mg_error_set(error, MAELYS_GIT_ERR_POLICY, 0, "unsupported escape in policy atom");
                        return 0;
                }
            }
            if (used + 1u >= sizeof(value)) {
                mg_error_set(error, MAELYS_GIT_ERR_POLICY, 0, "policy atom exceeds 63 bytes");
                return 0;
            }
            value[used++] = (char)ch;
        }
        if (*cursor != '"' || !add_policy_atom(value, used)) {
            mg_error_set(error, MAELYS_GIT_ERR_POLICY, 0, "invalid or excessive policy atom vocabulary");
            return 0;
        }
    }
    return 1;
}

static char *read_text_file(const char *path, size_t max_size, maelys_git_error_t *error) {
    FILE *file = fopen(path, "rb");
    if (!file) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno, "cannot open %s: %s", path, strerror(errno));
        return NULL;
    }
    char *data = malloc(max_size + 1u);
    if (!data) { fclose(file); return NULL; }
    size_t length = fread(data, 1u, max_size + 1u, file);
    int failed = ferror(file);
    fclose(file);
    if (failed || length > max_size) {
        free(data);
        mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0, "%s exceeds the one-megabyte policy limit", path);
        return NULL;
    }
    data[length] = '\0';
    return data;
}

static int policy_path_is_safe(const char *path) {
    if (!path || !*path || path[0] == '/') return 0;
    const char *component = path;
    for (const char *p = path;; ++p) {
        if (*p == '/' || *p == '\0') {
            size_t length = (size_t)(p - component);
            if (length == 0u || (length == 1u && component[0] == '.') ||
                (length == 2u && component[0] == '.' && component[1] == '.')) return 0;
            if (*p == '\0') break;
            component = p + 1u;
        } else if (!(isalnum((unsigned char)*p) || *p == '.' || *p == '_' || *p == '-')) {
            return 0;
        }
    }
    return 1;
}

static int collect_manifest_atoms(const char *manifest_path, maelys_git_error_t *error) {
    s_policy_atom_count = 0u;
    char *manifest = read_text_file(manifest_path, 1024u * 1024u, error);
    if (!manifest) return 0;
    char directory[4096];
    if (!mg_copy_string(directory, sizeof(directory), manifest_path)) { free(manifest); return 0; }
    char *slash = strrchr(directory, '/');
    if (slash) *slash = '\0';
    else (void)mg_copy_string(directory, sizeof(directory), ".");

    size_t file_count = 0u;
    const char *cursor = manifest;
    while ((cursor = strstr(cursor, "\"file\"")) != NULL) {
        cursor += 6u;
        while (isspace((unsigned char)*cursor)) ++cursor;
        if (*cursor++ != ':') continue;
        while (isspace((unsigned char)*cursor)) ++cursor;
        if (*cursor++ != '"') continue;
        const char *end = strchr(cursor, '"');
        if (!end) break;
        size_t length = (size_t)(end - cursor);
        char relative[512];
        if (length >= sizeof(relative)) { free(manifest); return 0; }
        memcpy(relative, cursor, length);
        relative[length] = '\0';
        if (!policy_path_is_safe(relative)) {
            free(manifest);
            mg_error_set(error, MAELYS_GIT_ERR_POLICY, 0, "unsafe policy file path in manifest");
            return 0;
        }
        char full_path[4096];
        int count = snprintf(full_path, sizeof(full_path), "%s/%s", directory, relative);
        if (count < 0 || (size_t)count >= sizeof(full_path)) { free(manifest); return 0; }
        char *source = read_text_file(full_path, 1024u * 1024u, error);
        if (!source || !collect_source_atoms(source, error)) {
            free(source);
            free(manifest);
            return 0;
        }
        free(source);
        ++file_count;
        cursor = end + 1u;
    }
    free(manifest);
    if (file_count == 0u) {
        mg_error_set(error, MAELYS_GIT_ERR_POLICY, 0, "manifest contains no policy file");
        return 0;
    }
    return 1;
}

static maelys_git_result_t datalog_failure(maelys_git_error_t *error,
                                           const char *operation,
                                           maelys_result_t result) {
    mg_error_set(error,
                 MAELYS_GIT_ERR_POLICY,
                 0,
                 "%s failed with Maelys Datalog error %d",
                 operation,
                 (int)result);
    return MAELYS_GIT_ERR_POLICY;
}

static maelys_git_result_t policy_open_unlocked(const char *manifest_path,
                                                 maelys_git_policy_t **out_policy,
                                                 maelys_git_error_t *error) {
    maelys_git_error_clear(error);
    if (!manifest_path || !out_policy) {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_ARGUMENT, 0, "manifest path and output are required");
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    }
    *out_policy = NULL;
    if (!collect_manifest_atoms(manifest_path, error)) return MAELYS_GIT_ERR_POLICY;
    maelys_result_t result = register_git_domain();
    if (result != MAELYS_OK) return datalog_failure(error, "domain registration", result);

    maelys_git_policy_t *policy = calloc(1u, sizeof(*policy));
    if (!policy) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, 0, "unable to allocate policy engine");
        return MAELYS_GIT_ERR_IO;
    }
    maelys_datalog_diagnostic_t diagnostic;
    result = maelys_datalog_manifest_load_ex(manifest_path, 0u, &policy->set, &diagnostic);
    if (result != MAELYS_OK) {
        mg_error_set(error,
                     MAELYS_GIT_ERR_POLICY,
                     0,
                     "policy load failed (%s): %s%s%s",
                     maelys_datalog_diag_code_name(diagnostic.code),
                     diagnostic.message,
                     diagnostic.hint[0] ? "; " : "",
                     diagnostic.hint);
        free(policy);
        return MAELYS_GIT_ERR_POLICY;
    }
    if (policy->set.policy_count == 0u) {
        maelys_datalog_policy_set_clear(&policy->set);
        free(policy);
        mg_error_set(error, MAELYS_GIT_ERR_POLICY, 0, "policy set contains no enabled policy");
        return MAELYS_GIT_ERR_POLICY;
    }
    *out_policy = policy;
    return MAELYS_GIT_OK;
}

maelys_git_result_t maelys_git_policy_open(const char *manifest_path,
                                            maelys_git_policy_t **out_policy,
                                            maelys_git_error_t *error) {
    while (atomic_flag_test_and_set_explicit(&s_policy_load_lock, memory_order_acquire)) {
    }
    maelys_git_result_t result = policy_open_unlocked(manifest_path, out_policy, error);
    atomic_flag_clear_explicit(&s_policy_load_lock, memory_order_release);
    return result;
}

void maelys_git_policy_close(maelys_git_policy_t *policy) {
    if (!policy) return;
    maelys_datalog_policy_set_clear(&policy->set);
    free(policy);
}

static maelys_result_t add_optional_fact(maelys_datalog_edb_t *edb,
                                         const char *predicate,
                                         const char *value) {
    if (!value || !*value) return MAELYS_OK;
    return maelys_datalog_edb_add_runtime_symbol_fact(edb, predicate, value);
}

static maelys_git_result_t solve_policy(const maelys_datalog_ruleset_t *source_ruleset,
                                        const maelys_git_policy_request_t *request,
                                        int *out_allow,
                                        int *out_deny,
                                        maelys_git_error_t *error) {
    maelys_datalog_ruleset_t *ruleset = malloc(sizeof(*ruleset));
    if (!ruleset) return MAELYS_GIT_ERR_IO;
    memcpy(ruleset, source_ruleset, sizeof(*ruleset));
    maelys_datalog_fact_t *facts = calloc(MAELYS_DATALOG_MAX_EDB_FACTS, sizeof(*facts));
    if (!facts) {
        free(ruleset);
        mg_error_set(error, MAELYS_GIT_ERR_IO, 0, "unable to allocate Datalog fact pool");
        return MAELYS_GIT_ERR_IO;
    }
    maelys_datalog_edb_t *edb = calloc(1u, sizeof(*edb));
    if (!edb) {
        free(facts);
        free(ruleset);
        mg_error_set(error, MAELYS_GIT_ERR_IO, 0, "unable to allocate Datalog EDB");
        return MAELYS_GIT_ERR_IO;
    }

    maelys_result_t rc = maelys_datalog_edb_init(edb,
                                                  facts,
                                                  MAELYS_DATALOG_MAX_EDB_FACTS,
                                                  &ruleset->symbols,
                                                  &ruleset->registry);
    const char *request_id = request->request_id && *request->request_id
                                 ? request->request_id
                                 : "request";
    maelys_datalog_symbol_id_t request_symbol = MAELYS_DATALOG_SYMBOL_ID_INVALID;
    if (rc == MAELYS_OK) rc = maelys_datalog_edb_intern_runtime_symbol(edb, request_id, &request_symbol);
    if (rc == MAELYS_OK) rc = maelys_datalog_edb_add_symbol_id_fact(edb, "request", request_symbol);
    if (rc == MAELYS_OK) rc = add_optional_fact(edb, "user", request->principal);
    if (rc == MAELYS_OK) rc = add_optional_fact(edb, "repository", request->repository);
    if (rc == MAELYS_OK) rc = add_optional_fact(edb, "operation", request->operation);
    if (rc == MAELYS_OK) rc = add_optional_fact(edb, "ref", request->ref_name);
    if (rc == MAELYS_OK) rc = add_optional_fact(edb, "ssh_key", request->ssh_key);
    if (rc == MAELYS_OK) rc = add_optional_fact(edb, "remote_address", request->remote_address);
    if (request->path_count > MAELYS_DATALOG_MAX_FACTS_PER_PRED) rc = MAELYS_ERR_PAYLOAD_TOO_LARGE;
    for (size_t i = 0u; rc == MAELYS_OK && i < request->path_count; ++i) {
        rc = add_optional_fact(edb, "path", request->paths[i]);
    }
    if (rc == MAELYS_OK) rc = maelys_datalog_edb_finalize(edb);
    if (rc != MAELYS_OK) {
        free(edb);
        free(facts);
        free(ruleset);
        return datalog_failure(error, "request fact construction", rc);
    }

    maelys_datalog_solve_result_t *solve_result = NULL;
    maelys_datalog_solve_diagnostic_t solve_diagnostic;
    rc = maelys_datalog_solve_once_ex(ruleset, edb, &solve_result, &solve_diagnostic);
    if (rc != MAELYS_OK) {
        mg_error_set(error,
                     MAELYS_GIT_ERR_POLICY,
                     0,
                     "policy solve failed: %s",
                     maelys_datalog_solve_diagnostic_category_name(solve_diagnostic.category));
        free(edb);
        free(facts);
        free(ruleset);
        return MAELYS_GIT_ERR_POLICY;
    }

    maelys_datalog_term_t query = {.kind = MAELYS_DATALOG_TERM_SYMBOL};
    query.as.symbol = request_symbol;
    bool allow = false;
    bool deny = false;
    rc = maelys_datalog_query_solved_ground_fact(solve_result, "deny", &query, 1u, &deny);
    if (rc == MAELYS_OK) {
        rc = maelys_datalog_query_solved_ground_fact(solve_result, "allow", &query, 1u, &allow);
    }
    maelys_datalog_solve_result_free(solve_result);
    free(edb);
    free(facts);
    free(ruleset);
    if (rc != MAELYS_OK) return datalog_failure(error, "decision query", rc);
    *out_allow = allow ? 1 : 0;
    *out_deny = deny ? 1 : 0;
    return MAELYS_GIT_OK;
}

maelys_git_result_t maelys_git_policy_authorize(maelys_git_policy_t *policy,
                                                 const maelys_git_policy_request_t *request,
                                                 maelys_git_policy_decision_t *out_decision,
                                                 maelys_git_error_t *error) {
    maelys_git_error_clear(error);
    if (!policy || !request || !out_decision || !request->principal ||
        !*request->principal || !request->repository || !*request->repository ||
        !request->operation || !*request->operation ||
        (request->path_count > 0u && !request->paths)) {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_ARGUMENT, 0, "principal, repository and operation are required");
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    }
    for (size_t i = 0u; i < request->path_count; ++i) {
        if (!request->paths[i] || !*request->paths[i]) {
            mg_error_set(error, MAELYS_GIT_ERR_INVALID_ARGUMENT, 0, "request paths must be non-empty");
            return MAELYS_GIT_ERR_INVALID_ARGUMENT;
        }
    }
    memset(out_decision, 0, sizeof(*out_decision));
    out_decision->matched_policy = SIZE_MAX;
    int saw_allow = 0;
    size_t allow_policy = SIZE_MAX;
    for (size_t i = 0u; i < policy->set.policy_count; ++i) {
        int allow = 0;
        int deny = 0;
        maelys_git_result_t result = solve_policy(&policy->set.policies[i], request, &allow, &deny, error);
        if (result != MAELYS_GIT_OK) {
            (void)mg_copy_string(out_decision->reason, sizeof(out_decision->reason), "policy evaluation failed; request denied");
            return result;
        }
        if (deny) {
            out_decision->explicit_deny = 1;
            out_decision->matched_policy = i;
            (void)snprintf(out_decision->reason,
                           sizeof(out_decision->reason),
                           "explicit deny from policy %s",
                           policy->set.policies[i].policy_id);
            return MAELYS_GIT_OK;
        }
        if (allow && !saw_allow) {
            saw_allow = 1;
            allow_policy = i;
        }
    }
    if (saw_allow) {
        out_decision->allowed = 1;
        out_decision->matched_policy = allow_policy;
        (void)snprintf(out_decision->reason,
                       sizeof(out_decision->reason),
                       "allowed by policy %s",
                       policy->set.policies[allow_policy].policy_id);
    } else {
        (void)mg_copy_string(out_decision->reason,
                             sizeof(out_decision->reason),
                             "no allow rule matched; denied by default");
    }
    return MAELYS_GIT_OK;
}
