#include "internal.h"

#include <maelys/cli/digest.h>
#include <maelys/datalog.h>
#include <maelys/datalog_explanations.h>

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MG_POLICY_ID_MAX 128u

/* The bound of Git Core that refused a request's facts, if any. */
typedef enum {
    REQUEST_BOUND_NONE = 0,
    REQUEST_BOUND_EDB_FACTS,  /* the fact buffer, MAX_EDB_FACTS */
    REQUEST_BOUND_PATHS,      /* one fact per path, MAX_FACTS_PER_PRED */
    REQUEST_BOUND_INTEGER     /* a value beyond INT64_MAX */
} request_bound_t;

/* One enabled policy of the manifest: its session, kept for the life of the
 * handle and reused by every request, and what a decision reports about it. */
typedef struct {
    maelys_datalog_session_t *session;
    char policy_id[MG_POLICY_ID_MAX];
    char fingerprint[MAELYS_DATALOG_PUBLIC_FINGERPRINT_BYTES];
} policy_entry_t;

/* A policy handle is thread-confined. Its fact buffer and its sessions are
 * allocated once by maelys_git_policy_open(); an authorization allocates
 * nothing in this file. The capacities are read from the loaded engine. */
struct maelys_git_policy {
    policy_entry_t *entries;
    size_t count;
    maelys_datalog_fact_t *facts;
    size_t fact_capacity;
    size_t fact_count;
    size_t path_limit;
    request_bound_t exceeded; /* the bound that refused the last request facts */
    char repository_copy[MAELYS_GIT_MAX_REPOSITORY];
    /* The first '/'-terminated prefixes of the request's ref, one string each. */
    char ref_prefixes[MG_REF_PREFIX_FACTS][MAELYS_GIT_MAX_REF];
    char fingerprint[MAELYS_DATALOG_PUBLIC_FINGERPRINT_BYTES];
    /* Allocated by the first explanation, kept until close: the storage of a
     * prepared explanation, and the document rendered from it. */
    void *explanation_storage;
    size_t explanation_storage_bytes;
    char *text;
    size_t text_capacity;
};

/* The schema of the maelys_git domain: predicates only. Constants written in
 * a policy belong to that policy (ALLOW_UNDECLARED_POLICY_ATOMS), filter
 * patterns to its rules, and request values to the session. */
static const maelys_datalog_predicate_t k_git_domain[] = {
    {"request", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"user", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"repository", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"repository_segment", 2u, MAELYS_DATALOG_PREDICATE_EDB},
    {"repository_depth", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"repository_leaf", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"repository_owner_namespace", 2u, MAELYS_DATALOG_PREDICATE_EDB},
    {"operation", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"ref", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"ref_prefix", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"ref_prefix_count", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"path", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"old_path", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"ref_kind", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"update_kind", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"change_kind", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"changed_count", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"added_count", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"modified_count", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"deleted_count", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"renamed_count", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"max_new_blob_size", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"total_new_blob_size", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"commit_count", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"merge_commit_count", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"has_binary", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"change_blob_size", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"old_mode", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"new_mode", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"change_binary", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"change_symlink", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"change_submodule", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"change_lfs_pointer", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"commit_email", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"commit_signed", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"commit_signature_status", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"commit_signer_fingerprint", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"commit_signer_identity", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"commit_signature_trusted", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"ssh_key", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"remote_address", 1u, MAELYS_DATALOG_PREDICATE_EDB},
    {"group_member", 2u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"group_in_group", 2u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"effective_group_member", 2u, MAELYS_DATALOG_PREDICATE_IDB},
    {"grant_read", 2u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"grant_write", 2u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"grant_push", 2u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"grant_force", 2u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"grant_create", 2u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"group_grant_read", 2u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"group_grant_write", 2u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"group_grant_push", 2u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"group_grant_force", 2u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"group_grant_create", 2u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"delegate_namespace", 2u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"group_delegate_namespace", 2u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"owned_repository", 1u, MAELYS_DATALOG_PREDICATE_IDB},
    {"namespace_creator", 2u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"group_namespace_creator", 2u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"can_create_namespace", 2u, MAELYS_DATALOG_PREDICATE_IDB},
    {"owner_namespace_grant_read", 1u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"owner_namespace_grant_write", 1u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"owner_namespace_grant_push", 1u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"owner_namespace_grant_force", 1u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"admin", 1u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"protected_ref", 1u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"protected_branch", 1u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"protected_tag", 1u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"require_signed_ref", 1u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"allowed_commit_email", 1u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"protected_path", 1u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"vref_deny_name", 3u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"group_vref_deny_name", 3u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"vref_deny_count", 3u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"group_vref_deny_count", 3u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"vref_deny_new_count", 3u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"group_vref_deny_new_count", 3u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"vref_deny_max_new_binary", 3u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"group_vref_deny_max_new_binary", 3u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"ref_grant_push", 3u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"group_ref_grant_push", 3u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"ref_grant_force", 3u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"group_ref_grant_force", 3u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"ref_deny", 3u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"group_ref_deny", 3u, MAELYS_DATALOG_PREDICATE_POLICY_FACT},
    {"effective_ref_grant_push", 3u, MAELYS_DATALOG_PREDICATE_IDB},
    {"effective_ref_grant_force", 3u, MAELYS_DATALOG_PREDICATE_IDB},
    {"effective_ref_deny", 3u, MAELYS_DATALOG_PREDICATE_IDB},
    {"push_request", 4u, MAELYS_DATALOG_PREDICATE_IDB},
    {"has_ref_write", 2u, MAELYS_DATALOG_PREDICATE_IDB},
    {"has_push_access", 2u, MAELYS_DATALOG_PREDICATE_IDB},
    {"effective_vref_deny_name", 3u, MAELYS_DATALOG_PREDICATE_IDB},
    {"effective_vref_deny_count", 3u, MAELYS_DATALOG_PREDICATE_IDB},
    {"effective_vref_deny_new_count", 3u, MAELYS_DATALOG_PREDICATE_IDB},
    {"effective_vref_deny_max_new_binary", 3u, MAELYS_DATALOG_PREDICATE_IDB},
    {"vref_count_exceeded", 2u, MAELYS_DATALOG_PREDICATE_IDB},
    {"vref_new_count_exceeded", 2u, MAELYS_DATALOG_PREDICATE_IDB},
    {"vref_new_binary_exceeded", 2u, MAELYS_DATALOG_PREDICATE_IDB},
    {"allow", 1u, MAELYS_DATALOG_PREDICATE_IDB | MAELYS_DATALOG_PREDICATE_QUERY},
    {"deny", 1u, MAELYS_DATALOG_PREDICATE_IDB | MAELYS_DATALOG_PREDICATE_QUERY},
};

/* The engine keeps domains for the life of the process and accepts an
 * identical registration again; one call suffices and gives every thread the
 * same answer. */
static pthread_once_t s_domain_once = PTHREAD_ONCE_INIT;
static maelys_datalog_status_t s_domain_status = MAELYS_DATALOG_STATUS_INVALID_STATE;

static void register_git_domain(void) {
    static const maelys_datalog_domain_t domain =
        MAELYS_DATALOG_DOMAIN_NO_ATOMS("maelys_git", k_git_domain);
    s_domain_status = maelys_datalog_domain_register(&domain);
}

static maelys_git_result_t engine_failure(maelys_git_error_t *error,
                                          const char *operation,
                                          maelys_datalog_status_t status) {
    mg_error_set(error, MAELYS_GIT_ERR_POLICY, 0, "%s failed: %s", operation,
                 maelys_datalog_status_name(status));
    return MAELYS_GIT_ERR_POLICY;
}

/* The kind of failure a diagnostic code reports, by an explicit table over
 * the engine's enumeration. A code this table does not know, including one a
 * later engine adds, is an engine failure. A capacity section overrides it. */
static maelys_git_failure_kind_t failure_kind(maelys_datalog_diag_code_t code) {
    switch (code) {
        case MAELYS_DATALOG_DIAG_MANIFEST_INVALID_JSON:
        case MAELYS_DATALOG_DIAG_MANIFEST_INVALID_FIELD:
        case MAELYS_DATALOG_DIAG_MANIFEST_UNKNOWN_FIELD:
        case MAELYS_DATALOG_DIAG_MANIFEST_UNKNOWN_DOMAIN:
        case MAELYS_DATALOG_DIAG_MANIFEST_SHA_MISMATCH:
        case MAELYS_DATALOG_DIAG_MANIFEST_POLICY_NOT_FOUND:
        case MAELYS_DATALOG_DIAG_MANIFEST_TEST_ONLY_REJECTED:
            return MAELYS_GIT_FAILURE_MANIFEST;
        case MAELYS_DATALOG_DIAG_LEXER_INVALID_TOKEN:
        case MAELYS_DATALOG_DIAG_LEXER_UNSUPPORTED_CONSTRUCT:
        case MAELYS_DATALOG_DIAG_LEXER_INVALID_UTF8:
        case MAELYS_DATALOG_DIAG_LEXER_STRING_TOO_LONG:
        case MAELYS_DATALOG_DIAG_PARSER_EXPECTED_PREDICATE:
        case MAELYS_DATALOG_DIAG_PARSER_EXPECTED_DOT:
        case MAELYS_DATALOG_DIAG_PARSER_EXPECTED_NECK:
            return MAELYS_GIT_FAILURE_SYNTAX;
        case MAELYS_DATALOG_DIAG_PARSER_UNKNOWN_PREDICATE:
        case MAELYS_DATALOG_DIAG_PARSER_ARITY_MISMATCH:
        case MAELYS_DATALOG_DIAG_PARSER_UNKNOWN_ATOM:
        case MAELYS_DATALOG_DIAG_PARSER_RULE_HEAD_EDB_FORBIDDEN:
        case MAELYS_DATALOG_DIAG_PARSER_RULE_BODY_LITERAL_OVERFLOW:
        case MAELYS_DATALOG_DIAG_PARSER_UNSAFE_VARIABLE:
        case MAELYS_DATALOG_DIAG_PARSER_INVALID_COMPARISON:
        case MAELYS_DATALOG_DIAG_PARSER_INVALID_FILTER:
        case MAELYS_DATALOG_DIAG_PARSER_FACT_USES_NON_BASE_PREDICATE:
        case MAELYS_DATALOG_DIAG_PARSER_ANONYMOUS_VARIABLE_IN_HEAD:
        case MAELYS_DATALOG_DIAG_PARSER_ANONYMOUS_VARIABLE_IN_COMPARISON:
        case MAELYS_DATALOG_DIAG_PARSER_ANONYMOUS_VARIABLE_IN_FACT:
        case MAELYS_DATALOG_DIAG_PARSER_TOO_MANY_VARIABLES:
        case MAELYS_DATALOG_DIAG_POLICY_NOT_STRATIFIABLE:
        case MAELYS_DATALOG_DIAG_REGISTRY_CONFLICT:
        case MAELYS_DATALOG_DIAG_REGISTRY_MUTATION_AFTER_FREEZE:
            return MAELYS_GIT_FAILURE_SEMANTICS;
        default:
            return MAELYS_GIT_FAILURE_ENGINE;
    }
}

/* Records what the engine's diagnostic says, after mg_error_set: its code,
 * its location and, for a capacity, the budget by its engine name, the
 * attempted count and the bound in effect. No number comes from a message. */
static void set_diagnostic_detail(maelys_git_error_t *error,
                                  const maelys_datalog_diagnostic_t *diagnostic) {
    maelys_git_failure_detail_t detail = {.kind = MAELYS_GIT_FAILURE_ENGINE};
    if (diagnostic->source != MAELYS_DATALOG_DIAGNOSTIC_NONE) {
        detail.kind = failure_kind(diagnostic->code);
        (void)mg_copy_string(detail.diagnostic, sizeof(detail.diagnostic),
                             maelys_datalog_diag_code_name(diagnostic->code));
        if (diagnostic->present & MAELYS_DATALOG_DIAGNOSTIC_CAPACITY) {
            const char *budget = maelys_datalog_limit_name(diagnostic->limit_kind);
            detail.kind = MAELYS_GIT_FAILURE_CAPACITY;
            if (budget) (void)mg_copy_string(detail.budget, sizeof(detail.budget), budget);
            detail.requested = diagnostic->observed_count;
            detail.limit = diagnostic->limit;
        }
        (void)mg_copy_string(detail.file, sizeof(detail.file), diagnostic->file);
        if (diagnostic->present & MAELYS_DATALOG_DIAGNOSTIC_LOCATION) {
            detail.line = diagnostic->line;
            detail.column = diagnostic->column;
        }
    }
    mg_error_set_detail(error, &detail);
}

/* A refused manifest reports the engine's own diagnostic: its code, where it
 * is in the policy when the engine located it, and the capacity it exceeded.
 * Whatever the cause, a manifest that does not load is a policy error: the
 * validation report of the command line depends on that single code. */
static maelys_git_result_t load_failure(maelys_git_error_t *error,
                                        maelys_datalog_status_t status,
                                        const maelys_datalog_diagnostic_t *diagnostic) {
    if (diagnostic->source == MAELYS_DATALOG_DIAGNOSTIC_NONE) {
        mg_error_set(error, MAELYS_GIT_ERR_POLICY, 0, "policy load failed: %s",
                     maelys_datalog_status_name(status));
        set_diagnostic_detail(error, diagnostic);
        return MAELYS_GIT_ERR_POLICY;
    }
    char location[384] = "";
    if ((diagnostic->present & MAELYS_DATALOG_DIAGNOSTIC_LOCATION) && diagnostic->line > 0u)
        (void)snprintf(location, sizeof(location), " in %.255s line %zu column %zu",
                       diagnostic->file[0] ? diagnostic->file : "policy", diagnostic->line,
                       diagnostic->column);
    else if (diagnostic->file[0])
        (void)snprintf(location, sizeof(location), " in %.255s", diagnostic->file);
    char capacity[96] = "";
    if (diagnostic->present & MAELYS_DATALOG_DIAGNOSTIC_CAPACITY)
        (void)snprintf(capacity, sizeof(capacity), " (%zu requested, limit %zu)",
                       diagnostic->observed_count, diagnostic->limit);
    mg_error_set(error, MAELYS_GIT_ERR_POLICY, 0, "policy load failed (%s)%s: %s%s%s%s",
                 maelys_datalog_diag_code_name(diagnostic->code), location, diagnostic->message,
                 capacity, diagnostic->hint[0] ? "; " : "", diagnostic->hint);
    set_diagnostic_detail(error, diagnostic);
    return MAELYS_GIT_ERR_POLICY;
}

static maelys_git_result_t read_limit(maelys_datalog_limit_t limit, size_t *out,
                                      maelys_git_error_t *error) {
    maelys_datalog_status_t status = maelys_datalog_limit_get(limit, out);
    return status == MAELYS_DATALOG_STATUS_OK && *out > 0u
               ? MAELYS_GIT_OK : engine_failure(error, "engine limit query", status);
}

size_t mg_policy_explanation_storage_bytes(const maelys_git_policy_t *policy) {
    return policy ? policy->explanation_storage_bytes : 0u;
}

maelys_git_result_t mg_policy_rule_limit(size_t *out_limit, maelys_git_error_t *error) {
    if (!out_limit) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    return read_limit(MAELYS_DATALOG_LIMIT_MAX_RULES, out_limit, error);
}

/* Creates the session of one policy and records its identity. */
static maelys_git_result_t prepare_entry(const maelys_datalog_policy_t *loaded, size_t index,
                                         policy_entry_t *entry, maelys_git_error_t *error) {
    maelys_datalog_status_t status = maelys_datalog_session_create(loaded, index, &entry->session);
    if (status != MAELYS_DATALOG_STATUS_OK)
        return engine_failure(error, "policy session preparation", status);
    status = maelys_datalog_session_fingerprint(entry->session, entry->fingerprint);
    if (status != MAELYS_DATALOG_STATUS_OK)
        return engine_failure(error, "policy session fingerprint", status);
    /* Borrowed from the loaded handle, which open() frees: copied here. */
    const char *policy_id = NULL;
    status = maelys_datalog_policy_id(loaded, index, &policy_id);
    if (status != MAELYS_DATALOG_STATUS_OK)
        return engine_failure(error, "policy identity query", status);
    if (!policy_id || !mg_copy_string(entry->policy_id, sizeof(entry->policy_id), policy_id)) {
        mg_error_set(error, MAELYS_GIT_ERR_POLICY, 0, "policy %zu has no usable identifier", index);
        return MAELYS_GIT_ERR_POLICY;
    }
    return MAELYS_GIT_OK;
}

maelys_git_result_t maelys_git_policy_open(const char *manifest_path,
                                            maelys_git_policy_t **out_policy,
                                            maelys_git_error_t *error) {
    maelys_git_error_clear(error);
    if (!manifest_path || !out_policy) {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_ARGUMENT, 0, "manifest path and output are required");
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    }
    *out_policy = NULL;
    if (pthread_once(&s_domain_once, register_git_domain) != 0 ||
        s_domain_status != MAELYS_DATALOG_STATUS_OK) {
        mg_error_set(error, MAELYS_GIT_ERR_POLICY, 0, "cannot register the maelys_git domain: %s",
                     maelys_datalog_status_name(s_domain_status));
        return MAELYS_GIT_ERR_POLICY;
    }
    /* The engine reads the manifest and its sources, checks their digests and
     * is the only reader of the policy language. */
    maelys_datalog_diagnostic_t diagnostic = MAELYS_DATALOG_DIAGNOSTIC_INIT;
    maelys_datalog_policy_t *loaded = NULL;
    maelys_datalog_status_t status = maelys_datalog_policy_load_manifest(
        manifest_path, MAELYS_DATALOG_PUBLIC_ALLOW_UNDECLARED_POLICY_ATOMS, &loaded, &diagnostic);
    if (status != MAELYS_DATALOG_STATUS_OK) return load_failure(error, status, &diagnostic);

    maelys_git_result_t result = MAELYS_GIT_OK;
    maelys_git_policy_t *policy = calloc(1u, sizeof(*policy));
    if (!policy) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, 0, "unable to allocate policy engine");
        result = MAELYS_GIT_ERR_IO;
    }
    size_t count = 0u;
    if (result == MAELYS_GIT_OK) {
        /* A manifest whose entries are all disabled loads into a handle that
         * holds no policy, which the engine reports as an invalid state. */
        status = maelys_datalog_policy_count(loaded, &count);
        if (status == MAELYS_DATALOG_STATUS_INVALID_STATE ||
            (status == MAELYS_DATALOG_STATUS_OK && count == 0u)) {
            mg_error_set(error, MAELYS_GIT_ERR_POLICY, 0, "manifest contains no enabled policy file");
            const maelys_git_failure_detail_t detail = {.kind = MAELYS_GIT_FAILURE_MANIFEST};
            mg_error_set_detail(error, &detail);
            result = MAELYS_GIT_ERR_POLICY;
        } else if (status != MAELYS_DATALOG_STATUS_OK) {
            result = engine_failure(error, "policy count", status);
        }
    }
    if (result == MAELYS_GIT_OK) {
        status = maelys_datalog_policy_fingerprint(loaded, policy->fingerprint);
        if (status != MAELYS_DATALOG_STATUS_OK)
            result = engine_failure(error, "policy-set fingerprint", status);
    }
    if (result == MAELYS_GIT_OK)
        result = read_limit(MAELYS_DATALOG_LIMIT_MAX_EDB_FACTS, &policy->fact_capacity, error);
    if (result == MAELYS_GIT_OK)
        result = read_limit(MAELYS_DATALOG_LIMIT_MAX_FACTS_PER_PRED, &policy->path_limit, error);
    if (result == MAELYS_GIT_OK && policy->path_limit < MG_REF_PREFIX_FACTS) {
        mg_error_set(error, MAELYS_GIT_ERR_POLICY, 0,
                     "the engine holds %zu facts per predicate, fewer than the %u ref prefixes",
                     policy->path_limit, MG_REF_PREFIX_FACTS);
        result = MAELYS_GIT_ERR_POLICY;
    }
    if (result == MAELYS_GIT_OK) {
        policy->entries = calloc(count, sizeof(*policy->entries));
        policy->facts = calloc(policy->fact_capacity, sizeof(*policy->facts));
        if (!policy->entries || !policy->facts) {
            mg_error_set(error, MAELYS_GIT_ERR_IO, 0, "unable to allocate the request fact buffer");
            result = MAELYS_GIT_ERR_IO;
        }
    }
    for (size_t i = 0u; result == MAELYS_GIT_OK && i < count; ++i) {
        result = prepare_entry(loaded, i, &policy->entries[i], error);
        policy->count = i + 1u; /* close releases a session created before a failure */
    }
    /* Sessions keep their own snapshot of the policy they were created from. */
    (void)maelys_datalog_policy_free(loaded);
    if (result != MAELYS_GIT_OK) {
        maelys_git_policy_close(policy);
        return result;
    }
    *out_policy = policy;
    return MAELYS_GIT_OK;
}

maelys_git_result_t maelys_git_policy_fingerprint(
    const maelys_git_policy_t *policy,
    char out_hex[65],
    maelys_git_error_t *error) {
    maelys_git_error_clear(error);
    if (!policy || !out_hex) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    memcpy(out_hex, policy->fingerprint, sizeof(policy->fingerprint));
    return MAELYS_GIT_OK;
}

void maelys_git_policy_close(maelys_git_policy_t *policy) {
    if (!policy) return;
    for (size_t i = 0u; policy->entries && i < policy->count; ++i)
        if (policy->entries[i].session)
            (void)maelys_datalog_session_free(policy->entries[i].session);
    free(policy->entries);
    free(policy->facts);
    free(policy->explanation_storage);
    free(policy->text);
    free(policy);
}

/* ---- request facts ------------------------------------------------------- */

static maelys_datalog_value_t symbol_value(const char *text) {
    maelys_datalog_value_t value = {.kind = MAELYS_DATALOG_VALUE_SYMBOL};
    value.as.symbol = text;
    return value;
}

static maelys_datalog_value_t integer_value(int64_t number) {
    maelys_datalog_value_t value = {.kind = MAELYS_DATALOG_VALUE_INTEGER};
    value.as.integer = number;
    return value;
}

static maelys_datalog_value_t boolean_value(int enabled) {
    maelys_datalog_value_t value = {.kind = MAELYS_DATALOG_VALUE_BOOLEAN};
    value.as.boolean = enabled != 0;
    return value;
}

static int push_fact(maelys_git_policy_t *policy, const char *predicate,
                     const maelys_datalog_value_t *terms, size_t arity) {
    if (policy->fact_count >= policy->fact_capacity) {
        policy->exceeded = REQUEST_BOUND_EDB_FACTS;
        return 0;
    }
    maelys_datalog_fact_t *fact = &policy->facts[policy->fact_count];
    memset(fact, 0, sizeof(*fact));
    fact->predicate = predicate;
    fact->arity = arity;
    for (size_t i = 0u; i < arity; ++i) fact->terms[i] = terms[i];
    ++policy->fact_count;
    return 1;
}

/* Absent values add no fact, so policies can test presence. */
static int push_symbol(maelys_git_policy_t *policy, const char *predicate, const char *text) {
    if (!text || !*text) return 1;
    maelys_datalog_value_t value = symbol_value(text);
    return push_fact(policy, predicate, &value, 1u);
}

static int push_integer(maelys_git_policy_t *policy, const char *predicate,
                        unsigned long long number) {
    if (number > INT64_MAX) {
        policy->exceeded = REQUEST_BOUND_INTEGER;
        return 0;
    }
    maelys_datalog_value_t value = integer_value((int64_t)number);
    return push_fact(policy, predicate, &value, 1u);
}

static int push_boolean(maelys_git_policy_t *policy, const char *predicate, int enabled) {
    maelys_datalog_value_t value = boolean_value(enabled);
    return push_fact(policy, predicate, &value, 1u);
}

/* repository_segment/2, repository_depth/1, repository_leaf/1 and, from
 * three segments on, repository_owner_namespace/2. The segment symbols point
 * into the handle's repository copy, which outlives the solve. */
static int push_repository_structure(maelys_git_policy_t *policy, const char *repository) {
    if (!repository || !maelys_git_repository_name_is_valid(repository)) return 1;
    if (!mg_copy_string(policy->repository_copy, sizeof(policy->repository_copy), repository))
        return 0;
    size_t depth = 0u;
    const char *first = NULL;
    const char *second = NULL;
    const char *leaf = NULL;
    char *save = NULL;
    for (char *segment = strtok_r(policy->repository_copy, "/", &save);
         segment; segment = strtok_r(NULL, "/", &save)) {
        maelys_datalog_value_t terms[2] = {integer_value((int64_t)depth), symbol_value(segment)};
        if (!push_fact(policy, "repository_segment", terms, 2u)) return 0;
        leaf = segment;
        if (depth == 0u) first = segment;
        else if (depth == 1u) second = segment;
        ++depth;
    }
    int ok = push_integer(policy, "repository_depth", depth) &&
             push_symbol(policy, "repository_leaf", leaf);
    if (ok && depth >= 3u) {
        maelys_datalog_value_t terms[2] = {symbol_value(first), symbol_value(second)};
        ok = push_fact(policy, "repository_owner_namespace", terms, 2u);
    }
    return ok;
}

/* ref_prefix/1 for each of the first MG_REF_PREFIX_FACTS prefixes of a valid
 * ref that end with '/', shortest first, never the ref itself, and
 * ref_prefix_count/1, the number of such prefixes, untruncated. A policy that
 * tests a deeper prefix can close on that count. The prefixes are copied into
 * the handle, which outlives the solve. */
static int push_ref_structure(maelys_git_policy_t *policy, const char *ref) {
    if (!ref || !maelys_git_ref_name_is_valid(ref)) return 1;
    size_t count = 0u;
    for (size_t i = 0u; ref[i]; ++i) {
        if (ref[i] != '/') continue;
        if (count < MG_REF_PREFIX_FACTS) {
            char *prefix = policy->ref_prefixes[count];
            memcpy(prefix, ref, i + 1u);
            prefix[i + 1u] = '\0';
            if (!push_symbol(policy, "ref_prefix", prefix)) return 0;
        }
        ++count;
    }
    return push_integer(policy, "ref_prefix_count", count);
}

/* The single builder of request facts. They borrow the request's strings and
 * stay valid, in the handle, until the next request. On failure the handle
 * says which bound refused them. */
static int build_request_facts(maelys_git_policy_t *policy,
                               const maelys_git_policy_request_t *request,
                               const char *request_id) {
    policy->fact_count = 0u;
    policy->exceeded = REQUEST_BOUND_NONE;
    int ok = push_symbol(policy, "request", request_id) &&
             push_symbol(policy, "user", request->principal) &&
             push_symbol(policy, "repository", request->repository) &&
             push_repository_structure(policy, request->repository) &&
             push_symbol(policy, "operation", request->operation) &&
             push_symbol(policy, "ref", request->ref_name) &&
             push_ref_structure(policy, request->ref_name) &&
             push_symbol(policy, "ref_kind", request->ref_kind) &&
             push_symbol(policy, "update_kind", request->update_kind) &&
             push_symbol(policy, "change_kind", request->change_kind) &&
             push_symbol(policy, "old_path", request->old_path) &&
             push_symbol(policy, "ssh_key", request->ssh_key) &&
             push_symbol(policy, "remote_address", request->remote_address) &&
             push_symbol(policy, "commit_email", request->commit_email) &&
             push_symbol(policy, "commit_signature_status", request->commit_signature_status) &&
             push_symbol(policy, "commit_signer_fingerprint", request->commit_signer_fingerprint) &&
             push_symbol(policy, "commit_signer_identity", request->commit_signer_identity);
    if (ok && request->has_commit_signed)
        ok = push_boolean(policy, "commit_signed", request->commit_signed);
    if (ok && request->has_commit_signature_trusted)
        ok = push_boolean(policy, "commit_signature_trusted", request->commit_signature_trusted);
    if (ok && request->has_summary)
        ok = push_integer(policy, "changed_count", request->changed_count) &&
             push_integer(policy, "added_count", request->added_count) &&
             push_integer(policy, "modified_count", request->modified_count) &&
             push_integer(policy, "deleted_count", request->deleted_count) &&
             push_integer(policy, "renamed_count", request->renamed_count) &&
             push_integer(policy, "max_new_blob_size", request->max_new_blob_size) &&
             push_integer(policy, "total_new_blob_size", request->total_new_blob_size) &&
             push_integer(policy, "commit_count", request->commit_count) &&
             push_integer(policy, "merge_commit_count", request->merge_commit_count) &&
             push_boolean(policy, "has_binary", request->has_binary);
    if (ok && request->has_change_details)
        ok = push_integer(policy, "change_blob_size", request->change_blob_size) &&
             push_integer(policy, "old_mode", request->old_mode) &&
             push_integer(policy, "new_mode", request->new_mode) &&
             push_boolean(policy, "change_binary", request->change_binary) &&
             push_boolean(policy, "change_symlink", request->change_symlink) &&
             push_boolean(policy, "change_submodule", request->change_submodule) &&
             push_boolean(policy, "change_lfs_pointer", request->change_lfs_pointer);
    if (ok && request->path_count > policy->path_limit) {
        policy->exceeded = REQUEST_BOUND_PATHS;
        ok = 0;
    }
    for (size_t i = 0u; ok && i < request->path_count; ++i)
        ok = push_symbol(policy, "path", request->paths[i]);
    return ok;
}

/* The detail of refused request facts: the bound that refused them, its
 * engine name and the capacity read from the engine. The fact buffer reports,
 * as the engine does, the attempted count: one more than it holds. */
static void set_request_detail(maelys_git_error_t *error, const maelys_git_policy_t *policy,
                               const maelys_git_policy_request_t *request) {
    maelys_git_failure_detail_t detail = {.kind = MAELYS_GIT_FAILURE_CAPACITY};
    maelys_datalog_limit_t budget = MAELYS_DATALOG_LIMIT_MAX_EDB_FACTS;
    switch (policy->exceeded) {
        case REQUEST_BOUND_EDB_FACTS:
            detail.requested = policy->fact_capacity + 1u;
            detail.limit = policy->fact_capacity;
            break;
        case REQUEST_BOUND_PATHS:
            budget = MAELYS_DATALOG_LIMIT_MAX_FACTS_PER_PRED;
            detail.requested = request->path_count;
            detail.limit = policy->path_limit;
            break;
        case REQUEST_BOUND_INTEGER:
            detail.kind = MAELYS_GIT_FAILURE_VALUE;
            break;
        case REQUEST_BOUND_NONE:
            return;
    }
    const char *name = maelys_datalog_limit_name(budget);
    if (detail.kind == MAELYS_GIT_FAILURE_CAPACITY && name)
        (void)mg_copy_string(detail.budget, sizeof(detail.budget), name);
    mg_error_set_detail(error, &detail);
}

static const char *request_identifier(const maelys_git_policy_request_t *request) {
    return request->request_id && *request->request_id ? request->request_id : "request";
}

/* ---- evaluation ---------------------------------------------------------- */

/* Solves one policy against the request facts of the handle. The result is
 * returned alive: the caller releases it before the next solve of the session. */
static maelys_git_result_t solve_entry(maelys_git_policy_t *policy, const policy_entry_t *entry,
                                       maelys_datalog_result_t **out_result,
                                       maelys_git_error_t *error) {
    maelys_datalog_diagnostic_t diagnostic = MAELYS_DATALOG_DIAGNOSTIC_INIT;
    maelys_datalog_status_t status = maelys_datalog_session_solve(
        entry->session, policy->facts, policy->fact_count, out_result, &diagnostic);
    if (status == MAELYS_DATALOG_STATUS_OK) return MAELYS_GIT_OK;
    mg_error_set(error, MAELYS_GIT_ERR_POLICY, 0, "policy solve failed: %s (%s)",
                 diagnostic.source == MAELYS_DATALOG_DIAGNOSTIC_NONE
                     ? "no diagnostic" : maelys_datalog_diag_code_name(diagnostic.code),
                 maelys_datalog_status_name(status));
    set_diagnostic_detail(error, &diagnostic);
    return MAELYS_GIT_ERR_POLICY;
}

/* Reads deny then allow for the request and lets the engine rank them. */
static maelys_git_result_t classify(const maelys_datalog_result_t *result, const char *request_id,
                                    maelys_datalog_decision_t *out_decision,
                                    maelys_git_error_t *error) {
    maelys_datalog_value_t query = symbol_value(request_id);
    int allow = 0;
    int deny = 0;
    maelys_datalog_status_t status =
        maelys_datalog_result_query(result, "deny", &query, 1u, &deny);
    if (status == MAELYS_DATALOG_STATUS_OK)
        status = maelys_datalog_result_query(result, "allow", &query, 1u, &allow);
    if (status == MAELYS_DATALOG_STATUS_OK)
        status = maelys_datalog_decision_from_presence(allow, 0, deny, out_decision);
    return status == MAELYS_DATALOG_STATUS_OK ? MAELYS_GIT_OK
                                              : engine_failure(error, "decision query", status);
}

/* The decision of a request over the policies of the handle, in order; it
 * counts the policies it solved. The request facts stay in the handle. */
static maelys_git_result_t decide(maelys_git_policy_t *policy,
                                  const maelys_git_policy_request_t *request,
                                  maelys_git_policy_decision_t *out_decision,
                                  size_t *out_evaluated, maelys_git_error_t *error) {
    *out_evaluated = 0u;
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
    memcpy(out_decision->policy_set_fingerprint, policy->fingerprint, sizeof(policy->fingerprint));
    const char *request_id = request_identifier(request);
    maelys_git_result_t result = MAELYS_GIT_OK;
    if (!build_request_facts(policy, request, request_id)) {
        mg_error_set(error, MAELYS_GIT_ERR_POLICY, 0,
                     "request fact construction failed: a value or the fact count exceeds the engine limits");
        set_request_detail(error, policy, request);
        result = MAELYS_GIT_ERR_POLICY;
    }
    size_t allow_policy = SIZE_MAX;
    for (size_t i = 0u; result == MAELYS_GIT_OK && i < policy->count; ++i) {
        const policy_entry_t *entry = &policy->entries[i];
        maelys_datalog_result_t *solved = NULL;
        maelys_datalog_decision_t ranked = MAELYS_DATALOG_DECISION_DENY_DEFAULT;
        result = solve_entry(policy, entry, &solved, error);
        *out_evaluated = i + 1u;
        if (result == MAELYS_GIT_OK) {
            result = classify(solved, request_id, &ranked, error);
            (void)maelys_datalog_result_free(solved);
        }
        if (result != MAELYS_GIT_OK) break;
        if (ranked == MAELYS_DATALOG_DECISION_DENY || ranked == MAELYS_DATALOG_DECISION_DENY_CONFLICT) {
            /* An explicit deny of any policy wins and ends the evaluation. */
            out_decision->explicit_deny = 1;
            out_decision->matched_policy = i;
            memcpy(out_decision->session_fingerprint, entry->fingerprint, sizeof(entry->fingerprint));
            (void)snprintf(out_decision->reason, sizeof(out_decision->reason),
                           "explicit deny from policy %s", entry->policy_id);
            return MAELYS_GIT_OK;
        }
        if (ranked == MAELYS_DATALOG_DECISION_ALLOW) {
            if (allow_policy == SIZE_MAX) allow_policy = i;
        } else if (ranked != MAELYS_DATALOG_DECISION_DENY_DEFAULT) {
            mg_error_set(error, MAELYS_GIT_ERR_POLICY, 0, "decision query returned an unknown rank");
            result = MAELYS_GIT_ERR_POLICY;
        }
    }
    if (result != MAELYS_GIT_OK) {
        (void)mg_copy_string(out_decision->reason, sizeof(out_decision->reason), "policy evaluation failed; request denied");
        return result;
    }
    if (allow_policy != SIZE_MAX) {
        const policy_entry_t *entry = &policy->entries[allow_policy];
        out_decision->allowed = 1;
        out_decision->matched_policy = allow_policy;
        memcpy(out_decision->session_fingerprint, entry->fingerprint, sizeof(entry->fingerprint));
        (void)snprintf(out_decision->reason, sizeof(out_decision->reason),
                       "allowed by policy %s", entry->policy_id);
    } else {
        (void)mg_copy_string(out_decision->reason, sizeof(out_decision->reason),
                             "no allow rule matched; denied by default");
    }
    return MAELYS_GIT_OK;
}

maelys_git_result_t maelys_git_policy_authorize(
    maelys_git_policy_t *policy, const maelys_git_policy_request_t *request,
    maelys_git_policy_decision_t *out_decision, maelys_git_error_t *error) {
    size_t evaluated = 0u;
    return decide(policy, request, out_decision, &evaluated, error);
}

/* ---- explanation --------------------------------------------------------- */

/* What one explanation of a decision says, read from the engine's structured
 * views of a single prepared explanation; its text, when the engine rendered
 * one, is in the handle's buffer. Git Core never reads that text. */
typedef struct {
    maelys_git_explanation_kind_t kind;
    maelys_git_receipt_status_t status;
    size_t policy_index;
    const char *query;
    int has_rule;
    size_t rule_id, step_count, premise_count;
    int has_counts;
    size_t candidate_rules, diagnostics, filter_cost_units, substitutions;
    unsigned limit_hits;
    int has_text;
    size_t text_bytes;
    char text_sha256[65];
    maelys_datalog_filter_statistics_t filters;
} explanation_t;

/* Storage for a prepared explanation of either kind, sized by the engine. */
static maelys_git_result_t explanation_storage(maelys_git_policy_t *policy,
                                               const maelys_datalog_session_t *session,
                                               maelys_datalog_explanation_kind_t kind,
                                               maelys_datalog_status_t *out_status,
                                               maelys_git_error_t *error) {
    size_t bytes = 0u, alignment = 0u;
    *out_status = maelys_datalog_session_explanation_storage_bound(session, kind, &bytes, &alignment);
    if (*out_status != MAELYS_DATALOG_STATUS_OK) return MAELYS_GIT_OK;
    if (bytes <= policy->explanation_storage_bytes) return MAELYS_GIT_OK;
    if (alignment < sizeof(void *)) alignment = sizeof(void *);
    void *storage = NULL;
    if (posix_memalign(&storage, alignment, bytes) != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, 0, "unable to allocate explanation storage");
        return MAELYS_GIT_ERR_IO;
    }
    free(policy->explanation_storage);
    policy->explanation_storage = storage;
    policy->explanation_storage_bytes = bytes;
    return MAELYS_GIT_OK;
}

static unsigned receipt_limit_hits(unsigned engine_hits) {
    static const struct { unsigned engine, receipt; } bits[] = {
        {MAELYS_DATALOG_WHY_FALSE_LIMIT_CANDIDATE_RULES, MAELYS_GIT_RECEIPT_LIMIT_CANDIDATE_RULES},
        {MAELYS_DATALOG_WHY_FALSE_LIMIT_SUBSTITUTIONS, MAELYS_GIT_RECEIPT_LIMIT_SUBSTITUTIONS},
        {MAELYS_DATALOG_WHY_FALSE_LIMIT_DEPTH, MAELYS_GIT_RECEIPT_LIMIT_DEPTH},
        {MAELYS_DATALOG_WHY_FALSE_LIMIT_DIAGNOSTICS, MAELYS_GIT_RECEIPT_LIMIT_DIAGNOSTICS},
        {MAELYS_DATALOG_WHY_FALSE_LIMIT_FILTER_COST, MAELYS_GIT_RECEIPT_LIMIT_FILTER_COST},
    };
    unsigned hits = 0u;
    for (size_t i = 0u; i < sizeof(bits) / sizeof(bits[0]); ++i)
        if (engine_hits & bits[i].engine) hits |= bits[i].receipt;
    return hits;
}

/* The status, counters and deciding rule of a prepared explanation. The rule
 * of a why-true is that of the step deriving the queried fact. */
static void read_views(const maelys_datalog_prepared_explanation_t *prepared, const char *query,
                       explanation_t *out) {
    maelys_datalog_explanation_info_t info;
    if (maelys_datalog_prepared_explanation_info(prepared, &info) != MAELYS_DATALOG_STATUS_OK) {
        out->status = MAELYS_GIT_RECEIPT_STATUS_UNKNOWN;
        return;
    }
    if (out->kind == MAELYS_GIT_EXPLANATION_WHY_TRUE) {
        out->status = !info.found ? MAELYS_GIT_RECEIPT_STATUS_NOT_APPLICABLE :
                      info.truncated ? MAELYS_GIT_RECEIPT_STATUS_TRUNCATED :
                                       MAELYS_GIT_RECEIPT_STATUS_COMPLETE;
        if (out->status != MAELYS_GIT_RECEIPT_STATUS_COMPLETE) return;
        for (size_t i = 0u; i < info.step_count; ++i) {
            maelys_datalog_explanation_step_view_t step;
            if (maelys_datalog_prepared_explanation_step(prepared, i, &step) == MAELYS_DATALOG_STATUS_OK &&
                step.fact.predicate && !strcmp(step.fact.predicate, query)) {
                out->has_rule = 1;
                out->rule_id = step.rule_id;
                out->step_count = info.step_count;
                out->premise_count = info.premise_count;
                break;
            }
        }
        return;
    }
    out->status = info.false_status == MAELYS_DATALOG_WHY_FALSE_STATUS_COMPLETE ?
                      MAELYS_GIT_RECEIPT_STATUS_COMPLETE :
                  info.false_status == MAELYS_DATALOG_WHY_FALSE_STATUS_TRUNCATED ?
                      MAELYS_GIT_RECEIPT_STATUS_TRUNCATED : MAELYS_GIT_RECEIPT_STATUS_NOT_APPLICABLE;
    out->has_counts = 1;
    out->candidate_rules = info.candidate_rule_count;
    out->diagnostics = info.diagnostic_count;
    out->filter_cost_units = info.filter_cost_units;
    out->substitutions = info.substitution_count;
    out->limit_hits = receipt_limit_hits(info.limit_hits);
}

/* Renders the document of a prepared explanation into the handle's buffer
 * and hashes it. */
static maelys_git_result_t render_text(maelys_git_policy_t *policy,
                                       const maelys_datalog_prepared_explanation_t *prepared,
                                       explanation_t *out, maelys_git_error_t *error) {
    size_t required = 0u;
    maelys_datalog_status_t status = maelys_datalog_prepared_explanation_text_size(prepared, &required);
    if (status != MAELYS_DATALOG_STATUS_OK) return engine_failure(error, "explanation size", status);
    if (required + 1u > policy->text_capacity) {
        char *text = realloc(policy->text, required + 1u);
        if (!text) {
            mg_error_set(error, MAELYS_GIT_ERR_IO, 0, "unable to allocate the explanation text");
            return MAELYS_GIT_ERR_IO;
        }
        policy->text = text;
        policy->text_capacity = required + 1u;
    }
    status = maelys_datalog_prepared_explanation_write_text(prepared, policy->text, required + 1u);
    if (status != MAELYS_DATALOG_STATUS_OK) return engine_failure(error, "explanation", status);
    out->has_text = 1;
    out->text_bytes = required;
    maelys_cli_sha256_hex(policy->text, required, out->text_sha256);
    return MAELYS_GIT_OK;
}

/* The single path that explains a decision: the witness of a derived allow or
 * deny in the policy that derived it, or the why-false document of allow in
 * the last policy for a denial by default. The request facts are still in
 * the handle: that policy is solved again and explained from the result that
 * carries the decision, by one preparation for the views and the text. */
static maelys_git_result_t explain_decision(maelys_git_policy_t *policy,
                                            const maelys_git_policy_request_t *request,
                                            const maelys_git_policy_decision_t *decision,
                                            explanation_t *out, maelys_git_error_t *error) {
    memset(out, 0, sizeof(*out));
    int why_true = decision->allowed || decision->explicit_deny;
    out->kind = why_true ? MAELYS_GIT_EXPLANATION_WHY_TRUE : MAELYS_GIT_EXPLANATION_WHY_FALSE;
    out->query = decision->explicit_deny ? "deny" : "allow";
    out->policy_index = why_true ? decision->matched_policy : policy->count - 1u;
    out->status = MAELYS_GIT_RECEIPT_STATUS_NOT_APPLICABLE;
    const policy_entry_t *entry = &policy->entries[out->policy_index];
    maelys_datalog_explanation_kind_t kind = why_true ? MAELYS_DATALOG_EXPLAIN_TRUE : MAELYS_DATALOG_EXPLAIN_FALSE;
    maelys_datalog_status_t status = MAELYS_DATALOG_STATUS_OK;
    maelys_git_result_t result = explanation_storage(policy, entry->session, kind, &status, error);
    if (result != MAELYS_GIT_OK) return result;
    /* A backend that cannot explain: the decision stands, without a document. */
    if (status == MAELYS_DATALOG_STATUS_UNSUPPORTED) return MAELYS_GIT_OK;
    if (status != MAELYS_DATALOG_STATUS_OK) return engine_failure(error, "explanation storage bound", status);
    maelys_datalog_result_t *solved = NULL;
    result = solve_entry(policy, entry, &solved, error);
    if (result != MAELYS_GIT_OK) return result;
    if (maelys_datalog_result_filter_statistics(solved, &out->filters) != MAELYS_DATALOG_STATUS_OK)
        memset(&out->filters, 0, sizeof(out->filters));
    maelys_datalog_value_t query = symbol_value(request_identifier(request));
    maelys_datalog_prepared_explanation_t *prepared = NULL;
    status = maelys_datalog_result_prepare_explanation(
        solved, kind, out->query, &query, 1u, policy->explanation_storage,
        policy->explanation_storage_bytes, &prepared);
    if (status == MAELYS_DATALOG_STATUS_OK) {
        read_views(prepared, out->query, out);
        result = render_text(policy, prepared, out, error);
        (void)maelys_datalog_prepared_explanation_release(prepared);
    } else if (status != MAELYS_DATALOG_STATUS_UNSUPPORTED) {
        result = engine_failure(error, "explanation", status);
    }
    (void)maelys_datalog_result_free(solved);
    return result;
}

maelys_git_result_t maelys_git_policy_explain(
    maelys_git_policy_t *policy, const maelys_git_policy_request_t *request,
    char *out_text, size_t capacity, maelys_git_policy_explanation_t *out_explanation,
    maelys_git_error_t *error) {
    maelys_git_error_clear(error);
    if (!out_explanation || (!out_text && capacity > 0u)) {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_ARGUMENT, 0, "an explanation record is required, and a buffer when a capacity is given");
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    }
    memset(out_explanation, 0, sizeof(*out_explanation));
    out_explanation->explained_policy = SIZE_MAX;
    if (out_text) out_text[0] = '\0';
    /* The decision first, by the very code path that authorizes. */
    maelys_git_result_t result =
        maelys_git_policy_authorize(policy, request, &out_explanation->decision, error);
    if (result != MAELYS_GIT_OK) return result;
    explanation_t explanation;
    result = explain_decision(policy, request, &out_explanation->decision, &explanation, error);
    if (result != MAELYS_GIT_OK) return result;
    out_explanation->kind = explanation.kind;
    out_explanation->explained_policy = explanation.policy_index;
    (void)mg_copy_string(out_explanation->query, sizeof(out_explanation->query), explanation.query);
    out_explanation->filter_matches = explanation.filters.matches;
    out_explanation->filter_non_matches = explanation.filters.non_matches;
    out_explanation->filter_cost_units = explanation.filters.cost_units;
    if (!explanation.has_text) {
        out_explanation->status = MAELYS_GIT_EXPLANATION_NOT_APPLICABLE;
        return MAELYS_GIT_OK;
    }
    out_explanation->text_required = explanation.text_bytes;
    /* Size query: the caller allocates text_required + 1 bytes and calls again. */
    if (!out_text) return MAELYS_GIT_OK;
    if (capacity <= explanation.text_bytes) {
        mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0, "the explanation needs %zu bytes and the buffer holds %zu",
                     explanation.text_bytes + 1u, capacity);
        return MAELYS_GIT_ERR_LIMIT;
    }
    memcpy(out_text, policy->text, explanation.text_bytes + 1u);
    out_explanation->text_length = explanation.text_bytes;
    out_explanation->status =
        explanation.status == MAELYS_GIT_RECEIPT_STATUS_COMPLETE ? MAELYS_GIT_EXPLANATION_COMPLETE :
        explanation.status == MAELYS_GIT_RECEIPT_STATUS_TRUNCATED ? MAELYS_GIT_EXPLANATION_TRUNCATED :
                                                                    MAELYS_GIT_EXPLANATION_NOT_APPLICABLE;
    return MAELYS_GIT_OK;
}

/* ---- receipts ------------------------------------------------------------- */

static int copy_field(char *out, size_t capacity, const char *value, maelys_git_error_t *error,
                      const char *name) {
    if (!value) value = "";
    if (mg_copy_string(out, capacity, value)) return 1;
    mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0, "the receipt cannot hold a request %s of %zu bytes",
                 name, strlen(value));
    return 0;
}

maelys_git_result_t maelys_git_policy_authorize_receipt(
    maelys_git_policy_t *policy, const maelys_git_policy_request_t *request,
    maelys_git_explain_mode_t mode, char *out_text, size_t text_capacity,
    maelys_git_policy_decision_t *out_decision, maelys_git_receipt_t *out_receipt,
    maelys_git_error_t *error) {
    maelys_git_error_clear(error);
    if (!out_receipt || !request || (mode != MAELYS_GIT_EXPLAIN_NEVER &&
        mode != MAELYS_GIT_EXPLAIN_ON_DENIAL && mode != MAELYS_GIT_EXPLAIN_ALWAYS)) {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_ARGUMENT, 0, "a request, a receipt and a known mode are required");
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    }
    if (out_text && text_capacity > 0u) out_text[0] = '\0';
    maelys_git_receipt_t *receipt = out_receipt;
    memset(receipt, 0, sizeof(*receipt));
    if (!copy_field(receipt->request.id, sizeof(receipt->request.id), request_identifier(request), error, "id") ||
        !copy_field(receipt->request.principal, sizeof(receipt->request.principal), request->principal, error, "principal") ||
        !copy_field(receipt->request.repository, sizeof(receipt->request.repository), request->repository, error, "repository") ||
        !copy_field(receipt->request.operation, sizeof(receipt->request.operation), request->operation, error, "operation") ||
        !copy_field(receipt->request.ref, sizeof(receipt->request.ref), request->ref_name, error, "ref"))
        return MAELYS_GIT_ERR_LIMIT;
    receipt->request.path_count = request->path_count;
    size_t evaluated = 0u;
    maelys_git_result_t result = decide(policy, request, out_decision, &evaluated, error);
    if (result == MAELYS_GIT_ERR_INVALID_ARGUMENT) return result;
    memcpy(receipt->policy_set_fingerprint, policy->fingerprint, sizeof(policy->fingerprint));
    receipt->edb_facts = policy->fact_count;
    receipt->evaluated_policies = evaluated;
    if (result != MAELYS_GIT_OK) {
        /* A failure denies; the receipt says so, and what kind of failure it was. */
        receipt->decision = MAELYS_GIT_RECEIPT_DENY_ERROR;
        (void)mg_copy_string(receipt->error_code, sizeof(receipt->error_code), maelys_git_result_name(result));
        if (error && error->detail.kind != MAELYS_GIT_FAILURE_NONE) {
            (void)mg_copy_string(receipt->error_kind, sizeof(receipt->error_kind),
                                 maelys_git_failure_kind_name(error->detail.kind));
            if (error->detail.kind == MAELYS_GIT_FAILURE_CAPACITY)
                (void)mg_copy_string(receipt->error_budget, sizeof(receipt->error_budget), error->detail.budget);
        }
        return result;
    }
    receipt->decision = out_decision->allowed ? MAELYS_GIT_RECEIPT_ALLOW :
                        out_decision->explicit_deny ? MAELYS_GIT_RECEIPT_DENY_EXPLICIT :
                                                      MAELYS_GIT_RECEIPT_DENY_DEFAULT;
    if (out_decision->allowed || out_decision->explicit_deny) {
        const policy_entry_t *entry = &policy->entries[out_decision->matched_policy];
        receipt->matched = 1;
        receipt->matched_policy_index = out_decision->matched_policy;
        (void)mg_copy_string(receipt->matched_policy_id, sizeof(receipt->matched_policy_id), entry->policy_id);
        memcpy(receipt->matched_session_fingerprint, entry->fingerprint, sizeof(entry->fingerprint));
    }
    if (mode == MAELYS_GIT_EXPLAIN_NEVER || (mode == MAELYS_GIT_EXPLAIN_ON_DENIAL && out_decision->allowed))
        return MAELYS_GIT_OK;
    explanation_t explanation;
    result = explain_decision(policy, request, out_decision, &explanation, error);
    if (result != MAELYS_GIT_OK) return result;
    receipt->explanation.kind = explanation.kind;
    receipt->explanation.status = explanation.status;
    receipt->explanation.policy_index = explanation.policy_index;
    (void)mg_copy_string(receipt->explanation.query, sizeof(receipt->explanation.query), explanation.query);
    receipt->explanation.has_rule = explanation.has_rule;
    receipt->explanation.rule_id = explanation.rule_id;
    receipt->explanation.step_count = explanation.step_count;
    receipt->explanation.premise_count = explanation.premise_count;
    receipt->explanation.has_counts = explanation.has_counts;
    receipt->explanation.candidate_rules = explanation.candidate_rules;
    receipt->explanation.diagnostics = explanation.diagnostics;
    receipt->explanation.filter_cost_units = explanation.filter_cost_units;
    receipt->explanation.substitutions = explanation.substitutions;
    receipt->explanation.limit_hits = explanation.limit_hits;
    receipt->explanation.has_text = explanation.has_text;
    receipt->explanation.text_bytes = explanation.text_bytes;
    memcpy(receipt->explanation.text_sha256, explanation.text_sha256, sizeof(explanation.text_sha256));
    if (explanation.has_text && out_text && text_capacity > explanation.text_bytes)
        memcpy(out_text, policy->text, explanation.text_bytes + 1u);
    return MAELYS_GIT_OK;
}
