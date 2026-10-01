#include "internal.h"

#include <maelys/datalog.h>
#include <maelys/datalog_advanced.h>
/* Only maelys_datalog_session_program() and maelys_datalog_program_info():
 * the consumer headers give a loaded policy no name, and a decision names
 * the policy that produced it. */
#include <maelys/datalog_backend.h>

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MG_POLICY_ID_MAX 128u

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
    char repository_copy[MAELYS_GIT_MAX_REPOSITORY];
    char fingerprint[MAELYS_DATALOG_PUBLIC_FINGERPRINT_BYTES];
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

/* A refused manifest reports the engine's own diagnostic. A capacity section
 * means a declared limit was exceeded, which is a limit error here too. */
static maelys_git_result_t load_failure(maelys_git_error_t *error,
                                        maelys_datalog_status_t status,
                                        const maelys_datalog_diagnostic_t *diagnostic) {
    if (diagnostic->source == MAELYS_DATALOG_DIAGNOSTIC_NONE) {
        mg_error_set(error, MAELYS_GIT_ERR_POLICY, 0, "policy load failed: %s",
                     maelys_datalog_status_name(status));
        return MAELYS_GIT_ERR_POLICY;
    }
    maelys_git_result_t code = (diagnostic->present & MAELYS_DATALOG_DIAGNOSTIC_CAPACITY)
                                   ? MAELYS_GIT_ERR_LIMIT : MAELYS_GIT_ERR_POLICY;
    char location[384] = "";
    if (diagnostic->present & MAELYS_DATALOG_DIAGNOSTIC_LOCATION)
        (void)snprintf(location, sizeof(location), " in %.255s line %zu column %zu",
                       diagnostic->file[0] ? diagnostic->file : "policy", diagnostic->line,
                       diagnostic->column);
    char capacity[96] = "";
    if (diagnostic->present & MAELYS_DATALOG_DIAGNOSTIC_CAPACITY)
        (void)snprintf(capacity, sizeof(capacity), " (%zu requested, limit %zu)",
                       diagnostic->observed_count, diagnostic->limit);
    mg_error_set(error, code, 0, "policy load failed (%s)%s: %s%s%s%s",
                 maelys_datalog_diag_code_name(diagnostic->code), location, diagnostic->message,
                 capacity, diagnostic->hint[0] ? "; " : "", diagnostic->hint);
    return code;
}

static maelys_git_result_t read_limit(maelys_datalog_limit_t limit, size_t *out,
                                      maelys_git_error_t *error) {
    maelys_datalog_status_t status = maelys_datalog_limit_get(limit, out);
    return status == MAELYS_DATALOG_STATUS_OK && *out > 0u
               ? MAELYS_GIT_OK : engine_failure(error, "engine limit query", status);
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
    const maelys_datalog_program_t *program = NULL;
    maelys_datalog_program_info_t info;
    memset(&info, 0, sizeof(info));
    status = maelys_datalog_session_program(entry->session, &program);
    if (status == MAELYS_DATALOG_STATUS_OK) status = maelys_datalog_program_info(program, &info);
    if (status != MAELYS_DATALOG_STATUS_OK)
        return engine_failure(error, "policy identity query", status);
    if (!info.policy_id || !mg_copy_string(entry->policy_id, sizeof(entry->policy_id), info.policy_id)) {
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
        status = maelys_datalog_policy_count(loaded, &count);
        if (status != MAELYS_DATALOG_STATUS_OK) result = engine_failure(error, "policy count", status);
        else if (count == 0u) {
            mg_error_set(error, MAELYS_GIT_ERR_POLICY, 0, "policy set contains no enabled policy");
            result = MAELYS_GIT_ERR_POLICY;
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
    if (policy->fact_count >= policy->fact_capacity) return 0;
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
    if (number > INT64_MAX) return 0;
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

/* The single builder of request facts. They borrow the request's strings and
 * stay valid, in the handle, until the next request. */
static int build_request_facts(maelys_git_policy_t *policy,
                               const maelys_git_policy_request_t *request,
                               const char *request_id) {
    policy->fact_count = 0u;
    int ok = push_symbol(policy, "request", request_id) &&
             push_symbol(policy, "user", request->principal) &&
             push_symbol(policy, "repository", request->repository) &&
             push_repository_structure(policy, request->repository) &&
             push_symbol(policy, "operation", request->operation) &&
             push_symbol(policy, "ref", request->ref_name) &&
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
    if (ok && request->path_count > policy->path_limit) ok = 0;
    for (size_t i = 0u; ok && i < request->path_count; ++i)
        ok = push_symbol(policy, "path", request->paths[i]);
    return ok;
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

maelys_git_result_t maelys_git_policy_authorize(
    maelys_git_policy_t *policy, const maelys_git_policy_request_t *request,
    maelys_git_policy_decision_t *out_decision, maelys_git_error_t *error) {
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
        result = MAELYS_GIT_ERR_POLICY;
    }
    size_t allow_policy = SIZE_MAX;
    for (size_t i = 0u; result == MAELYS_GIT_OK && i < policy->count; ++i) {
        const policy_entry_t *entry = &policy->entries[i];
        maelys_datalog_result_t *solved = NULL;
        maelys_datalog_decision_t ranked = MAELYS_DATALOG_DECISION_DENY_DEFAULT;
        result = solve_entry(policy, entry, &solved, error);
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

/* ---- explanation --------------------------------------------------------- */

/* The status line of a MAELYS-DATALOG-v2 explanation document. */
static maelys_git_explanation_status_t document_status(const char *text) {
    const char *line = strstr(text, "\nstatus=");
    if (!line) return MAELYS_GIT_EXPLANATION_NOT_APPLICABLE;
    line += 8;
    if (strncmp(line, "complete", 8u) == 0) return MAELYS_GIT_EXPLANATION_COMPLETE;
    if (strncmp(line, "truncated", 9u) == 0) return MAELYS_GIT_EXPLANATION_TRUNCATED;
    return MAELYS_GIT_EXPLANATION_NOT_APPLICABLE;
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
    const maelys_git_policy_decision_t *decision = &out_explanation->decision;
    int why_true = decision->allowed || decision->explicit_deny;
    const char *query_name = decision->explicit_deny ? "deny" : "allow";
    /* A derived allow or deny is witnessed by the policy that derived it; a
     * default denial is examined on the last policy that could have allowed. */
    size_t target = why_true ? decision->matched_policy : policy->count - 1u;
    out_explanation->kind = why_true ? MAELYS_GIT_EXPLANATION_WHY_TRUE : MAELYS_GIT_EXPLANATION_WHY_FALSE;
    out_explanation->explained_policy = target;
    (void)mg_copy_string(out_explanation->query, sizeof(out_explanation->query), query_name);

    /* The request facts are still in the handle: solve the one policy again and
     * render from the result that carries the decision. */
    maelys_datalog_result_t *solved = NULL;
    result = solve_entry(policy, &policy->entries[target], &solved, error);
    if (result != MAELYS_GIT_OK) return result;
    maelys_datalog_value_t query = symbol_value(request_identifier(request));
    maelys_datalog_status_t (*render)(const maelys_datalog_result_t *, const char *,
                                      const maelys_datalog_value_t *, size_t, char *, size_t,
                                      size_t *) =
        why_true ? maelys_datalog_result_explain_true_text : maelys_datalog_result_explain_false_text;
    size_t required = 0u;
    maelys_datalog_status_t status = render(solved, query_name, &query, 1u, NULL, 0u, &required);
    if (status == MAELYS_DATALOG_STATUS_UNSUPPORTED) {
        /* The backend cannot explain: the decision stands, without a document. */
        (void)maelys_datalog_result_free(solved);
        out_explanation->status = MAELYS_GIT_EXPLANATION_NOT_APPLICABLE;
        return MAELYS_GIT_OK;
    }
    if (status != MAELYS_DATALOG_STATUS_OK && status != MAELYS_DATALOG_STATUS_PAYLOAD_TOO_LARGE) {
        (void)maelys_datalog_result_free(solved);
        return engine_failure(error, "explanation", status);
    }
    out_explanation->text_required = required;
    maelys_datalog_filter_statistics_t filters;
    memset(&filters, 0, sizeof(filters));
    if (maelys_datalog_result_filter_statistics(solved, &filters) == MAELYS_DATALOG_STATUS_OK) {
        out_explanation->filter_matches = filters.matches;
        out_explanation->filter_non_matches = filters.non_matches;
        out_explanation->filter_cost_units = filters.cost_units;
    }
    if (!out_text) {
        /* Size query: the caller allocates text_required + 1 bytes and calls again. */
        (void)maelys_datalog_result_free(solved);
        return MAELYS_GIT_OK;
    }
    if (capacity <= required) {
        (void)maelys_datalog_result_free(solved);
        mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0,
                     "the explanation needs %zu bytes and the buffer holds %zu", required + 1u, capacity);
        return MAELYS_GIT_ERR_LIMIT;
    }
    /* The text is copied into the caller's buffer before the result goes. */
    status = render(solved, query_name, &query, 1u, out_text, capacity, &required);
    (void)maelys_datalog_result_free(solved);
    if (status != MAELYS_DATALOG_STATUS_OK) {
        out_text[0] = '\0';
        return engine_failure(error, "explanation", status);
    }
    out_explanation->text_length = required;
    out_explanation->status = document_status(out_text);
    return MAELYS_GIT_OK;
}
