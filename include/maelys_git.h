#ifndef MAELYS_GIT_H
#define MAELYS_GIT_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAELYS_GIT_VERSION "0.1.0"
#define MAELYS_GIT_MAX_REPOSITORY 512u
#define MAELYS_GIT_MAX_REF 512u
#define MAELYS_GIT_MAX_ERROR 512u
#define MAELYS_GIT_MAX_PROTOCOL_LINE (64u * 1024u)
#define MAELYS_GIT_MAX_CHANGED_PATHS 64u /* legacy bounded request helper */
#define MAELYS_GIT_MAX_RECEIVE_UPDATES 1024u
#define MAELYS_GIT_MAX_CONFLICT_PATHS 128u
#define MAELYS_GIT_MAX_LIFECYCLE_ID 128u
/* Default quotas. Plain decimal literals so that the CLI catalogs can
 * declare them through MAELYS_CLI_DEFAULT_OF and keep one source. */
#define MAELYS_GIT_PR_DEFAULT_MAX_SOURCE_OBJECTS 100000
#define MAELYS_GIT_PR_DEFAULT_MAX_SOURCE_BYTES 536870912 /* 512 MiB */
#define MAELYS_GIT_DEFAULT_MAX_COMMITS 10000
#define MAELYS_GIT_DEFAULT_MAX_CHANGES 100000
#define MAELYS_GIT_DEFAULT_MAX_TOTAL_NEW_BLOB_BYTES 10737418240 /* 10 GiB */
#define MAELYS_GIT_DEFAULT_MAX_INSPECTED_BLOB_BYTES 536870912 /* 512 MiB */

typedef enum {
    MAELYS_GIT_OK = 0,
    MAELYS_GIT_ERR_INVALID_ARGUMENT = -1,
    MAELYS_GIT_ERR_INVALID_COMMAND = -2,
    MAELYS_GIT_ERR_INVALID_REPOSITORY = -3,
    MAELYS_GIT_ERR_POLICY = -4,
    MAELYS_GIT_ERR_DENIED = -5,
    MAELYS_GIT_ERR_IO = -6,
    MAELYS_GIT_ERR_PROCESS = -7,
    MAELYS_GIT_ERR_PROTOCOL = -8,
    MAELYS_GIT_ERR_LIMIT = -9,
    MAELYS_GIT_ERR_NOT_FOUND = -10
} maelys_git_result_t;

/* What kind of policy failure a MAELYS_GIT_ERR_POLICY reports. Any other
 * failure, and a policy failure outside loading, solving and building the
 * request facts, leaves MAELYS_GIT_FAILURE_NONE. */
typedef enum {
    MAELYS_GIT_FAILURE_NONE = 0,
    MAELYS_GIT_FAILURE_CAPACITY = 1,  /* a budget of the engine is exceeded */
    MAELYS_GIT_FAILURE_SYNTAX = 2,    /* the policy text cannot be read */
    MAELYS_GIT_FAILURE_SEMANTICS = 3, /* the policy reads but means nothing valid */
    MAELYS_GIT_FAILURE_MANIFEST = 4,  /* the manifest, its digests or its entries */
    MAELYS_GIT_FAILURE_VALUE = 5,     /* a request value the engine cannot hold */
    MAELYS_GIT_FAILURE_ENGINE = 6     /* any other refusal of the engine */
} maelys_git_failure_kind_t;

/* The machine-readable detail of a policy failure, taken from the engine's
 * diagnostic and from Git Core's own bounds; the message says the same for
 * a person. Empty strings and zero numbers mean unknown. */
typedef struct {
    maelys_git_failure_kind_t kind;
    char diagnostic[64]; /* the engine's diagnostic code name */
    char budget[48];     /* CAPACITY: the engine's budget name, e.g. "MAX_RULES" */
    uint64_t requested;  /* CAPACITY: the count or size that was attempted */
    uint64_t limit;      /* CAPACITY: the bound in effect where it failed */
    char file[256];      /* the policy, as the engine names it */
    size_t line, column;
} maelys_git_failure_detail_t;

typedef struct {
    maelys_git_result_t code;
    int system_error;
    char message[MAELYS_GIT_MAX_ERROR];
    maelys_git_failure_detail_t detail;
} maelys_git_error_t;

const char *maelys_git_result_name(maelys_git_result_t result);
/* "none", "capacity", "syntax", "semantics", "manifest", "value", "engine". */
const char *maelys_git_failure_kind_name(maelys_git_failure_kind_t kind);
void maelys_git_error_clear(maelys_git_error_t *error);

typedef enum {
    MAELYS_GIT_SERVICE_UPLOAD_PACK = 1,
    MAELYS_GIT_SERVICE_RECEIVE_PACK = 2
} maelys_git_service_t;

typedef struct {
    maelys_git_service_t service;
    char repository[MAELYS_GIT_MAX_REPOSITORY];
} maelys_git_ssh_command_t;

maelys_git_result_t maelys_git_parse_ssh_command(
    const char *original_command,
    maelys_git_ssh_command_t *out,
    maelys_git_error_t *error);

int maelys_git_repository_name_is_valid(const char *name);
int maelys_git_ref_name_is_valid(const char *ref_name);
/* 40 (SHA-1) or 64 (SHA-256) hexadecimal digits. */
int maelys_git_oid_is_valid(const char *value);

maelys_git_result_t maelys_git_resolve_repository(
    const char *repository_root,
    const char *repository_name,
    char *out_path,
    size_t out_capacity,
    maelys_git_error_t *error);

/* A loaded policy set. Handles are thread-confined: distinct handles are
 * independent, but one handle must not be used concurrently. */
typedef struct maelys_git_policy maelys_git_policy_t;

typedef struct {
    const char *request_id;
    const char *principal;
    const char *repository;
    const char *operation;
    const char *ref_name;
    const char *ssh_key;
    const char *remote_address;
    const char *const *paths;
    size_t path_count;
    const char *ref_kind;
    const char *update_kind;
    const char *change_kind;
    const char *old_path;
    size_t changed_count;
    size_t added_count;
    size_t modified_count;
    size_t deleted_count;
    size_t renamed_count;
    unsigned long long max_new_blob_size;
    unsigned long long total_new_blob_size;
    size_t commit_count;
    size_t merge_commit_count;
    int has_binary;
    int has_summary;
    unsigned long long change_blob_size;
    unsigned int old_mode;
    unsigned int new_mode;
    int change_binary;
    int change_symlink;
    int change_submodule;
    int change_lfs_pointer;
    int has_change_details;
    const char *commit_email;
    int commit_signed;
    int has_commit_signed;
    const char *commit_signature_status;
    const char *commit_signer_fingerprint;
    const char *commit_signer_identity;
    int commit_signature_trusted;
    int has_commit_signature_trusted;
} maelys_git_policy_request_t;

typedef struct {
    int allowed;
    int explicit_deny;
    size_t matched_policy;
    char reason[MAELYS_GIT_MAX_ERROR];
    /* Identity of the evaluated policy set (maelys_git_policy_fingerprint) and
     * of the policy that produced the decision; the latter is empty for a
     * denial by default, which no single policy produced. */
    char policy_set_fingerprint[65];
    char session_fingerprint[65];
} maelys_git_policy_decision_t;

/* What an explanation document is. A why-true document is a derivation
 * witness. A why-false document refutes the fact within the engine's search
 * bounds when its status is complete; when truncated it is a partial
 * diagnostic and proves no absence. */
typedef enum {
    MAELYS_GIT_EXPLANATION_NONE = 0,
    MAELYS_GIT_EXPLANATION_WHY_TRUE = 1,
    MAELYS_GIT_EXPLANATION_WHY_FALSE = 2
} maelys_git_explanation_kind_t;

typedef enum {
    MAELYS_GIT_EXPLANATION_NOT_APPLICABLE = 0,
    MAELYS_GIT_EXPLANATION_COMPLETE = 1,
    MAELYS_GIT_EXPLANATION_TRUNCATED = 2
} maelys_git_explanation_status_t;

typedef struct {
    maelys_git_policy_decision_t decision;
    maelys_git_explanation_kind_t kind;
    maelys_git_explanation_status_t status;
    /* The explained query predicate, "allow" or "deny", and the policy whose
     * result was explained. */
    char query[8];
    size_t explained_policy;
    /* Filter evaluations of that policy's solve. */
    size_t filter_matches;
    size_t filter_non_matches;
    size_t filter_cost_units;
    /* Bytes of the document, excluding the terminating NUL: written, and needed. */
    size_t text_length;
    size_t text_required;
} maelys_git_policy_explanation_t;

maelys_git_result_t maelys_git_policy_open(
    const char *manifest_path,
    maelys_git_policy_t **out_policy,
    maelys_git_error_t *error);
/* maelys_git_policy_open with a snapshot of Gitolite grants,
 * maelys-git-grants/1 or /2, read once as a trusted file: links are followed and
 * the directory of their target judged; the descriptor read is observed
 * before and after the read. A set whose policy reads the snapshot (the
 * audited Gitolite program, the only one allowed to) must be opened so; a
 * snapshot needs such a set. A snapshot is published by renaming a new,
 * complete file over the path, never by writing the published one. */
maelys_git_result_t maelys_git_policy_open_grants(
    const char *manifest_path,
    const char *grants_path,
    maelys_git_policy_t **out_policy,
    maelys_git_error_t *error);
void maelys_git_policy_close(maelys_git_policy_t *policy);
/* The SHA-256 of the bytes of the handle's snapshot of grants; an empty
 * string for a handle opened without one. */
maelys_git_result_t maelys_git_policy_grants_fingerprint(
    const maelys_git_policy_t *policy,
    char out_hex[65],
    maelys_git_error_t *error);
maelys_git_result_t maelys_git_policy_fingerprint(
    const maelys_git_policy_t *policy,
    char out_hex[65],
    maelys_git_error_t *error);
maelys_git_result_t maelys_git_policy_authorize(
    maelys_git_policy_t *policy,
    const maelys_git_policy_request_t *request,
    maelys_git_policy_decision_t *out_decision,
    maelys_git_error_t *error);

/* Decides as maelys_git_policy_authorize does, then renders the canonical
 * MAELYS-DATALOG-v2 explanation of that decision into out_text: the witness of
 * a derived allow or deny, or the why-false document of a denial by default.
 * With out_text NULL and capacity 0 only the record is filled, including
 * text_required. A buffer shorter than text_required + 1 bytes is
 * MAELYS_GIT_ERR_LIMIT and receives no partial text. The document may quote
 * policy and request values. */
maelys_git_result_t maelys_git_policy_explain(
    maelys_git_policy_t *policy,
    const maelys_git_policy_request_t *request,
    char *out_text,
    size_t capacity,
    maelys_git_policy_explanation_t *out_explanation,
    maelys_git_error_t *error);

/* ---- authorization receipts ------------------------------------------------- */

typedef enum {
    MAELYS_GIT_RECEIPT_ALLOW = 1,
    MAELYS_GIT_RECEIPT_DENY_EXPLICIT = 2,
    MAELYS_GIT_RECEIPT_DENY_DEFAULT = 3,
    MAELYS_GIT_RECEIPT_DENY_ERROR = 4
} maelys_git_receipt_decision_t;

/* When the engine's explanation of a decision is rendered: never, on a
 * denial only, or always. NEVER renders, hashes and allocates nothing. */
typedef enum {
    MAELYS_GIT_EXPLAIN_NEVER = 0,
    MAELYS_GIT_EXPLAIN_ON_DENIAL = 1,
    MAELYS_GIT_EXPLAIN_ALWAYS = 2
} maelys_git_explain_mode_t;

typedef enum {
    MAELYS_GIT_RECEIPT_STATUS_NOT_REQUESTED = 0,
    MAELYS_GIT_RECEIPT_STATUS_COMPLETE = 1,
    MAELYS_GIT_RECEIPT_STATUS_TRUNCATED = 2,
    MAELYS_GIT_RECEIPT_STATUS_NOT_APPLICABLE = 3,
    MAELYS_GIT_RECEIPT_STATUS_UNKNOWN = 4
} maelys_git_receipt_status_t;

/* Bits of maelys_git_receipt_t.explanation.limit_hits. */
#define MAELYS_GIT_RECEIPT_LIMIT_CANDIDATE_RULES 1u
#define MAELYS_GIT_RECEIPT_LIMIT_SUBSTITUTIONS 2u
#define MAELYS_GIT_RECEIPT_LIMIT_DEPTH 4u
#define MAELYS_GIT_RECEIPT_LIMIT_DIAGNOSTICS 8u
#define MAELYS_GIT_RECEIPT_LIMIT_FILTER_COST 16u

/* The request a receipt records: no path, only their number. */
typedef struct {
    char id[512];
    char principal[512];
    char repository[MAELYS_GIT_MAX_REPOSITORY];
    char operation[64];
    char ref[MAELYS_GIT_MAX_REF]; /* empty without a ref */
    size_t path_count;
} maelys_git_receipt_request_t;

/* The bounded summary of a rendered explanation, read from the engine's
 * structured views; the text itself is only known by its size and digest. */
typedef struct {
    maelys_git_explanation_kind_t kind; /* NONE when not rendered */
    maelys_git_receipt_status_t status;
    size_t policy_index;
    char query[8];                      /* "allow" or "deny" */
    int has_rule;                       /* why-true complete */
    size_t rule_id, step_count, premise_count;
    int has_counts;                     /* why-false with structured views */
    size_t candidate_rules, diagnostics, filter_cost_units, substitutions;
    unsigned limit_hits;
    int has_text;                       /* the engine rendered a document */
    size_t text_bytes;
    char text_sha256[65];
} maelys_git_receipt_explanation_t;

/* The snapshot of grants a decision used: present when a policy of the set
 * read it, which only the audited Gitolite program may (receipt version 2).
 * Its format is the one read, maelys-git-grants/1, or /2 when it holds
 * regex ref patterns. The program is the version of the audited Gitolite
 * program the set holds, known when the set is opened, whichever policy
 * decides: maelys-git-gitolite-program/1, or /2, which also reads a
 * repository by a ref grant. The format of the slice is fixed by the
 * receipt's version: maelys-git-slice/1. */
typedef struct {
    int present;
    char sha256[65]; /* of the snapshot's bytes */
    size_t facts;    /* distinct tuples of the slice given to the engine */
    char format[32]; /* maelys-git-grants/1 or maelys-git-grants/2 */
    char program[40]; /* maelys-git-gitolite-program/1 or maelys-git-gitolite-program/2 */
} maelys_git_receipt_grants_t;

/* The record of one decision, built by the code path that authorizes. It
 * holds a bounded summary of the engine's explanation, never its text: the
 * text travels beside the receipt, which keeps its size and SHA-256. Every
 * string is NUL-terminated; an empty one is null in the serialized form
 * where the contract allows null. */
typedef struct {
    maelys_git_receipt_decision_t decision;
    char error_code[32];   /* deny_error: maelys_git_result_name of the failure */
    char error_kind[16];   /* deny_error: maelys_git_failure_kind_name, or empty */
    char error_budget[48]; /* deny_error of a capacity the engine names, or empty */
    char policy_set_fingerprint[65];
    int matched;           /* allow and deny_explicit name the deciding policy */
    size_t matched_policy_index;
    char matched_policy_id[128];
    char matched_session_fingerprint[65];
    maelys_git_receipt_request_t request;
    size_t edb_facts;          /* request facts given to the engine */
    size_t evaluated_policies; /* policies solved before the decision */
    maelys_git_receipt_explanation_t explanation;
    maelys_git_receipt_grants_t grants;
} maelys_git_receipt_t;

/* Authorizes as maelys_git_policy_authorize does and fills the receipt of
 * that decision. The decision, its reason and the result code are those of
 * maelys_git_policy_authorize; a failure of the engine is also recorded as a
 * deny_error receipt. With a rendered explanation, its text is copied into
 * out_text when text_capacity exceeds its size; the receipt is identical
 * either way. Engine failures keep their code; a receipt whose request does
 * not fit its fields is MAELYS_GIT_ERR_LIMIT. */
maelys_git_result_t maelys_git_policy_authorize_receipt(
    maelys_git_policy_t *policy,
    const maelys_git_policy_request_t *request,
    maelys_git_explain_mode_t mode,
    char *out_text,
    size_t text_capacity,
    maelys_git_policy_decision_t *out_decision,
    maelys_git_receipt_t *out_receipt,
    maelys_git_error_t *error);

typedef struct {
    char **items;
    size_t count;
} maelys_git_path_list_t;

void maelys_git_path_list_clear(maelys_git_path_list_t *paths);

maelys_git_result_t maelys_git_repository_changed_paths(
    const char *git_executable,
    const char *repository_path,
    const char *old_oid,
    const char *new_oid,
    maelys_git_path_list_t *out_paths,
    maelys_git_error_t *error);

typedef enum {
    MAELYS_GIT_REF_BRANCH = 1,
    MAELYS_GIT_REF_TAG = 2,
    MAELYS_GIT_REF_OTHER = 3
} maelys_git_ref_kind_t;

typedef enum {
    MAELYS_GIT_UPDATE_CREATE = 1,
    MAELYS_GIT_UPDATE_FAST_FORWARD = 2,
    MAELYS_GIT_UPDATE_FORCE = 3,
    MAELYS_GIT_UPDATE_DELETE = 4
} maelys_git_update_kind_t;

typedef enum {
    MAELYS_GIT_CHANGE_ADD = 1,
    MAELYS_GIT_CHANGE_MODIFY = 2,
    MAELYS_GIT_CHANGE_DELETE = 3,
    MAELYS_GIT_CHANGE_RENAME = 4,
    MAELYS_GIT_CHANGE_TYPE = 5
} maelys_git_change_kind_t;

typedef struct {
    maelys_git_change_kind_t kind;
    char path[4096];
    char old_path[4096];
    char old_oid[65];
    char new_oid[65];
    unsigned int old_mode;
    unsigned int new_mode;
    unsigned long long new_blob_size;
    int binary;
    int symlink;
    int submodule;
    int lfs_pointer;
} maelys_git_change_t;

typedef struct {
    size_t changed_count;
    size_t added_count;
    size_t modified_count;
    size_t deleted_count;
    size_t renamed_count;
    unsigned long long max_new_blob_size;
    unsigned long long total_new_blob_size;
    size_t inspected_blob_bytes;
    int has_binary;
} maelys_git_change_summary_t;

typedef struct {
    size_t max_commits;
    size_t max_changes;
    unsigned long long max_total_new_blob_size;
    size_t max_inspected_blob_bytes;
} maelys_git_inspection_limits_t;

void maelys_git_inspection_limits_default(maelys_git_inspection_limits_t *limits);

typedef maelys_git_result_t (*maelys_git_change_visitor_t)(
    const maelys_git_change_t *change,
    void *context,
    maelys_git_error_t *error);

const char *maelys_git_ref_kind_name(maelys_git_ref_kind_t kind);
const char *maelys_git_update_kind_name(maelys_git_update_kind_t kind);
const char *maelys_git_change_kind_name(maelys_git_change_kind_t kind);
maelys_git_ref_kind_t maelys_git_classify_ref(const char *ref_name);
maelys_git_result_t maelys_git_repository_classify_update(
    const char *git_executable,
    const char *repository_path,
    const char *old_oid,
    const char *new_oid,
    maelys_git_update_kind_t *out_kind,
    maelys_git_error_t *error);
maelys_git_result_t maelys_git_repository_visit_changes(
    const char *git_executable,
    const char *repository_path,
    const char *old_oid,
    const char *new_oid,
    maelys_git_change_visitor_t visitor,
    void *visitor_context,
    maelys_git_change_summary_t *out_summary,
    maelys_git_error_t *error);
maelys_git_result_t maelys_git_repository_visit_changes_ex(
    const char *git_executable,
    const char *repository_path,
    const char *old_oid,
    const char *new_oid,
    const maelys_git_inspection_limits_t *limits,
    maelys_git_change_visitor_t visitor,
    void *visitor_context,
    maelys_git_change_summary_t *out_summary,
    maelys_git_error_t *error);

typedef struct {
    char old_oid[65];
    char new_oid[65];
    char ref_name[MAELYS_GIT_MAX_REF];
    maelys_git_ref_kind_t ref_kind;
    maelys_git_update_kind_t update_kind;
    size_t commit_count;
    size_t merge_commit_count;
    maelys_git_change_summary_t changes;
} maelys_git_receive_update_t;

typedef struct {
    maelys_git_receive_update_t *updates;
    size_t update_count;
    maelys_git_change_summary_t changes;
} maelys_git_receive_transaction_t;

void maelys_git_receive_transaction_clear(maelys_git_receive_transaction_t *transaction);
maelys_git_result_t maelys_git_receive_transaction_read(
    FILE *input,
    maelys_git_receive_transaction_t *out_transaction,
    maelys_git_error_t *error);

maelys_git_result_t maelys_git_repository_init_bare(
    const char *git_executable,
    const char *repository_root,
    const char *repository_name,
    maelys_git_error_t *error);

maelys_git_result_t maelys_git_repository_update_ref(
    const char *git_executable,
    const char *repository_path,
    const char *ref_name,
    const char *new_oid,
    const char *expected_old_oid,
    maelys_git_error_t *error);

typedef enum {
    MAELYS_GIT_REPOSITORY_ACTIVE = 1,
    MAELYS_GIT_REPOSITORY_ARCHIVE = 2,
    MAELYS_GIT_REPOSITORY_TRASH = 3
} maelys_git_repository_state_t;

typedef struct {
    char repository[MAELYS_GIT_MAX_REPOSITORY];
    char storage_id[MAELYS_GIT_MAX_LIFECYCLE_ID];
    maelys_git_repository_state_t state;
} maelys_git_repository_entry_t;

typedef struct {
    maelys_git_repository_entry_t *entries;
    size_t count;
} maelys_git_repository_list_t;

typedef struct {
    char repository[MAELYS_GIT_MAX_REPOSITORY];
    char path[4096];
    char identity[128];
    char head_ref[MAELYS_GIT_MAX_REF];
    char head_oid[65];
    size_t ref_count;
    unsigned long long object_count;
    unsigned long long object_bytes;
} maelys_git_repository_info_t;

typedef struct {
    char source_repository[MAELYS_GIT_MAX_REPOSITORY];
    char target_repository[MAELYS_GIT_MAX_REPOSITORY];
    char storage_id[MAELYS_GIT_MAX_LIFECYCLE_ID];
    char source_identity[128];
    char source_path[4096];
    char target_path[4096];
    maelys_git_repository_state_t source_state;
    maelys_git_repository_state_t target_state;
} maelys_git_repository_transition_t;

const char *maelys_git_repository_state_name(maelys_git_repository_state_t state);
int maelys_git_lifecycle_id_is_valid(const char *identifier);
void maelys_git_repository_list_clear(maelys_git_repository_list_t *list);
maelys_git_result_t maelys_git_repository_list(
    const char *repository_root,
    int include_stored,
    maelys_git_repository_list_t *out_list,
    maelys_git_error_t *error);
maelys_git_result_t maelys_git_repository_inspect(
    const char *git_executable,
    const char *repository_root,
    const char *repository_name,
    maelys_git_repository_info_t *out_info,
    maelys_git_error_t *error);
maelys_git_result_t maelys_git_repository_rename(
    const char *repository_root,
    const char *source_repository,
    const char *target_repository,
    const char *expected_source_identity,
    int apply,
    maelys_git_repository_transition_t *out_transition,
    maelys_git_error_t *error);
maelys_git_result_t maelys_git_repository_store(
    const char *repository_root,
    const char *repository_name,
    maelys_git_repository_state_t target_state,
    const char *storage_id,
    const char *expected_source_identity,
    int apply,
    maelys_git_repository_transition_t *out_transition,
    maelys_git_error_t *error);
maelys_git_result_t maelys_git_repository_restore(
    const char *repository_root,
    maelys_git_repository_state_t source_state,
    const char *storage_id,
    const char *target_repository,
    const char *expected_source_identity,
    int apply,
    maelys_git_repository_transition_t *out_transition,
    maelys_git_error_t *error);

typedef struct {
    char source_repository[MAELYS_GIT_MAX_REPOSITORY];
    char target_repository[MAELYS_GIT_MAX_REPOSITORY];
    char source_path[4096];
    char target_path[4096];
    char source_identity[128];
    char target_identity[128];
    char source_fingerprint[65];
    char target_fingerprint[65];
    int target_exists;
    int changed;
} maelys_git_repository_mirror_result_t;

maelys_git_result_t maelys_git_repository_mirror(
    const char *git_executable,
    const char *source_root,
    const char *source_repository,
    const char *target_root,
    const char *target_repository,
    const char *expected_source_identity,
    const char *expected_target_identity,
    const char *expected_source_fingerprint,
    const char *expected_target_fingerprint,
    int apply,
    maelys_git_repository_mirror_result_t *out_result,
    maelys_git_error_t *error);

typedef enum {
    MAELYS_GIT_MERGE_FAST_FORWARD = 1,
    MAELYS_GIT_MERGE_COMMIT = 2,
    MAELYS_GIT_MERGE_SQUASH = 3
} maelys_git_merge_style_t;

typedef struct {
    const char *repository_path;
    const char *repository_name;
    const char *ref_name;
    const char *expected_identity;
    size_t max_objects;
    uint64_t max_bytes;
} maelys_git_pr_source_t;

typedef struct {
    int mergeable;
    int empty;
    int cross_repository;
    char merge_base_oid[65];
    char merge_tree_oid[65];
    char prepared_oid[65];
    char policy_fingerprint[65];
    char target_identity[128];
    char source_repository[MAELYS_GIT_MAX_REPOSITORY];
    char source_ref[MAELYS_GIT_MAX_REF];
    char source_oid[65];
    char source_identity[128];
    size_t source_object_count;
    uint64_t source_object_bytes;
    char pr_id[128];
    char pr_head_ref[MAELYS_GIT_MAX_REF];
    char pr_merged_ref[MAELYS_GIT_MAX_REF];
    maelys_git_path_list_t conflict_paths;
    /* The pull request's own diff, merge base -> head: a diagnostic, always
     * present, that no decision reads. */
    maelys_git_change_summary_t changes;
    /* The SHA-256 of the policy handle's snapshot of grants; empty without
     * one, and for pr check, which decides nothing. */
    char grants_fingerprint[65];
    /* The change the merge applies to its base, base -> prepared commit:
     * what pr merge authorizes, its paths, their attributes and this
     * summary. Present only with a prepared commit: not for a conflict, a
     * fast-forward that cannot be, or an empty pull request. */
    int has_applied_changes;
    maelys_git_change_summary_t applied_changes;
} maelys_git_pr_check_result_t;

typedef struct {
    size_t approvals;
    size_t required_approvals;
    int status_checks_passed;
    int blocking_review;
} maelys_git_pr_gates_t;

void maelys_git_pr_check_result_clear(maelys_git_pr_check_result_t *result);
maelys_git_result_t maelys_git_pr_check(
    const char *git_executable,
    const char *repository_path,
    const char *base_oid,
    const char *head_oid,
    maelys_git_merge_style_t style,
    const char *message,
    maelys_git_pr_check_result_t *out_result,
    maelys_git_error_t *error);
maelys_git_result_t maelys_git_pr_check_with_source(
    const char *git_executable,
    const char *repository_path,
    const char *base_oid,
    const char *head_oid,
    maelys_git_merge_style_t style,
    const char *message,
    const maelys_git_pr_source_t *source,
    maelys_git_pr_check_result_t *out_result,
    maelys_git_error_t *error);
maelys_git_result_t maelys_git_pr_merge(
    const char *git_executable,
    const char *repository_path,
    const char *repository_name,
    const char *base_ref,
    const char *base_oid,
    const char *head_oid,
    maelys_git_merge_style_t style,
    const char *message,
    const char *principal,
    const maelys_git_pr_gates_t *gates,
    maelys_git_policy_t *policy,
    const char *pr_id,
    const char *expected_target_identity,
    const char *expected_prepared_oid,
    const char *expected_policy_fingerprint,
    int apply,
    maelys_git_pr_check_result_t *out_result,
    maelys_git_error_t *error);
maelys_git_result_t maelys_git_pr_merge_with_source(
    const char *git_executable,
    const char *repository_path,
    const char *repository_name,
    const char *base_ref,
    const char *base_oid,
    const char *head_oid,
    maelys_git_merge_style_t style,
    const char *message,
    const char *principal,
    const maelys_git_pr_gates_t *gates,
    maelys_git_policy_t *policy,
    const char *pr_id,
    const maelys_git_pr_source_t *source,
    const char *expected_target_identity,
    const char *expected_prepared_oid,
    const char *expected_policy_fingerprint,
    int apply,
    maelys_git_pr_check_result_t *out_result,
    maelys_git_error_t *error);

/* maelys_git_pr_merge_with_source with the precondition on grants: apply
 * on a handle opened with a snapshot of grants requires the grants
 * fingerprint the plan returned, and refuses other grants with "grants
 * changed; run a new pull request plan". The two entry points above plan
 * on such a handle, and refuse to apply on it. */
maelys_git_result_t maelys_git_pr_merge_grants(
    const char *git_executable,
    const char *repository_path,
    const char *repository_name,
    const char *base_ref,
    const char *base_oid,
    const char *head_oid,
    maelys_git_merge_style_t style,
    const char *message,
    const char *principal,
    const maelys_git_pr_gates_t *gates,
    maelys_git_policy_t *policy,
    const char *pr_id,
    const maelys_git_pr_source_t *source,
    const char *expected_target_identity,
    const char *expected_prepared_oid,
    const char *expected_policy_fingerprint,
    const char *expected_grants_fingerprint,
    int apply,
    maelys_git_pr_check_result_t *out_result,
    maelys_git_error_t *error);

typedef maelys_git_result_t (*maelys_git_inspector_fn)(
    const maelys_git_receive_update_t *update,
    const maelys_git_change_t *change,
    void *context,
    maelys_git_error_t *error);

typedef struct {
    const char *name;
    maelys_git_inspector_fn inspect;
    void *context;
} maelys_git_inspector_t;

maelys_git_result_t maelys_git_run_inspectors(
    const maelys_git_inspector_t *inspectors,
    size_t inspector_count,
    const maelys_git_receive_update_t *update,
    const maelys_git_change_t *change,
    maelys_git_error_t *error);

maelys_git_result_t maelys_git_compile_authorized_keys(
    const char *key_directory,
    const char *output_path,
    const char *shell_path,
    const char *repository_root,
    const char *manifest_path,
    int apply,
    size_t *out_key_count,
    maelys_git_error_t *error);

/* What a generated policy costs, against the bounds of the linked engine.
 * Compilation is the engine's verdict on the policy: its rules, facts and
 * predicates, 0 when it refused. Execution is the generator's own worst case
 * for one request, by construction: the most facts one derived predicate can
 * hold, and all derived facts together. `failure` says which bound does not
 * hold; its kind is NONE when the budget holds. */
typedef struct {
    int compiled;
    size_t rules;
    size_t rule_limit;
    size_t facts;
    size_t fact_limit;
    size_t predicates;
    size_t predicate_limit;
    size_t derived_per_predicate;
    size_t derived_per_predicate_limit;
    size_t derived;
    size_t derived_limit;
    maelys_git_failure_detail_t failure;
} maelys_git_policy_budget_t;

typedef struct {
    size_t group_count;
    size_t repository_count;
    size_t rule_count;
    size_t vref_count;
    char **unsupported;
    size_t unsupported_count;
    maelys_git_policy_budget_t budget;
    /* The format of grants.json: maelys-git-grants/1, or /2 when a refex is
     * migrated as a regex pattern. */
    char grants_format[32];
    /* What applies otherwise than in Gitolite without refusing the entry:
     * a repository whose ref denies win over its grants whatever their
     * order, a group that holds rights without a member. */
    char **remarks;
    size_t remark_count;
} maelys_git_gitolite_migration_result_t;

void maelys_git_gitolite_migration_result_clear(
    maelys_git_gitolite_migration_result_t *result);
/* Migrates the safe subset of a Gitolite configuration into OUTPUT_DIRECTORY,
 * which must not exist: the audited Gitolite program,
 * maelys-git-gitolite-program/2, as gitolite-migrated.dl, its manifest, and
 * the configuration's grants as grants.json, maelys-git-grants/1 (or /2 when
 * it holds regex ref patterns), which the program reads with --grants
 * (maelys_git_policy_open_grants). A set written as /1 by an earlier Git
 * Core is still opened and decided as it was. The program
 * does not depend on the configuration: its budget is fixed; the plan judges
 * the groups of a user and the bounds of the snapshot. Apply publishes the
 * directory by one rename, after the engine loaded it with its snapshot. */
maelys_git_result_t maelys_git_migrate_gitolite(
    const char *input_path,
    const char *output_directory,
    int apply,
    maelys_git_gitolite_migration_result_t *out_result,
    maelys_git_error_t *error);

maelys_git_result_t maelys_git_exec_service(
    const char *git_executable,
    maelys_git_service_t service,
    const char *repository_path,
    const char *principal,
    maelys_git_error_t *error);

maelys_git_result_t maelys_git_pre_receive(
    maelys_git_policy_t *policy,
    const char *git_executable,
    const char *repository_path,
    const char *repository_name,
    const char *principal,
    FILE *input,
    FILE *diagnostics,
    maelys_git_error_t *error);
maelys_git_result_t maelys_git_pre_receive_ex(
    maelys_git_policy_t *policy,
    const char *git_executable,
    const char *repository_path,
    const char *repository_name,
    const char *principal,
    const maelys_git_inspector_t *inspectors,
    size_t inspector_count,
    FILE *input,
    FILE *diagnostics,
    maelys_git_error_t *error);
maelys_git_result_t maelys_git_pre_receive_with_limits(
    maelys_git_policy_t *policy,
    const char *git_executable,
    const char *repository_path,
    const char *repository_name,
    const char *principal,
    const maelys_git_inspection_limits_t *limits,
    const maelys_git_inspector_t *inspectors,
    size_t inspector_count,
    FILE *input,
    FILE *diagnostics,
    maelys_git_error_t *error);

maelys_git_result_t maelys_git_post_receive(
    const char *repository_name,
    const char *principal,
    FILE *input,
    FILE *events,
    maelys_git_error_t *error);

#ifdef __cplusplus
}
#endif

#endif
