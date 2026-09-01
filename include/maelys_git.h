#ifndef MAELYS_GIT_H
#define MAELYS_GIT_H

#include <stddef.h>
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

typedef struct {
    maelys_git_result_t code;
    int system_error;
    char message[MAELYS_GIT_MAX_ERROR];
} maelys_git_error_t;

const char *maelys_git_result_name(maelys_git_result_t result);
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

maelys_git_result_t maelys_git_resolve_repository(
    const char *repository_root,
    const char *repository_name,
    char *out_path,
    size_t out_capacity,
    maelys_git_error_t *error);

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
    size_t changed_count;
    size_t added_count;
    size_t modified_count;
    size_t deleted_count;
    size_t renamed_count;
    unsigned long long max_new_blob_size;
    int has_binary;
    int has_summary;
    const char *commit_email;
    int commit_signed;
    int has_commit_signed;
} maelys_git_policy_request_t;

typedef struct {
    int allowed;
    int explicit_deny;
    size_t matched_policy;
    char reason[MAELYS_GIT_MAX_ERROR];
} maelys_git_policy_decision_t;

maelys_git_result_t maelys_git_policy_open(
    const char *manifest_path,
    maelys_git_policy_t **out_policy,
    maelys_git_error_t *error);
void maelys_git_policy_close(maelys_git_policy_t *policy);
maelys_git_result_t maelys_git_policy_authorize(
    maelys_git_policy_t *policy,
    const maelys_git_policy_request_t *request,
    maelys_git_policy_decision_t *out_decision,
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
} maelys_git_change_t;

typedef struct {
    size_t changed_count;
    size_t added_count;
    size_t modified_count;
    size_t deleted_count;
    size_t renamed_count;
    unsigned long long max_new_blob_size;
    int has_binary;
} maelys_git_change_summary_t;

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

typedef struct {
    char old_oid[65];
    char new_oid[65];
    char ref_name[MAELYS_GIT_MAX_REF];
    maelys_git_ref_kind_t ref_kind;
    maelys_git_update_kind_t update_kind;
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
    MAELYS_GIT_MERGE_FAST_FORWARD = 1,
    MAELYS_GIT_MERGE_COMMIT = 2,
    MAELYS_GIT_MERGE_SQUASH = 3
} maelys_git_merge_style_t;

typedef struct {
    int mergeable;
    int empty;
    char merge_base_oid[65];
    char merge_tree_oid[65];
    char prepared_oid[65];
    maelys_git_path_list_t conflict_paths;
    maelys_git_change_summary_t changes;
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
