#ifndef MAELYS_GIT_INTERNAL_H
#define MAELYS_GIT_INTERNAL_H

/* Private helpers shared by the core library modules. Every function here is
 * an implementation detail: it is not installed and may change freely. */

#include "maelys_git.h"

#include <limits.h>
#include <spawn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* "device:inode" identity of a directory, in hexadecimal. */
#define MG_IDENTITY_MAX 128u

/* Default wall-clock budget of one Git subprocess. */
#define MG_PROCESS_TIMEOUT_MS UINT64_C(120000)

#if defined(__GNUC__) || defined(__clang__)
#define MG_PRINTF(format_index, first_argument) \
    __attribute__((format(printf, format_index, first_argument)))
#else
#define MG_PRINTF(format_index, first_argument)
#endif

/* ---- diagnostics and strings ------------------------------------------- */

/* Sets the code and message and resets the failure detail. */
void mg_error_set(maelys_git_error_t *error,
                  maelys_git_result_t code,
                  int system_error,
                  const char *format,
                  ...) MG_PRINTF(4, 5);
/* Records the detail of the policy failure just set by mg_error_set; an
 * error whose code is not MAELYS_GIT_ERR_POLICY keeps none. */
void mg_error_set_detail(maelys_git_error_t *error, const maelys_git_failure_detail_t *detail);
int mg_copy_string(char *out, size_t capacity, const char *value);
int mg_is_oid(const char *value);
int mg_is_zero_oid(const char *value);
/* Removes trailing CR/LF bytes and keeps the buffer NUL-terminated. */
void mg_trim_line_endings(unsigned char *data, size_t *length);
int mg_json_write_string(FILE *output, const char *value);

/* ---- files and directories ----------------------------------------------- */

/* realpath() of an existing directory that is not itself a symbolic link.
 * `what` names the path in diagnostics ("repository root"). */
maelys_git_result_t mg_canonical_directory(const char *path,
                                           char out[PATH_MAX],
                                           const char *what,
                                           maelys_git_error_t *error);
int mg_identity_from_stat(const struct stat *status, char out[MG_IDENTITY_MAX]);
/* Identity of a direct directory; returns 0 for anything else. */
int mg_path_identity(const char *path,
                     char out[MG_IDENTITY_MAX],
                     struct stat *out_status);
/* rename(2) that never replaces an existing entry; atomic where the
 * platform offers it. Returns -1 with errno (EEXIST when occupied). */
int mg_rename_no_replace(const char *source, const char *target);
/* Absolute temporary root: TMPDIR when it names a directory, else /tmp. */
const char *mg_temporary_root(void);
/* Creates a private directory named `prefix.XXXXXX`. */
maelys_git_result_t mg_make_temporary_directory(const char *prefix,
                                                char out[PATH_MAX],
                                                maelys_git_error_t *error);
/* Creates a new file (O_EXCL, no symlink following), writes it completely,
 * fsyncs it, and removes it again on any failure. */
maelys_git_result_t mg_write_file_exclusive(const char *path,
                                            const void *data,
                                            size_t length,
                                            mode_t mode,
                                            maelys_git_error_t *error);
int mg_remove_tree(const char *path);
maelys_git_result_t mg_repository_ensure_parent_directories(
    const char *root,
    const char *target,
    maelys_git_error_t *error);

/* ---- processes ------------------------------------------------------------- */

int64_t mg_monotonic_ms(void);
int mg_pipe_cloexec(int pipe_fds[2]);
/* Status-returning helpers retain a bounded diagnostic in error->message on
 * nonzero exit. Convert it into a structured failure without losing detail. */
void mg_process_status_error(maelys_git_error_t *error, const char *operation, int status);
/* Only the SSH hook enables receive-pack's validated, repository-local
 * quarantine. The scope is thread-local and must be cleared after receive. */
maelys_git_result_t mg_receive_objects_begin(const char *repository_path,
                                             maelys_git_error_t *error);
void mg_receive_objects_end(void);
maelys_git_result_t mg_spawn_isolated(
    pid_t *out_pid,
    const char *executable,
    const posix_spawn_file_actions_t *actions,
    char *const argv[],
    maelys_git_error_t *error);
/* Starts a group leader whose Git children remain in the supervised group. */
maelys_git_result_t mg_spawn_executor(
    pid_t *out_pid, const char *executable,
    const posix_spawn_file_actions_t *actions, char *const argv[],
    maelys_git_error_t *error);
void mg_terminate_process_group(pid_t pid);
maelys_git_result_t mg_process_run_with_timeout(
    const char *executable,
    char *const argv[],
    uint64_t timeout_ms,
    int *out_exit_status,
    maelys_git_error_t *error);
maelys_git_result_t mg_process_run(const char *executable,
                                   char *const argv[],
                                   int *out_exit_status,
                                   maelys_git_error_t *error);
maelys_git_result_t mg_process_run_status(const char *executable,
                                          char *const argv[],
                                          int *out_exit_status,
                                          maelys_git_error_t *error);
maelys_git_result_t mg_process_capture(const char *executable,
                                       char *const argv[],
                                       unsigned char **out_data,
                                       size_t *out_length,
                                       size_t max_length,
                                       maelys_git_error_t *error);
maelys_git_result_t mg_process_capture_status(const char *executable,
                                              char *const argv[],
                                              unsigned char **out_data,
                                              size_t *out_length,
                                              size_t max_length,
                                              int *out_exit_status,
                                              maelys_git_error_t *error);
maelys_git_result_t mg_process_capture_prefix(const char *executable,
                                              char *const argv[],
                                              unsigned char **out_data,
                                              size_t *out_length,
                                              size_t prefix_length,
                                              int *out_exit_status,
                                              maelys_git_error_t *error);
maelys_git_result_t mg_process_to_file(const char *executable,
                                       char *const argv[],
                                       FILE *output,
                                       int *out_exit_status,
                                       maelys_git_error_t *error);
maelys_git_result_t mg_process_spool_status(const char *executable,
                                            char *const argv[],
                                            FILE *output,
                                            size_t max_length,
                                            int *out_exit_status,
                                            maelys_git_error_t *error);
maelys_git_result_t mg_process_filter_spool_status(const char *executable,
                                                   char *const argv[],
                                                   FILE *input,
                                                   FILE *output,
                                                   size_t max_length,
                                                   int *out_exit_status,
                                                   maelys_git_error_t *error);

/* The receipt of a receive or a merge, asked for by the caller: each
 * authorization fills it, so it ends as the first denial or as the last
 * authorization of an accepted transaction. `decided` says whether it is the
 * receipt of the outcome; a failure outside the policy leaves it 0. */
typedef struct {
    maelys_git_explain_mode_t mode;
    char *text;
    size_t text_capacity;
    maelys_git_receipt_t receipt;
    int decided;
} mg_receive_receipt_t;

/* Shared receive authorization for the hook and the agent's update_ref.
 * Optional outputs expose the aggregate count, the last policy decision and
 * the decisive receipt. Without a receipt the path is that of authorize. */
maelys_git_result_t mg_receive_authorize(
    maelys_git_policy_t *policy, const char *git, const char *repository_path,
    const char *repository_name, const char *principal,
    const maelys_git_inspection_limits_t *limits,
    const maelys_git_inspector_t *inspectors, size_t inspector_count,
    FILE *input, FILE *diagnostics, maelys_git_change_summary_t *out_summary,
    maelys_git_policy_decision_t *out_decision, mg_receive_receipt_t *out_receipt,
    maelys_git_error_t *error);

/* maelys_git_pr_merge_with_source for the agent: the optional outputs expose
 * the last policy decision and the decisive receipt. A refusal of the gates,
 * of an empty or unmergeable pull request or of a changed plan is not the
 * policy's and leaves `decided` 0. */
maelys_git_result_t mg_pr_merge(
    const char *git, const char *repository_path, const char *repository_name,
    const char *base_ref, const char *base_oid, const char *head_oid,
    maelys_git_merge_style_t style, const char *message, const char *principal,
    const maelys_git_pr_gates_t *gates, maelys_git_policy_t *policy, const char *pr_id,
    const maelys_git_pr_source_t *source,
    const char *expected_target_identity, const char *expected_prepared_oid,
    const char *expected_policy_fingerprint, int apply,
    maelys_git_pr_check_result_t *out_result,
    maelys_git_policy_decision_t *out_decision, mg_receive_receipt_t *out_receipt,
    maelys_git_error_t *error);

/* Internal receive budget: zero means no remaining consumption is allowed. */
maelys_git_result_t mg_repository_visit_changes_with_budget(
    const char *git, const char *repository_path, const char *old_oid, const char *new_oid,
    const maelys_git_inspection_limits_t *limits,
    maelys_git_change_visitor_t visitor, void *context,
    maelys_git_change_summary_t *summary, maelys_git_error_t *error);

/* Bytes of explanation storage the handle holds: zero until it explains. */
size_t mg_policy_explanation_storage_bytes(const maelys_git_policy_t *policy);
/* The '/'-terminated prefixes of a request's ref given as ref_prefix facts. */
#define MG_REF_PREFIX_FACTS 16u

/* maelys_git_policy_open on a manifest and the source of its single policy,
 * held in memory: the same loader contract and the same failure detail. */
maelys_git_result_t mg_policy_open_buffer(const char *manifest, size_t manifest_length,
                                          const char *policy_id, const char *source,
                                          size_t source_length, maelys_git_policy_t **out_policy,
                                          maelys_git_error_t *error);
/* The compiled size of an open policy, or nothing for NULL, and the engine
 * bounds that apply to it. The worst cases of execution are the caller's. */
maelys_git_result_t mg_policy_budget(const maelys_git_policy_t *policy,
                                     maelys_git_policy_budget_t *out_budget,
                                     maelys_git_error_t *error);

#endif
