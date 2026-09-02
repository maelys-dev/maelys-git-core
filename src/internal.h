#ifndef MAELYS_GIT_INTERNAL_H
#define MAELYS_GIT_INTERNAL_H

#include "maelys_git.h"

#include <spawn.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

void mg_error_set(maelys_git_error_t *error,
                  maelys_git_result_t code,
                  int system_error,
                  const char *format,
                  ...);
int mg_copy_string(char *out, size_t capacity, const char *value);
int mg_is_oid(const char *value);
int mg_is_zero_oid(const char *value);
int mg_json_write_string(FILE *output, const char *value);

int64_t mg_monotonic_ms(void);
int mg_pipe_cloexec(int pipe_fds[2]);
maelys_git_result_t mg_spawn_isolated(
    pid_t *out_pid,
    const char *executable,
    const posix_spawn_file_actions_t *actions,
    char *const argv[],
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
int mg_remove_tree(const char *path);
maelys_git_result_t mg_repository_ensure_parent_directories(
    const char *root,
    const char *target,
    maelys_git_error_t *error);

#endif
