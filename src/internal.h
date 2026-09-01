#ifndef MAELYS_GIT_INTERNAL_H
#define MAELYS_GIT_INTERNAL_H

#include "maelys_git.h"

#include <stddef.h>

void mg_error_set(maelys_git_error_t *error,
                  maelys_git_result_t code,
                  int system_error,
                  const char *format,
                  ...);
int mg_copy_string(char *out, size_t capacity, const char *value);
int mg_is_oid(const char *value);
int mg_is_zero_oid(const char *value);
int mg_json_write_string(FILE *output, const char *value);

maelys_git_result_t mg_process_run(const char *executable,
                                   char *const argv[],
                                   int *out_exit_status,
                                   maelys_git_error_t *error);
maelys_git_result_t mg_process_capture(const char *executable,
                                       char *const argv[],
                                       unsigned char **out_data,
                                       size_t *out_length,
                                       size_t max_length,
                                       maelys_git_error_t *error);

#endif
