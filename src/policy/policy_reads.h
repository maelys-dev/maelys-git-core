#ifndef MAELYS_GIT_POLICY_READS_H
#define MAELYS_GIT_POLICY_READS_H

/* The question a policy set answers when it is opened: whether its enabled
 * policy at policy_index reads name/arity. maelys_git_policy_open asks the
 * engine, maelys_datalog_policy_reads_predicate; a test answers in its place
 * to drive a failed answer through the code that opens a policy. */

#include "maelys_git.h"

#include <maelys/datalog.h>

typedef maelys_datalog_status_t (*mg_policy_reads_t)(const maelys_datalog_policy_t *policy,
                                                     size_t policy_index, const char *name,
                                                     size_t arity, int *out_reads);

/* maelys_git_policy_open, with `reads` answering the question above. */
maelys_git_result_t mg_policy_open_reads(const char *manifest_path, mg_policy_reads_t reads,
                                         maelys_git_policy_t **out_policy,
                                         maelys_git_error_t *error);

#endif
