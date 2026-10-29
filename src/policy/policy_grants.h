#ifndef MAELYS_GIT_POLICY_GRANTS_HANDLE_H
#define MAELYS_GIT_POLICY_GRANTS_HANDLE_H

/* A policy handle opened with a snapshot of grants. The audited Gitolite
 * program of its set receives, for each request, the slice of the snapshot
 * after the request's facts; every other policy receives the request's
 * facts alone. */

#include "maelys_git.h"
#include "policy/slice.h"

#include <maelys/datalog.h>

#include <stddef.h>

/* maelys_git_policy_open, with the snapshot of grants at GRANTS_PATH, read
 * once as a trusted file. A set whose policy reads slice_* must be opened
 * so, and that policy must be the audited program; a snapshot needs a set
 * that has it. */
maelys_git_result_t mg_policy_open_grants(const char *manifest_path, const char *grants_path,
                                          maelys_git_policy_t **out_policy, maelys_git_error_t *error);

/* Reads the handle's snapshot again, for a stream, before each command: the
 * same bytes keep the index; other bytes replace it; a failure leaves the
 * handle without a snapshot, refusing every request until a reading
 * succeeds. A handle opened without grants is left as it is, and so is a
 * pinned handle during the first command of its stream
 * (mg_policy_expect_grants). */
maelys_git_result_t mg_policy_refresh_grants(maelys_git_policy_t *policy, maelys_git_error_t *error);

/* Marks the start of one command of a stream, whatever it is, health and an
 * expired command included: the first one of a pinned handle uses the
 * reading its pin verified, and every later one reads again. */
void mg_policy_begin_command(maelys_git_policy_t *policy);

/* Every reading of the handle's snapshot, the one made at its opening
 * included, must have SHA256: a reading with other bytes refuses, as a
 * failed reading does, with MAELYS_GIT_ERR_PROCESS. An executor started on an
 * immutable file of the agent's store is given its digest. The reading this
 * call verifies serves the next command of the stream, whatever it is
 * (mg_policy_begin_command): a health or an expired command uses it up
 * without reading, and every later command reads again. */
maelys_git_result_t mg_policy_expect_grants(maelys_git_policy_t *policy, const char *sha256,
                                            maelys_git_error_t *error);

/* The SHA-256 of the snapshot's bytes, or NULL for a handle without one. */
const char *mg_policy_grants_sha256(const maelys_git_policy_t *policy);
/* The regex searches the handle's current snapshot has made (tests and
 * measurements): a new generation starts again from zero. */
size_t mg_policy_regex_searches(const maelys_git_policy_t *policy);
/* The scratch of the handle's current snapshot and its size (tests). */
void *mg_policy_grants_scratch(const maelys_git_policy_t *policy, size_t *out_size);

/* The facts of the last request: its context, which every policy received,
 * and its slice, which the audited program alone received. */
void mg_policy_slice_counts(const maelys_git_policy_t *policy, size_t *out_context, size_t *out_slice);
/* The facts the policy at INDEX received in its last solve. */
size_t mg_policy_entry_facts(const maelys_git_policy_t *policy, size_t index);

/* Benches only: the facts the policy at INDEX received in its last solve,
 * borrowed from the handle until its next request or its close. */
const maelys_datalog_fact_t *mg_policy_entry_batch(const maelys_git_policy_t *policy, size_t index,
                                                   size_t *out_count);

/* Tests only: the facts of the last slice the handle still holds; none once
 * its snapshot is gone, since their strings were the snapshot's. */
size_t mg_policy_slice_held(const maelys_git_policy_t *policy);

/* Tests only: a filter applied to each slice before it is given, which
 * keeps a fact when it returns non-zero; NULL removes it. The oracles of the
 * slice use it to show what a missing fact changes. */
typedef int (*mg_policy_slice_filter_t)(const mg_slice_fact_t *fact, void *context);
void mg_policy_set_slice_filter(maelys_git_policy_t *policy, mg_policy_slice_filter_t filter, void *context);

#endif
