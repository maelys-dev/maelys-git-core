#ifndef MAELYS_GIT_AGENT_H
#define MAELYS_GIT_AGENT_H

#include "maelys_git.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAELYS_GIT_AGENT_PROTOCOL "maelys-git-agent/1"

typedef struct maelys_git_agent_config maelys_git_agent_config_t;
typedef struct maelys_git_agent_store maelys_git_agent_store_t;

maelys_git_result_t maelys_git_protocol_write_decision(
    FILE *output,
    const char *request_id,
    const maelys_git_policy_decision_t *decision,
    maelys_git_error_t *error);

maelys_git_result_t maelys_git_agent_serve(
    maelys_git_policy_t *policy,
    const char *git_executable,
    const char *repository_root,
    FILE *input,
    FILE *output,
    FILE *diagnostics,
    maelys_git_error_t *error);

maelys_git_result_t maelys_git_agent_provision(
    const char *config_path,
    const char *agent_id,
    const char *authority,
    const char *ca_file,
    const char *token_file,
    const char *database_path,
    const char *manifest_path,
    const char *repository_root,
    const char *executor_path,
    maelys_git_error_t *error);

maelys_git_result_t maelys_git_agent_validate_provision(
    const char *config_path,
    const char *agent_id,
    const char *authority,
    const char *ca_file,
    const char *token_file,
    const char *database_path,
    const char *manifest_path,
    const char *repository_root,
    const char *executor_path,
    maelys_git_error_t *error);

maelys_git_result_t maelys_git_agent_run_cloud(
    const char *config_path,
    int run_once,
    maelys_git_error_t *error);

#ifdef __cplusplus
}
#endif

#endif
