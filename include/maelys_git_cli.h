#ifndef MAELYS_GIT_CLI_H
#define MAELYS_GIT_CLI_H

/*
 * Command-line interface of Maelys Git Core, built on the shared Maelys CLI
 * framework (libmaelys_cli). Each program declares one application whose
 * catalog is the single source of truth for parsing, help, describe and the
 * generated reference. Program entry points reduce to
 * maelys_cli_main(&maelys_git_cli_*_app, argc, argv).
 */

#include "maelys_git.h"

#include <maelys/cli.h>

#ifdef __cplusplus
extern "C" {
#endif

/* maelys-git: policy validation, authorization and repository administration. */
extern const maelys_cli_app_t maelys_git_cli_admin_app;
/* maelys-git-agent: provisioning, Cloud synchronization loop and stdio executor. */
extern const maelys_cli_app_t maelys_git_cli_agent_app;
/* maelys-git-executor: the isolated JSONL executor started by the agent. */
extern const maelys_cli_app_t maelys_git_cli_executor_app;
/* maelys-git-shell: the SSH forced command. */
extern const maelys_cli_app_t maelys_git_cli_shell_app;
/* maelys-git-hook: pre-receive authorization and post-receive events. */
extern const maelys_cli_app_t maelys_git_cli_hook_app;

/* Emits the failure envelope matching a core result and returns the process
 * exit code. The mapping to stable error codes is documented in
 * docs/command-conventions.md. */
int maelys_git_cli_fail_result(
    maelys_cli_context_t *context,
    maelys_git_result_t result,
    const maelys_git_error_t *error);

#ifdef __cplusplus
}
#endif

#endif
