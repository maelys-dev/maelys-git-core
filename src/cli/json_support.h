#ifndef MAELYS_GIT_CLI_JSON_SUPPORT_H
#define MAELYS_GIT_CLI_JSON_SUPPORT_H

/* Bridge between Jansson documents built by the handlers and the framework
 * renderer, which only receives serialized text. */

#include "cli/support.h"

#include <jansson.h>

/* Replies with `data` (a Jansson object whose reference is consumed, may be
 * NULL after an allocation failure) and returns the process exit code. */
int maelys_git_cli_succeed_json(
    maelys_cli_context_t *context, json_t *data, const char *human, int exit_code);

/* Change summary object shared by the pull request commands. */
json_t *maelys_git_cli_change_summary_json(const maelys_git_change_summary_t *summary);

#endif
