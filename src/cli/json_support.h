#ifndef MAELYS_GIT_CLI_JSON_SUPPORT_H
#define MAELYS_GIT_CLI_JSON_SUPPORT_H

/* Bridge between the data documents the handlers write with maelys-json and
 * the framework, which writes the envelope and receives the data as text. */

#include "cli/support.h"
#include "common/json_write.h"

/* Finishes `data` (an MG_JSON_DATA document), replies with it and returns
 * the process exit code. A document that failed replies UNEXPECTED. */
int maelys_git_cli_succeed_document(
    maelys_cli_context_t *context, mg_json_t *data, const char *human, int exit_code);

/* Change summary object shared by the pull request commands, as member `key`. */
void maelys_git_cli_change_summary(mg_json_t *data, const char *key,
                                   const maelys_git_change_summary_t *summary);

#endif
