#ifndef MAELYS_GIT_AGENT_LAB_H
#define MAELYS_GIT_AGENT_LAB_H

/* The qualification laboratory of GIT-C10 (harness plan §2.3): named points
 * the product reaches, at which a laboratory build injects a fault. The
 * points exist only in the -lab targets, compiled with MG_LAB_FAULTS; in a
 * deliverable the macros below expand to nothing, and no name, no string,
 * no call of this file reaches the installed binaries. The code under
 * MG_LAB_FAULTS never changes the nominal path outside the definition. */

#if defined(MG_LAB_FAULTS)

#include "maelys_git.h"

#include <stdint.h>

/* What a point decides for this passage: the point's own effect (an
 * executor alteration), or a synthetic failure of the layer the point
 * belongs to, with the code of that layer (an errno for a file sync, a
 * SQLite result for a journal transaction). Both zero when nothing is
 * injected. A kill or a pause never returns here as a decision. */
typedef struct {
    int apply;
    int synthetic;
    int code;
    const char *code_name;
} mg_lab_outcome_t;

/* Reads the faults of the process once: the agent from MG_QUAL_FAULT in its
 * environment, the executor from the fault file fixed at configuration
 * (MG_LAB_FAULT_FILE), 0600 of its own account. A fault that cannot be read
 * or parsed ends the process with status 70 after a line on stderr: a
 * laboratory that is misconfigured never passes as nominal. The agent
 * registers the SQLite VFS of the laboratory, maelys-lab, as the default.
 * ROLE is "agent" or "executor". */
void mg_lab_init(const char *role);

/* The command the following markers belong to; NULL clears it. */
void mg_lab_context(const char *message_id);

/* The product reached POINT: a marker is written, the passage counted, and
 * the fault armed for this passage, if any, is applied: kill (SIGKILL to
 * self), pause (a marker, then a wait for the resume file), log, the
 * arming of a VFS fault for the phase this point opens, or the decision
 * returned. An unknown point is reported on stderr and ignored. */
mg_lab_outcome_t mg_lab_reach(const char *point);

/* One return of maelys_http_exchange_advance, with the time it took: a
 * marker when http.trace is enabled. */
void mg_lab_http_trace(const char *method, const char *target, int result, const char *result_name,
                       int64_t duration_ms);

/* The executor's result line, after the effect and before it is written:
 * each alteration point of the executor is reached in turn, and the line
 * is replaced by the altered one when a point applies. A hang or an exit
 * after the effect never returns. MAELYS_GIT_OK, or the error of a
 * rewrite that failed. */
maelys_git_result_t mg_lab_alter_result(char **line);

#define MG_LAB_INIT(role) mg_lab_init(role)
#define MG_LAB_CONTEXT(message_id) mg_lab_context(message_id)
#define MG_LAB_POINT(point) ((void)mg_lab_reach(point))

#else

#define MG_LAB_INIT(role) ((void)0)
#define MG_LAB_CONTEXT(message_id) ((void)0)
#define MG_LAB_POINT(point) ((void)0)

#endif

#endif
