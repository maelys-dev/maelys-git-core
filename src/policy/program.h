#ifndef MAELYS_GIT_POLICY_PROGRAM_H
#define MAELYS_GIT_POLICY_PROGRAM_H

/* The audited Gitolite program, format maelys-git-gitolite-program/1: the
 * fixed rules of a migrated Gitolite configuration, whose grants it reads as
 * the slice_* input facts of one request (policy/slice.h). Its text does not
 * depend on the configuration, and Git Core gives a slice only to a policy
 * whose source is these bytes, as the engine has checked them: a policy that
 * reads slice_* and is not this program is refused at open. */

#include <stddef.h>

#define MG_GITOLITE_PROGRAM_FORMAT "maelys-git-gitolite-program/1"

/* The canonical text, NUL-terminated, and its length without the NUL. */
const char *mg_gitolite_program_text(size_t *length);
/* The SHA-256 of the canonical text, in lowercase hex. */
const char *mg_gitolite_program_sha256(void);

#endif
