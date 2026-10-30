#ifndef MAELYS_GIT_POLICY_PROGRAM_H
#define MAELYS_GIT_POLICY_PROGRAM_H

/* The audited Gitolite program: the fixed rules of a migrated Gitolite
 * configuration, whose grants it reads as the slice_* input facts of one
 * request (policy/slice.h). Its text does not depend on the configuration,
 * and Git Core gives a slice only to a policy whose source is the text of
 * one of its versions, as the engine has checked them: a policy that reads
 * slice_* and is none of them is refused at open.
 *
 * Version 1, maelys-git-gitolite-program/1, reads a repository only by a
 * grant on the whole repository, and applies the denies of a ref and the
 * VREF denies to push alone. Version 2, maelys-git-gitolite-program/2, the
 * one the migration writes, also reads it by a grant on one of its refs,
 * and applies those denies to merge and update-ref too, as Gitolite does. A
 * set holds one version, never both; a set of version 1 is refused a merge
 * or an update-ref its denies concern (policy.c). */

#include <stddef.h>

#define MG_GITOLITE_PROGRAM_FORMAT_1 "maelys-git-gitolite-program/1"
#define MG_GITOLITE_PROGRAM_FORMAT_2 "maelys-git-gitolite-program/2"
#define MG_GITOLITE_PROGRAM_VERSIONS 2u
/* The version the migration writes. */
#define MG_GITOLITE_PROGRAM_VERSION 2u
#define MG_GITOLITE_PROGRAM_FORMAT MG_GITOLITE_PROGRAM_FORMAT_2

/* The canonical text of VERSION, NUL-terminated, and its length without the
 * NUL; NULL for a version that does not exist. */
const char *mg_gitolite_program_text_of(unsigned version, size_t *length);
/* The SHA-256 of that text, in lowercase hex; NULL likewise. */
const char *mg_gitolite_program_sha256_of(unsigned version);
/* The format that names VERSION; NULL likewise. */
const char *mg_gitolite_program_format_of(unsigned version);
/* The version whose canonical text has SHA256, or 0 when none has. */
unsigned mg_gitolite_program_version(const char *sha256);

/* The text and SHA-256 of the version the migration writes. */
const char *mg_gitolite_program_text(size_t *length);
const char *mg_gitolite_program_sha256(void);

#endif
