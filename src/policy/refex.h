#ifndef MAELYS_GIT_POLICY_REFEX_H
#define MAELYS_GIT_POLICY_REFEX_H

/* A ref pattern of the form "regex" (directive GIT-C08, section 4.3): a
 * Gitolite refex, completed by refs/heads/ as Gitolite completes it, kept as
 * written, and anchored at its start only, as Gitolite matches it
 * ($ref =~ /^$refex/). It is read with the subset of maelys/cli/regex.h,
 * which reads every pattern it accepts as Perl does on the refs Gitolite
 * admits. The restrictions are one function, called by the migration and by
 * the reader of a snapshot alike, so that a snapshot written by hand cannot
 * hold what the migration refuses. */

#include <maelys/cli/regex.h>

#include <stddef.h>

/* The longest pattern, its completion included: the bound of every ref
 * pattern of a snapshot. */
#define MG_REFEX_PATTERN_MAX 256u

/* The budgets of D3, in states of the compiled program, its anchor
 * included: one pattern; the distinct patterns of one repository, which
 * bound the work of a request, a request touching one repository; the
 * distinct patterns of a snapshot, which bound its memory. Provisional
 * values, fixed by the review of D3 before patterns are searched. */
#define MG_REFEX_MAX_STATES 4096u
#define MG_REFEX_REPOSITORY_STATES 65536u
#define MG_REFEX_TOTAL_STATES 1048576u

/* Checks PATTERN against the restrictions and compiles "^" PATTERN. On
 * success returns NULL and, when OUT is not NULL, the compiled regex the
 * caller frees with maelys_cli_regex_free. Otherwise returns a stable reason
 * and sets *OUT_OFFSET to the byte of PATTERN where it stands (its length
 * for what only the end reveals). The restrictions:
 *   - it begins with refs/ and holds at most MG_REFEX_PATTERN_MAX bytes;
 *   - no alternation at its top level: a '|' outside a class and a group,
 *     not escaped, which Gitolite would read as "or anywhere" after its
 *     anchor (D2); (a|b), \| and [|] are admitted;
 *   - no '^' outside a class, not escaped: Gitolite anchors already, and a
 *     '^' after refs/heads/ never matches; [^a-z] is admitted;
 *   - no /USER/, which Gitolite replaces by each user's name (D6);
 *   - it compiles in the subset, within MG_REFEX_MAX_STATES. */
const char *mg_refex_regex_check(const char *pattern, maelys_cli_regex_t **out, size_t *out_offset);

#endif
