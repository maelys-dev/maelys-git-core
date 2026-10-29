#include "policy/refex.h"

#include <stdlib.h>
#include <string.h>

/* Reads PATTERN outside its classes and escapes for a top-level '|' or a
 * '^'. A class closes at the first ']' that is not its first member; a
 * class the subset refuses is refused again when it is compiled, so that a
 * misreading here only changes which reason is given. */
static const char *scan(const char *pattern, size_t length, size_t *out_offset) {
    size_t depth = 0u;
    int in_class = 0;
    size_t class_start = 0u;
    for (size_t i = 0u; i < length; ++i) {
        char ch = pattern[i];
        if (ch == '\\') {
            ++i;
            continue;
        }
        if (in_class) {
            size_t first = class_start + 1u + (pattern[class_start + 1u] == '^');
            if (ch == ']' && i > first) in_class = 0;
            continue;
        }
        if (ch == '[') {
            in_class = 1;
            class_start = i;
        } else if (ch == '(') {
            ++depth;
        } else if (ch == ')') {
            if (depth) --depth;
        } else if (ch == '|' && depth == 0u) {
            *out_offset = i;
            return "a '|' at the top level of a refex: write (a|b)";
        } else if (ch == '^') {
            *out_offset = i;
            return "a '^' outside a class: Gitolite anchors a refex already";
        }
    }
    return NULL;
}

const char *mg_refex_regex_check(const char *pattern, maelys_cli_regex_t **out, size_t *out_offset) {
    size_t ignored = 0u;
    if (!out_offset) out_offset = &ignored;
    if (out) *out = NULL;
    *out_offset = 0u;
    size_t length = pattern ? strlen(pattern) : 0u;
    if (length < 5u || strncmp(pattern, "refs/", 5u) != 0) return "a regex pattern begins with refs/";
    if (length > MG_REFEX_PATTERN_MAX) {
        *out_offset = MG_REFEX_PATTERN_MAX;
        return "ref pattern exceeds 256 bytes";
    }
    const char *refused = scan(pattern, length, out_offset);
    if (refused) return refused;
    const char *user = strstr(pattern, "/USER/");
    if (user) {
        *out_offset = (size_t)(user - pattern);
        return "'/USER/' is the user's own name in Gitolite; not supported";
    }
    char anchored[MG_REFEX_PATTERN_MAX + 2u];
    anchored[0] = '^';
    memcpy(anchored + 1u, pattern, length);
    maelys_cli_regex_t *regex = NULL;
    maelys_cli_regex_diagnostic_t diagnostic;
    maelys_cli_regex_status_t status = maelys_cli_regex_compile(anchored, length + 1u, &regex, &diagnostic);
    if (status != MAELYS_CLI_REGEX_OK) {
        *out_offset = diagnostic.offset ? diagnostic.offset - 1u : 0u;
        return status == MAELYS_CLI_REGEX_NO_MEMORY ? "out of memory while compiling a refex"
                                                    : maelys_cli_regex_status_text(status);
    }
    if (maelys_cli_regex_states(regex) > MG_REFEX_MAX_STATES) {
        maelys_cli_regex_free(regex);
        *out_offset = length;
        return "a refex compiles to more than 4096 states";
    }
    if (out) *out = regex;
    else maelys_cli_regex_free(regex);
    return NULL;
}
