#include "internal.h"

#include <ctype.h>
#include <string.h>

int mg_json_write_string(FILE *output, const char *value) {
    if (!output || !value || fputc('"', output) == EOF) return 0;
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
        const char *escaped = NULL;
        switch (*p) {
            case '"': escaped = "\\\""; break;
            case '\\': escaped = "\\\\"; break;
            case '\b': escaped = "\\b"; break;
            case '\f': escaped = "\\f"; break;
            case '\n': escaped = "\\n"; break;
            case '\r': escaped = "\\r"; break;
            case '\t': escaped = "\\t"; break;
            default: break;
        }
        if (escaped) {
            if (fputs(escaped, output) == EOF) return 0;
        } else if (*p < 0x20u) {
            if (fprintf(output, "\\u%04x", (unsigned)*p) < 0) return 0;
        } else if (fputc(*p, output) == EOF) {
            return 0;
        }
    }
    return fputc('"', output) != EOF;
}

int mg_copy_string(char *out, size_t capacity, const char *value) {
    if (!out || capacity == 0u || !value) return 0;
    size_t length = strlen(value);
    if (length >= capacity) return 0;
    memcpy(out, value, length + 1u);
    return 1;
}

int maelys_git_oid_is_valid(const char *value) {
    if (!value) return 0;
    size_t length = strlen(value);
    if (length != 40u && length != 64u) return 0;
    for (size_t i = 0u; i < length; ++i) {
        if (!isxdigit((unsigned char)value[i])) return 0;
    }
    return 1;
}

int mg_is_oid(const char *value) {
    return maelys_git_oid_is_valid(value);
}

int mg_is_zero_oid(const char *value) {
    if (!mg_is_oid(value)) return 0;
    for (const char *p = value; *p; ++p) {
        if (*p != '0') return 0;
    }
    return 1;
}

void mg_trim_line_endings(unsigned char *data, size_t *length) {
    if (!data || !length) return;
    while (*length && (data[*length - 1u] == '\n' || data[*length - 1u] == '\r'))
        --*length;
    data[*length] = '\0';
}
