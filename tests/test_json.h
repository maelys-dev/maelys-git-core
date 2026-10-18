#ifndef MAELYS_GIT_TEST_JSON_H
#define MAELYS_GIT_TEST_JSON_H

/* Reading and rewriting JSON in the C tests, with maelys-json only.
 *
 * A path names a value from a root: members by name and array elements by
 * index, separated by dots ("data.receipt.decision", "items.0.name"). An
 * empty path is the root itself. Lookups never fail loudly: a missing value
 * reads as absent, so assertions say what they expect. */

#include "common/json_write.h"

#include <maelys/json.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Parses `text` (NUL-terminated) under generous limits; NULL when invalid. */
static inline maelys_json_document_t *tj_parse(const char *text) {
    const maelys_json_limits_t limits = {.maximum_bytes = 64u << 20, .maximum_depth = 64u,
                                         .maximum_tokens = 1u << 22};
    maelys_json_document_t *document = NULL;
    if (!text || maelys_json_document_parse(text, strlen(text), MAELYS_JSON_PROFILE_RFC8259, &limits,
                                            &document, NULL) != MAELYS_JSON_OK)
        return NULL;
    return document;
}

static inline void tj_release(maelys_json_document_t *document) {
    maelys_json_document_release(document);
}

/* The value at `path` from `from`, or MAELYS_JSON_VALUE_NONE. */
static inline maelys_json_value_t tj_at(const maelys_json_document_t *document,
                                        maelys_json_value_t from, const char *path) {
    if (!document || from == MAELYS_JSON_VALUE_NONE) return MAELYS_JSON_VALUE_NONE;
    maelys_json_value_t value = from;
    char segment[256];
    while (path && *path) {
        size_t length = strcspn(path, ".");
        if (length >= sizeof(segment)) return MAELYS_JSON_VALUE_NONE;
        memcpy(segment, path, length);
        segment[length] = '\0';
        path += length + (path[length] == '.');
        maelys_json_value_t next = MAELYS_JSON_VALUE_NONE;
        maelys_json_type_t type = maelys_json_value_type(document, value);
        if (type == MAELYS_JSON_TYPE_OBJECT) {
            if (maelys_json_object_get(document, value, segment, &next) != MAELYS_JSON_OK)
                return MAELYS_JSON_VALUE_NONE;
        } else if (type == MAELYS_JSON_TYPE_ARRAY) {
            char *end = NULL;
            unsigned long index = strtoul(segment, &end, 10);
            if (!*segment || *end ||
                maelys_json_array_get(document, value, (size_t)index, &next) != MAELYS_JSON_OK)
                return MAELYS_JSON_VALUE_NONE;
        } else {
            return MAELYS_JSON_VALUE_NONE;
        }
        value = next;
    }
    return value;
}

static inline maelys_json_value_t tj_root_at(const maelys_json_document_t *document, const char *path) {
    return document ? tj_at(document, maelys_json_document_root(document), path) : MAELYS_JSON_VALUE_NONE;
}

static inline maelys_json_type_t tj_type(const maelys_json_document_t *document, const char *path) {
    maelys_json_value_t value = tj_root_at(document, path);
    return value == MAELYS_JSON_VALUE_NONE ? MAELYS_JSON_TYPE_NONE : maelys_json_value_type(document, value);
}

static inline int tj_has(const maelys_json_document_t *document, const char *path) {
    return tj_root_at(document, path) != MAELYS_JSON_VALUE_NONE;
}

/* The string at `path`, borrowed from the document, or NULL. */
static inline const char *tj_string(const maelys_json_document_t *document, const char *path) {
    maelys_json_view_t view;
    maelys_json_value_t value = tj_root_at(document, path);
    return value != MAELYS_JSON_VALUE_NONE &&
           maelys_json_value_string(document, value, &view) == MAELYS_JSON_OK ? view.data : NULL;
}

/* 1 when the string at `path` is `expected`. */
static inline int tj_string_is(const maelys_json_document_t *document, const char *path, const char *expected) {
    const char *text = tj_string(document, path);
    return text && !strcmp(text, expected);
}

/* The integer at `path`, or `fallback` when it is not an integer. */
static inline int64_t tj_i64(const maelys_json_document_t *document, const char *path, int64_t fallback) {
    int64_t number;
    maelys_json_value_t value = tj_root_at(document, path);
    return value != MAELYS_JSON_VALUE_NONE &&
           maelys_json_value_i64(document, value, &number) == MAELYS_JSON_OK ? number : fallback;
}

/* 1 true, 0 false, -1 when the value is not a boolean. */
static inline int tj_boolean(const maelys_json_document_t *document, const char *path) {
    int flag;
    maelys_json_value_t value = tj_root_at(document, path);
    return value != MAELYS_JSON_VALUE_NONE &&
           maelys_json_value_boolean(document, value, &flag) == MAELYS_JSON_OK ? (flag != 0) : -1;
}

static inline int tj_is_null(const maelys_json_document_t *document, const char *path) {
    return tj_type(document, path) == MAELYS_JSON_TYPE_NULL;
}

/* Members of an object or elements of an array at `path`; 0 otherwise. */
static inline size_t tj_size(const maelys_json_document_t *document, const char *path) {
    size_t size = 0u;
    maelys_json_value_t value = tj_root_at(document, path);
    maelys_json_type_t type = value == MAELYS_JSON_VALUE_NONE ? MAELYS_JSON_TYPE_NONE :
                              maelys_json_value_type(document, value);
    if (type == MAELYS_JSON_TYPE_OBJECT) (void)maelys_json_object_size(document, value, &size);
    else if (type == MAELYS_JSON_TYPE_ARRAY) (void)maelys_json_array_size(document, value, &size);
    return size;
}

/* Structural equality: member order ignored, array order and number lexemes kept. */
static inline int tj_value_equal(const maelys_json_document_t *a, maelys_json_value_t x,
                                 const maelys_json_document_t *b, maelys_json_value_t y) {
    maelys_json_type_t type = maelys_json_value_type(a, x);
    if (type != maelys_json_value_type(b, y)) return 0;
    maelys_json_view_t va, vb;
    size_t count = 0u, other = 0u;
    switch (type) {
        case MAELYS_JSON_TYPE_STRING:
            return maelys_json_value_string(a, x, &va) == MAELYS_JSON_OK &&
                   maelys_json_value_string(b, y, &vb) == MAELYS_JSON_OK &&
                   va.size == vb.size && !memcmp(va.data, vb.data, va.size);
        case MAELYS_JSON_TYPE_NUMBER:
            return maelys_json_value_number_text(a, x, &va) == MAELYS_JSON_OK &&
                   maelys_json_value_number_text(b, y, &vb) == MAELYS_JSON_OK &&
                   va.size == vb.size && !memcmp(va.data, vb.data, va.size);
        case MAELYS_JSON_TYPE_BOOLEAN: {
            int fa = 0, fb = 0;
            return maelys_json_value_boolean(a, x, &fa) == MAELYS_JSON_OK &&
                   maelys_json_value_boolean(b, y, &fb) == MAELYS_JSON_OK && !fa == !fb;
        }
        case MAELYS_JSON_TYPE_NULL:
            return 1;
        case MAELYS_JSON_TYPE_ARRAY:
            if (maelys_json_array_size(a, x, &count) != MAELYS_JSON_OK ||
                maelys_json_array_size(b, y, &other) != MAELYS_JSON_OK || count != other)
                return 0;
            for (size_t i = 0u; i < count; ++i) {
                maelys_json_value_t ex, ey;
                if (maelys_json_array_get(a, x, i, &ex) != MAELYS_JSON_OK ||
                    maelys_json_array_get(b, y, i, &ey) != MAELYS_JSON_OK || !tj_value_equal(a, ex, b, ey))
                    return 0;
            }
            return 1;
        case MAELYS_JSON_TYPE_OBJECT:
            if (maelys_json_object_size(a, x, &count) != MAELYS_JSON_OK ||
                maelys_json_object_size(b, y, &other) != MAELYS_JSON_OK || count != other)
                return 0;
            for (size_t i = 0u; i < count; ++i) {
                maelys_json_view_t key;
                maelys_json_value_t ex, ey;
                if (maelys_json_object_member_at(a, x, i, &key, &ex) != MAELYS_JSON_OK ||
                    maelys_json_object_get(b, y, key.data, &ey) != MAELYS_JSON_OK ||
                    !tj_value_equal(a, ex, b, ey))
                    return 0;
            }
            return 1;
        default:
            return 0;
    }
}

/* Structural equality of two JSON texts. */
static inline int tj_text_equal(const char *left, const char *right) {
    maelys_json_document_t *a = tj_parse(left), *b = tj_parse(right);
    int equal = a && b && tj_value_equal(a, maelys_json_document_root(a), b, maelys_json_document_root(b));
    tj_release(a);
    tj_release(b);
    return equal;
}

/* `text`, an object, written again with `flags` (MAELYS_JSON_WRITER_ASCII,
 * _INDENT): member `key` replaced by the JSON `value` (added when absent),
 * or removed when `value` is NULL; with a NULL `key`, unchanged. Keys come
 * out sorted. The caller frees the result; NULL on failure. */
static inline char *tj_rewrite(const char *text, const char *key, const char *value, unsigned int flags) {
    maelys_json_document_t *document = tj_parse(text);
    maelys_json_document_t *replacement = key && value ? tj_parse(value) : NULL;
    char *out = NULL;
    if (document && (!key || !value || replacement)) {
        const maelys_json_limits_t limits = {.maximum_bytes = 64u << 20, .maximum_depth = 64u,
                                             .maximum_tokens = 1u << 22};
        maelys_json_writer_t *writer = NULL;
        const char *excluded[1] = {key};
        size_t size = 0u;
        if (maelys_json_writer_create(MAELYS_JSON_PROFILE_RFC8259, &limits, flags, &writer) == MAELYS_JSON_OK &&
            maelys_json_writer_object_begin_except(writer, document, maelys_json_document_root(document),
                                                   excluded, key ? 1u : 0u) == MAELYS_JSON_OK &&
            (!replacement ||
             (maelys_json_writer_key_cstr(writer, key) == MAELYS_JSON_OK &&
              maelys_json_writer_value(writer, replacement, maelys_json_document_root(replacement)) ==
                  MAELYS_JSON_OK)) &&
            maelys_json_writer_object_end(writer) == MAELYS_JSON_OK &&
            maelys_json_writer_finish(writer, &out, &size) != MAELYS_JSON_OK) {
            free(out);
            out = NULL;
        }
        maelys_json_writer_release(writer);
    }
    tj_release(document);
    tj_release(replacement);
    return out;
}

static inline char *tj_with(const char *text, const char *key, const char *value) {
    return tj_rewrite(text, key, value, 0u);
}

/* The value at `path` in `text`, written alone: compact, UTF-8 kept, keys
 * sorted, number lexemes kept. The caller frees the result; NULL when absent. */
static inline char *tj_extract(const char *text, const char *path) {
    maelys_json_document_t *document = tj_parse(text);
    maelys_json_value_t value = tj_root_at(document, path);
    char *out = NULL;
    if (value != MAELYS_JSON_VALUE_NONE) {
        const maelys_json_limits_t limits = {.maximum_bytes = 64u << 20, .maximum_depth = 64u,
                                             .maximum_tokens = 1u << 22};
        maelys_json_writer_t *writer = NULL;
        size_t size = 0u;
        if (maelys_json_writer_create(MAELYS_JSON_PROFILE_RFC8259, &limits, 0u, &writer) == MAELYS_JSON_OK &&
            maelys_json_writer_value(writer, document, value) == MAELYS_JSON_OK &&
            maelys_json_writer_finish(writer, &out, &size) != MAELYS_JSON_OK) {
            free(out);
            out = NULL;
        }
        maelys_json_writer_release(writer);
    }
    tj_release(document);
    return out;
}

/* `value` as a JSON string literal. The caller frees the result. */
static inline char *tj_quote(const char *value) {
    mg_json_t json;
    mg_json_begin(&json, MG_JSON_DATA);
    mg_json_string(&json, NULL, value);
    char *out = NULL;
    (void)mg_json_finish(&json, &out, NULL);
    return out;
}

#endif
