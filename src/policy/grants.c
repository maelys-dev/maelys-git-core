#include "internal.h"
#include "policy/grants.h"

#include <maelys/cli/digest.h>
#include <maelys/cli/files.h>
#include <maelys/json.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* The parse limits of a snapshot: its bytes, three levels (the object, a
 * section, a tuple) and the values a text of that size can hold. */
#define GRANTS_DEPTH 3u
#define GRANTS_TOKENS ((MG_GRANTS_MAX_BYTES + 1u) / 2u)
#define MAX_FIELDS 6u

struct mg_grants {
    maelys_json_document_t *document;   /* owns every string of the view */
    mg_grants_view_t view;
    char sha256[MAELYS_CLI_SHA256_HEX_SIZE];
};

/* One field of a tuple while it is read: a string, or the integer of a
 * VREF limit. Tuples compare field by field, strings by their bytes. */
typedef struct {
    const char *text;
    int64_t number;
} field_t;

typedef struct {
    const maelys_json_document_t *document;
    maelys_git_error_t *error;
    const char *section;
    size_t index;
    size_t tuples;
} reader_t;

static int refuse(reader_t *reader, maelys_git_result_t code, const char *reason) {
    mg_error_set(reader->error, code, 0, "grants snapshot: %s[%zu]: %s", reader->section, reader->index,
                 reason);
    return 0;
}

static int compare_fields(const field_t *a, const field_t *b, size_t count) {
    for (size_t i = 0u; i < count; ++i) {
        if (a[i].text && b[i].text) {
            int order = strcmp(a[i].text, b[i].text);
            if (order) return order;
        } else if (a[i].number != b[i].number) {
            return a[i].number < b[i].number ? -1 : 1;
        }
    }
    return 0;
}

/* The string of a tuple element, at most MG_GRANTS_MAX_STRING bytes. */
static const char *string_at(reader_t *reader, maelys_json_value_t tuple, size_t position) {
    maelys_json_value_t value;
    maelys_json_view_t view;
    if (maelys_json_array_get(reader->document, tuple, position, &value) != MAELYS_JSON_OK ||
        maelys_json_value_string(reader->document, value, &view) != MAELYS_JSON_OK) {
        (void)refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT, "a string is expected");
        return NULL;
    }
    if (view.size == 0u || view.size > MG_GRANTS_MAX_STRING) {
        (void)refuse(reader, MAELYS_GIT_ERR_LIMIT, "a string is empty or longer than 1023 bytes");
        return NULL;
    }
    return view.data;
}

static int one_of(const char *value, const char *const *allowed) {
    for (; *allowed; ++allowed)
        if (!strcmp(value, *allowed)) return 1;
    return 0;
}

static int subject_kind(reader_t *reader, const char *text, mg_subject_kind_t *out) {
    if (!strcmp(text, "user")) *out = MG_SUBJECT_USER;
    else if (!strcmp(text, "group")) *out = MG_SUBJECT_GROUP;
    else return refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT, "kind is \"user\" or \"group\"");
    return 1;
}

static int name(reader_t *reader, const char *text) {
    return mg_gitolite_name_is_valid(text) ||
           refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT, "a user, group or namespace name is invalid");
}

static int repository(reader_t *reader, const char *text) {
    return maelys_git_repository_name_is_valid(text) ||
           refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT, "a repository name is invalid");
}

/* The generator's refex subset, without the policy atom bound: an exact
 * ref, or a prefix of refs/ of [A-Za-z0-9._/-] that ends with '/', or, for
 * a deny, a bare literal Gitolite also denies as a prefix. */
static int pattern(reader_t *reader, int prefix, int deny, const char *text) {
    size_t length = strlen(text);
    int valid = length <= 256u;
    if (prefix) {
        valid = valid && length > 5u && !strncmp(text, "refs/", 5u) && (deny || text[length - 1u] == '/') &&
                !strstr(text, "..") && !strstr(text, "//");
        for (size_t i = 0u; valid && i < length; ++i) {
            unsigned char ch = (unsigned char)text[i];
            valid = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
                    ch == '.' || ch == '_' || ch == '/' || ch == '-';
        }
    } else {
        valid = valid && maelys_git_ref_name_is_valid(text);
    }
    return valid || refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT, "a ref pattern is invalid");
}

/* A VREF path: relative, components of [A-Za-z0-9._-], none "." or "..". */
static int vref_path(reader_t *reader, const char *text) {
    int valid = text[0] != '/' && text[strlen(text) - 1u] != '/';
    const char *component = text;
    for (const char *p = text; valid; ++p) {
        if (*p == '/' || *p == '\0') {
            size_t length = (size_t)(p - component);
            valid = length && !(length == 1u && component[0] == '.') &&
                    !(length == 2u && component[0] == '.' && component[1] == '.');
            if (*p == '\0') break;
            component = p + 1;
        } else {
            unsigned char ch = (unsigned char)*p;
            valid = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
                    ch == '.' || ch == '_' || ch == '-';
        }
    }
    return valid || refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT, "a VREF path is invalid");
}

/* The tuples of SECTION, of ARITY elements each, in strictly increasing
 * order. READ_TUPLE validates one tuple into FIELDS and stores it at
 * index *count of OUT. */
typedef int (*tuple_reader_t)(reader_t *reader, maelys_json_value_t tuple, field_t *fields, void *out,
                              size_t index);

static int read_section(reader_t *reader, maelys_json_value_t root, const char *section, size_t arity,
                        size_t element_size, tuple_reader_t read_tuple, void **out, size_t *out_count,
                        size_t *index_bytes) {
    reader->section = section;
    reader->index = 0u;
    maelys_json_value_t array;
    size_t count = 0u;
    if (maelys_json_object_get(reader->document, root, section, &array) != MAELYS_JSON_OK ||
        maelys_json_array_size(reader->document, array, &count) != MAELYS_JSON_OK)
        return refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT, "an array is expected");
    if (count > MG_GRANTS_MAX_TUPLES - reader->tuples)
        return refuse(reader, MAELYS_GIT_ERR_LIMIT, "the snapshot holds more than 65536 grants");
    reader->tuples += count;
    void *elements = count ? calloc(count, element_size) : NULL;
    if (count && !elements) return refuse(reader, MAELYS_GIT_ERR_IO, "out of memory");
    *out = elements;
    *out_count = count;
    *index_bytes += count * element_size;
    field_t previous[MAX_FIELDS], current[MAX_FIELDS];
    for (size_t i = 0u; i < count; ++i) {
        reader->index = i;
        maelys_json_value_t tuple;
        size_t size = 0u;
        if (maelys_json_array_get(reader->document, array, i, &tuple) != MAELYS_JSON_OK ||
            maelys_json_array_size(reader->document, tuple, &size) != MAELYS_JSON_OK || size != arity)
            return refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT, "a tuple has the wrong number of elements");
        memset(current, 0, sizeof(current));
        if (!read_tuple(reader, tuple, current, elements, i)) return 0;
        if (i && compare_fields(previous, current, arity) >= 0)
            return refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT,
                          "tuples are not in strictly increasing order");
        memcpy(previous, current, sizeof(previous));
    }
    return 1;
}

static int read_member(reader_t *reader, maelys_json_value_t tuple, field_t *fields, void *out, size_t index) {
    mg_grant_member_t *member = (mg_grant_member_t *)out + index;
    if (!(member->user = fields[0].text = string_at(reader, tuple, 0u)) ||
        !(member->group = fields[1].text = string_at(reader, tuple, 1u)))
        return 0;
    return name(reader, member->user) && name(reader, member->group);
}

static int read_nested(reader_t *reader, maelys_json_value_t tuple, field_t *fields, void *out, size_t index) {
    mg_grant_nested_t *nested = (mg_grant_nested_t *)out + index;
    if (!(nested->group = fields[0].text = string_at(reader, tuple, 0u)) ||
        !(nested->parent = fields[1].text = string_at(reader, tuple, 1u)))
        return 0;
    return name(reader, nested->group) && name(reader, nested->parent);
}

/* kind and subject, the first two elements of most tuples. */
static int read_subject(reader_t *reader, maelys_json_value_t tuple, field_t *fields,
                        mg_subject_kind_t *kind, const char **subject) {
    return (fields[0].text = string_at(reader, tuple, 0u)) &&
           subject_kind(reader, fields[0].text, kind) &&
           (*subject = fields[1].text = string_at(reader, tuple, 1u)) && name(reader, *subject);
}

static int read_access(reader_t *reader, maelys_json_value_t tuple, field_t *fields, void *out, size_t index) {
    static const char *const levels[] = {"C", "R", "RW", "RW+", NULL};
    mg_grant_access_t *access = (mg_grant_access_t *)out + index;
    if (!read_subject(reader, tuple, fields, &access->kind, &access->subject) ||
        !(access->repository = fields[2].text = string_at(reader, tuple, 2u)) ||
        !repository(reader, access->repository) ||
        !(access->level = fields[3].text = string_at(reader, tuple, 3u)))
        return 0;
    return one_of(access->level, levels) ||
           refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT, "level is \"C\", \"R\", \"RW\" or \"RW+\"");
}

static int read_ref(reader_t *reader, maelys_json_value_t tuple, field_t *fields, void *out, size_t index) {
    static const char *const levels[] = {"RW", "RW+", "-", NULL};
    mg_grant_ref_t *ref = (mg_grant_ref_t *)out + index;
    if (!read_subject(reader, tuple, fields, &ref->kind, &ref->subject) ||
        !(ref->repository = fields[2].text = string_at(reader, tuple, 2u)) ||
        !repository(reader, ref->repository) || !(fields[3].text = string_at(reader, tuple, 3u)))
        return 0;
    if (!strcmp(fields[3].text, "prefix")) ref->prefix = 1;
    else if (strcmp(fields[3].text, "exact"))
        return refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT, "form is \"exact\" or \"prefix\"");
    if (!(ref->pattern = fields[4].text = string_at(reader, tuple, 4u)) ||
        !(ref->level = fields[5].text = string_at(reader, tuple, 5u)))
        return 0;
    if (!one_of(ref->level, levels))
        return refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT, "level is \"RW\", \"RW+\" or \"-\"");
    return pattern(reader, ref->prefix, !strcmp(ref->level, "-"), ref->pattern);
}

static int read_creator(reader_t *reader, maelys_json_value_t tuple, field_t *fields, void *out, size_t index) {
    mg_grant_creator_t *creator = (mg_grant_creator_t *)out + index;
    return read_subject(reader, tuple, fields, &creator->kind, &creator->subject) &&
           (creator->namespace_name = fields[2].text = string_at(reader, tuple, 2u)) &&
           name(reader, creator->namespace_name);
}

static int read_owner(reader_t *reader, maelys_json_value_t tuple, field_t *fields, void *out, size_t index) {
    static const char *const levels[] = {"R", "RW", "RW+", NULL};
    mg_grant_owner_t *owner = (mg_grant_owner_t *)out + index;
    if (!(owner->namespace_name = fields[0].text = string_at(reader, tuple, 0u)) ||
        !name(reader, owner->namespace_name) || !(owner->level = fields[1].text = string_at(reader, tuple, 1u)))
        return 0;
    return one_of(owner->level, levels) ||
           refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT, "level is \"R\", \"RW\" or \"RW+\"");
}

static int read_vref_name(reader_t *reader, maelys_json_value_t tuple, field_t *fields, void *out, size_t index) {
    mg_grant_vref_name_t *vref = (mg_grant_vref_name_t *)out + index;
    return read_subject(reader, tuple, fields, &vref->kind, &vref->subject) &&
           (vref->repository = fields[2].text = string_at(reader, tuple, 2u)) &&
           repository(reader, vref->repository) &&
           (vref->path = fields[3].text = string_at(reader, tuple, 3u)) && vref_path(reader, vref->path);
}

static int read_vref_limit(reader_t *reader, maelys_json_value_t tuple, field_t *fields, void *out, size_t index) {
    static const char *const limits[] = {"count", "new_count", "max_new_binary", NULL};
    mg_grant_vref_limit_t *vref = (mg_grant_vref_limit_t *)out + index;
    if (!read_subject(reader, tuple, fields, &vref->kind, &vref->subject) ||
        !(vref->repository = fields[2].text = string_at(reader, tuple, 2u)) ||
        !repository(reader, vref->repository) || !(vref->limit = fields[3].text = string_at(reader, tuple, 3u)))
        return 0;
    if (!one_of(vref->limit, limits))
        return refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT,
                      "limit is \"count\", \"new_count\" or \"max_new_binary\"");
    maelys_json_value_t value;
    if (maelys_json_array_get(reader->document, tuple, 4u, &value) != MAELYS_JSON_OK ||
        maelys_json_value_i64(reader->document, value, &vref->value) != MAELYS_JSON_OK || vref->value < 0)
        return refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT, "value is an integer in [0, INT64_MAX]");
    fields[4].number = vref->value;
    return 1;
}

static int compare_names(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* The distinct groups the snapshot names, and at most
 * MG_GRANTS_MAX_DIRECT_GROUPS direct groups for any member. */
static int count_groups(reader_t *reader, mg_grants_view_t *view) {
    reader->section = "members";
    for (size_t i = 0u, run = 0u; i < view->member_count; ++i) {
        run = i && !strcmp(view->members[i].user, view->members[i - 1u].user) ? run + 1u : 1u;
        reader->index = i;
        if (run > MG_GRANTS_MAX_DIRECT_GROUPS)
            return refuse(reader, MAELYS_GIT_ERR_LIMIT, "a member belongs directly to more than 64 groups");
    }
    size_t capacity = view->member_count + 2u * view->nested_count + view->access_count + view->ref_count +
                      view->creator_count + view->vref_name_count + view->vref_limit_count;
    const char **names = capacity ? calloc(capacity, sizeof(*names)) : NULL;
    if (capacity && !names) return refuse(reader, MAELYS_GIT_ERR_IO, "out of memory");
    size_t used = 0u;
    for (size_t i = 0u; i < view->member_count; ++i) names[used++] = view->members[i].group;
    for (size_t i = 0u; i < view->nested_count; ++i) {
        names[used++] = view->nested[i].group;
        names[used++] = view->nested[i].parent;
    }
#define GROUP_SUBJECTS(array, count) \
    for (size_t i = 0u; i < (count); ++i) \
        if ((array)[i].kind == MG_SUBJECT_GROUP) names[used++] = (array)[i].subject;
    GROUP_SUBJECTS(view->access, view->access_count)
    GROUP_SUBJECTS(view->refs, view->ref_count)
    GROUP_SUBJECTS(view->creators, view->creator_count)
    GROUP_SUBJECTS(view->vref_names, view->vref_name_count)
    GROUP_SUBJECTS(view->vref_limits, view->vref_limit_count)
#undef GROUP_SUBJECTS
    if (used) qsort(names, used, sizeof(*names), compare_names);
    size_t distinct = 0u;
    for (size_t i = 0u; i < used; ++i)
        if (!i || strcmp(names[i], names[i - 1u])) ++distinct;
    free(names);
    view->group_count = distinct;
    reader->section = "groups";
    reader->index = distinct;
    return distinct <= MG_GRANTS_MAX_GROUPS ||
           refuse(reader, MAELYS_GIT_ERR_LIMIT, "the snapshot names more than 4096 groups");
}

static const char *const k_sections[] = {"access", "format", "members", "namespace_creators", "nested",
                                         "owner_access", "refs", "vref_limits", "vref_names"};

/* The root: an object of exactly the nine members, and the format. */
static int read_root(reader_t *reader, maelys_json_value_t root) {
    reader->section = "root";
    size_t size = 0u;
    if (maelys_json_value_type(reader->document, root) != MAELYS_JSON_TYPE_OBJECT ||
        maelys_json_object_size(reader->document, root, &size) != MAELYS_JSON_OK ||
        size != sizeof(k_sections) / sizeof(k_sections[0]))
        return refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT, "an object of nine members is expected");
    for (size_t i = 0u; i < size; ++i) {
        maelys_json_view_t key;
        maelys_json_value_t value;
        reader->index = i;
        if (maelys_json_object_member_at(reader->document, root, i, &key, &value) != MAELYS_JSON_OK ||
            !bsearch(&key.data, k_sections, sizeof(k_sections) / sizeof(k_sections[0]), sizeof(k_sections[0]),
                     compare_names))
            return refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT, "an unknown member");
    }
    maelys_json_value_t format;
    maelys_json_view_t view;
    if (maelys_json_object_get(reader->document, root, "format", &format) != MAELYS_JSON_OK ||
        maelys_json_value_string(reader->document, format, &view) != MAELYS_JSON_OK ||
        strcmp(view.data, MG_GRANTS_FORMAT))
        return refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT, "format is not " MG_GRANTS_FORMAT);
    return 1;
}

void mg_grants_free(mg_grants_t *grants) {
    if (!grants) return;
    free((void *)grants->view.members);
    free((void *)grants->view.nested);
    free((void *)grants->view.access);
    free((void *)grants->view.refs);
    free((void *)grants->view.creators);
    free((void *)grants->view.owners);
    free((void *)grants->view.vref_names);
    free((void *)grants->view.vref_limits);
    maelys_json_document_release(grants->document);
    free(grants);
}

maelys_git_result_t mg_grants_parse(const void *bytes, size_t size, mg_grants_t **out,
                                    maelys_git_error_t *error) {
    if (!bytes || !out) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    *out = NULL;
    if (size > MG_GRANTS_MAX_BYTES) {
        mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0, "grants snapshot exceeds %u bytes", MG_GRANTS_MAX_BYTES);
        return MAELYS_GIT_ERR_LIMIT;
    }
    mg_grants_t *grants = calloc(1u, sizeof(*grants));
    if (!grants) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, 0, "out of memory");
        return MAELYS_GIT_ERR_IO;
    }
    const maelys_json_limits_t limits = {.maximum_bytes = MG_GRANTS_MAX_BYTES,
                                         .maximum_depth = GRANTS_DEPTH,
                                         .maximum_tokens = GRANTS_TOKENS};
    maelys_json_error_t json_error;
    maelys_json_result_t parsed = maelys_json_document_parse(bytes, size, MAELYS_JSON_PROFILE_RFC8259, &limits,
                                                             &grants->document, &json_error);
    if (parsed != MAELYS_JSON_OK) {
        maelys_git_result_t code = parsed == MAELYS_JSON_ERR_LIMIT ? MAELYS_GIT_ERR_LIMIT
                                                                    : MAELYS_GIT_ERR_INVALID_ARGUMENT;
        mg_error_set(error, code, 0, "grants snapshot is not valid JSON within its limits: %s",
                     maelys_json_result_string(parsed));
        mg_grants_free(grants);
        return code;
    }
    reader_t reader = {.document = grants->document, .error = error};
    mg_grants_view_t *view = &grants->view;
    maelys_json_value_t root = maelys_json_document_root(grants->document);
    int ok = read_root(&reader, root) &&
        read_section(&reader, root, "members", 2u, sizeof(mg_grant_member_t), read_member,
                     (void **)&view->members, &view->member_count, &view->index_bytes) &&
        read_section(&reader, root, "nested", 2u, sizeof(mg_grant_nested_t), read_nested,
                     (void **)&view->nested, &view->nested_count, &view->index_bytes) &&
        read_section(&reader, root, "access", 4u, sizeof(mg_grant_access_t), read_access,
                     (void **)&view->access, &view->access_count, &view->index_bytes) &&
        read_section(&reader, root, "refs", 6u, sizeof(mg_grant_ref_t), read_ref,
                     (void **)&view->refs, &view->ref_count, &view->index_bytes) &&
        read_section(&reader, root, "namespace_creators", 3u, sizeof(mg_grant_creator_t), read_creator,
                     (void **)&view->creators, &view->creator_count, &view->index_bytes) &&
        read_section(&reader, root, "owner_access", 2u, sizeof(mg_grant_owner_t), read_owner,
                     (void **)&view->owners, &view->owner_count, &view->index_bytes) &&
        read_section(&reader, root, "vref_names", 4u, sizeof(mg_grant_vref_name_t), read_vref_name,
                     (void **)&view->vref_names, &view->vref_name_count, &view->index_bytes) &&
        read_section(&reader, root, "vref_limits", 5u, sizeof(mg_grant_vref_limit_t), read_vref_limit,
                     (void **)&view->vref_limits, &view->vref_limit_count, &view->index_bytes) &&
        count_groups(&reader, view);
    if (!ok) {
        mg_grants_free(grants);
        return error && error->code != MAELYS_GIT_OK ? error->code : MAELYS_GIT_ERR_INVALID_ARGUMENT;
    }
    maelys_cli_sha256_hex(bytes, size, grants->sha256);
    *out = grants;
    return MAELYS_GIT_OK;
}

maelys_git_result_t mg_grants_load(const char *path, mg_grants_t **out, maelys_git_error_t *error) {
    if (!path || !out) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    *out = NULL;
    unsigned char *bytes = NULL;
    size_t size = 0u;
    const char *reason = NULL;
    if (maelys_cli_read_trusted_file(path,
                                     MAELYS_CLI_FILE_REGULAR | MAELYS_CLI_FILE_OWNER_TRUSTED |
                                         MAELYS_CLI_FILE_NOT_WRITABLE_BY_OTHERS |
                                         MAELYS_CLI_FILE_TRUSTED_DIRECTORY,
                                     1u, MG_GRANTS_MAX_BYTES, &bytes, &size, &reason) != 0) {
        int saved = errno;
        maelys_git_result_t code = saved == EPERM || saved == EACCES ? MAELYS_GIT_ERR_DENIED
                                 : saved == ENOENT ? MAELYS_GIT_ERR_NOT_FOUND
                                 : saved == EFBIG ? MAELYS_GIT_ERR_LIMIT : MAELYS_GIT_ERR_IO;
        mg_error_set(error, code, saved, "grants snapshot %s refused: %s", path,
                     reason ? reason : strerror(saved));
        return code;
    }
    maelys_git_result_t result = mg_grants_parse(bytes, size, out, error);
    free(bytes);
    return result;
}

const char *mg_grants_sha256(const mg_grants_t *grants) {
    return grants ? grants->sha256 : "";
}

void mg_grants_view(const mg_grants_t *grants, mg_grants_view_t *out) {
    if (grants && out) *out = grants->view;
}
